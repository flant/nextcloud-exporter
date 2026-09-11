package metrics

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xperimental/nextcloud-exporter/internal/client"
)

const (
	advisoriesRefreshInterval = 12 * time.Hour

	advisoriesRetryInterval = 15 * time.Minute

	advisoriesMaxAge = 48 * time.Hour
)

type advisorySnapshot struct {
	fixes     []advisoryFix
	fetchedAt time.Time
}

type SecurityChecker struct {
	log     logrus.FieldLogger
	fetcher *advisoryFetcher

	// info asks Nextcloud which version is installed and which one is offered.
	//
	// The advisory list says nothing about the server, so without this the verdict could
	// only be printed once a scrape brought the versions along. May be nil, in which case
	// the last pair a scrape reported is used instead.
	info client.InfoClient

	mu       sync.RWMutex
	snapshot *advisorySnapshot

	lastVersions versionPair

	results changeOnlyLogger
}

type versionPair struct {
	current   string
	available string
}

func NewSecurityChecker(log logrus.FieldLogger, userAgent string, info client.InfoClient) *SecurityChecker {
	return &SecurityChecker{
		log:     log,
		fetcher: newAdvisoryFetcher(userAgent),
		info:    info,
	}
}

func (c *SecurityChecker) Start(ctx context.Context) {
	go c.refreshLoop(ctx)
}

func (c *SecurityChecker) refreshLoop(ctx context.Context) {
	for {
		wait := advisoriesRefreshInterval
		if err := c.refresh(ctx); err != nil {
			c.log.Warnf("Security check: can not refresh advisories: %s", err)
			wait = advisoriesRetryInterval
		}

		timer := time.NewTimer(wait)

		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return
		}
	}
}

func (c *SecurityChecker) refresh(ctx context.Context) error {
	advisories, err := c.fetcher.fetchAll(ctx)
	if err != nil {
		return err
	}

	fixes := parseFixes(advisories)
	if len(fixes) == 0 {
		return fmt.Errorf("no usable advisories in %d records", len(advisories))
	}

	c.mu.Lock()
	c.snapshot = &advisorySnapshot{fixes: fixes, fetchedAt: time.Now()}
	c.mu.Unlock()

	c.log.Infof("Security check: loaded %d advisories for Nextcloud Server.", len(fixes))

	c.results.reset()
	c.logLoadedResult()

	return nil
}

// logLoadedResult prints the verdict for the advisories that were just loaded.
func (c *SecurityChecker) logLoadedResult() {
	seen, ok := c.loadedVersions()
	if !ok {
		return
	}

	_, _, message, warn := c.evaluate(seen.current, seen.available)
	c.logResult(warn, message)
}

// loadedVersions picks the version pair the verdict is printed for, asking Nextcloud
// directly so that the line does not wait for anyone to pull /metrics.
//
// When there is no client to ask, or the request fails, the pair from the last scrape is
// used instead. A false second value means there is nothing to report at all.
func (c *SecurityChecker) loadedVersions() (versionPair, bool) {
	if c.info == nil {
		return c.lastSeen()
	}

	status, err := c.info()
	if err != nil {
		c.log.Warnf("Security check: can not read the server version: %s", err)
		return c.lastSeen()
	}

	system := status.Data.Nextcloud.System
	if !system.Update.Available || system.Version == system.Update.AvailableVersion {
		// The server offers no update, so there is no verdict to print. This mirrors
		// collectUpdate, which consults the checker only when an update is available.
		return versionPair{}, false
	}

	return versionPair{current: system.Version, available: system.Update.AvailableVersion}, true
}

// lastSeen returns the version pair from the last scrape, if there has been one.
func (c *SecurityChecker) lastSeen() (versionPair, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.lastVersions, c.lastVersions != versionPair{}
}

func (c *SecurityChecker) currentSnapshot() *advisorySnapshot {
	if c == nil {
		return nil
	}

	c.mu.RLock()
	snapshot := c.snapshot
	c.mu.RUnlock()

	if snapshot == nil || time.Since(snapshot.fetchedAt) > advisoriesMaxAge {
		return nil
	}

	return snapshot
}

func (c *SecurityChecker) Available() bool {
	return c.currentSnapshot() != nil
}

func (c *SecurityChecker) Check(current, available string) (fixed []string, ok bool) {
	fixed, ok, message, warn := c.evaluate(current, available)

	if c.remember(current, available) {
		c.logResult(warn, message)
	}

	return fixed, ok
}

func (c *SecurityChecker) remember(current, available string) bool {
	if c == nil {
		return false
	}

	seen := versionPair{current: current, available: available}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.lastVersions == seen {
		return false
	}

	c.lastVersions = seen

	return true
}

func (c *SecurityChecker) evaluate(current, available string) (fixed []string, ok bool, message string, warn bool) {
	snapshot := c.currentSnapshot()
	if snapshot == nil {
		return nil, false, "Security check: no usable advisories, reporting update.", true
	}

	currentVersion, currentOK := parseVersion(current)
	availableVersion, availableOK := parseVersion(available)
	if !currentOK || !availableOK {
		return nil, false, fmt.Sprintf("Security check: can not parse versions %q and %q, reporting update.", current, available), true
	}

	for _, fix := range snapshot.fixes {
		if fix.fixes(currentVersion, availableVersion) {
			fixed = append(fixed, fix.id())
		}
	}

	if len(fixed) == 0 {
		return nil, true, fmt.Sprintf("Security check: update %s -> %s contains no known security fixes.", current, available), false
	}

	slices.Sort(fixed)
	slices.Reverse(fixed)

	return fixed, true, fmt.Sprintf("Security check: update %s -> %s contains fixes for %d vulnerabilities: %s.",
		current, available, len(fixed), strings.Join(fixed, ", ")), false
}

func (c *SecurityChecker) logResult(warn bool, message string) {
	if c == nil {
		return
	}

	if !c.results.changed(message) {
		return
	}

	if warn {
		c.log.Warn(message)
		return
	}

	c.log.Info(message)
}

type changeOnlyLogger struct {
	mu   sync.Mutex
	last string
}

func (l *changeOnlyLogger) changed(message string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if message == l.last {
		return false
	}

	l.last = message

	return true
}

func (l *changeOnlyLogger) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.last = ""
}

package metrics

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
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

	mu       sync.RWMutex
	snapshot *advisorySnapshot

	lastVersions versionPair

	results changeOnlyLogger
}

type versionPair struct {
	current   string
	available string
}

func NewSecurityChecker(log logrus.FieldLogger, userAgent string) *SecurityChecker {
	return &SecurityChecker{
		log:     log,
		fetcher: newAdvisoryFetcher(userAgent),
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
	c.logLastResult()

	return nil
}

func (c *SecurityChecker) logLastResult() {
	c.mu.RLock()
	seen := c.lastVersions
	c.mu.RUnlock()

	if seen == (versionPair{}) {
		return
	}

	_, _, message, warn := c.evaluate(seen.current, seen.available)
	c.logResult(warn, message)
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

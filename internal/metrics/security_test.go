package metrics

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func testChecker(snapshot *advisorySnapshot) *SecurityChecker {
	log := logrus.New()
	log.SetOutput(io.Discard)

	return &SecurityChecker{log: log, snapshot: snapshot}
}

func testCheckerWithLog(snapshot *advisorySnapshot) (*SecurityChecker, *bytes.Buffer) {
	var buf bytes.Buffer

	log := logrus.New()
	log.SetOutput(&buf)

	return &SecurityChecker{log: log, snapshot: snapshot}, &buf
}

func countLines(buf *bytes.Buffer) int {
	count := 0
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}

	return count
}

func testSnapshot(patched ...string) *advisorySnapshot {
	fix := advisoryFix{ghsaID: "GHSA-test"}
	for _, raw := range patched {
		parsed, _ := parseVersion(raw)
		fix.patchedVersions = append(fix.patchedVersions, parsed)
	}

	return &advisorySnapshot{fixes: []advisoryFix{fix}, fetchedAt: time.Now()}
}

type testFix struct {
	cve     string
	patched string
}

func testSnapshotOf(fixes ...testFix) *advisorySnapshot {
	snapshot := &advisorySnapshot{fetchedAt: time.Now()}
	for _, f := range fixes {
		parsed, _ := parseVersion(f.patched)
		snapshot.fixes = append(snapshot.fixes, advisoryFix{
			ghsaID:          "GHSA-for-" + f.cve,
			cveID:           f.cve,
			patchedVersions: []version{parsed},
		})
	}

	return snapshot
}

func TestAvailable(t *testing.T) {
	fresh := testSnapshot("34.0.1")
	stale := testSnapshot("34.0.1")
	stale.fetchedAt = time.Now().Add(-advisoriesMaxAge - time.Hour)

	tt := []struct {
		desc     string
		snapshot *advisorySnapshot
		want     bool
	}{
		{"no snapshot yet", nil, false},
		{"snapshot is fresh", fresh, true},
		{"snapshot is stale", stale, false},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			if got := testChecker(tc.snapshot).Available(); got != tc.want {
				t.Errorf("Available() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNilCheckerAnswersUnknown(t *testing.T) {
	var checker *SecurityChecker

	if checker.Available() {
		t.Error("Available() = true on a nil checker, want false")
	}

	fixed, ok := checker.Check("34.0.0.1", "34.0.3.1")
	if ok {
		t.Error("Check() answered on a nil checker, want no answer")
	}

	if fixed != nil {
		t.Errorf("Check() = %v on a nil checker, want nil", fixed)
	}
}

func TestCheck(t *testing.T) {
	stale := testSnapshot("34.0.1")
	stale.fetchedAt = time.Now().Add(-advisoriesMaxAge - time.Hour)

	withCVE := testSnapshotOf(testFix{cve: "CVE-2026-0001", patched: "34.0.1"})

	tt := []struct {
		desc      string
		snapshot  *advisorySnapshot
		current   string
		available string
		wantFixed []string
		wantOK    bool
	}{
		{"no snapshot yet", nil, "34.0.0.1", "34.0.3.1", nil, false},
		{"snapshot is stale", stale, "34.0.0.1", "34.0.3.1", nil, false},
		{"version did not parse", withCVE, "34.0.0 RC1", "34.0.3.1", nil, false},
		{"a fix was found", withCVE, "34.0.0.1", "34.0.3.1", []string{"CVE-2026-0001"}, true},
		{"no fixes", withCVE, "34.0.2.1", "34.0.3.1", nil, true},
		{
			// Some records have no CVE number assigned, and then the GHSA goes into the result.
			desc:      "the GHSA is used when there is no CVE number",
			snapshot:  &advisorySnapshot{fetchedAt: time.Now(), fixes: []advisoryFix{{ghsaID: "GHSA-only", patchedVersions: []version{{34, 0, 1}}}}},
			current:   "34.0.0.1",
			available: "34.0.3.1",
			wantFixed: []string{"GHSA-only"},
			wantOK:    true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			fixed, ok := testChecker(tc.snapshot).Check(tc.current, tc.available)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}

			if !ok {
				return
			}

			if len(fixed) != len(tc.wantFixed) {
				t.Fatalf("fixed = %v, want %v", fixed, tc.wantFixed)
			}

			for i, want := range tc.wantFixed {
				if fixed[i] != want {
					t.Errorf("fixed[%d] = %q, want %q", i, fixed[i], want)
				}
			}
		})
	}
}

// Check must collect every match rather than stop at the first one, and return them in a
// deterministic order: the list goes to the log, and a reshuffled order would read as a
// new result.
func TestCheckCollectsAllSortedNewestFirst(t *testing.T) {
	snapshot := testSnapshotOf(
		testFix{cve: "CVE-2025-0002", patched: "34.0.1"},
		testFix{cve: "CVE-2026-0001", patched: "34.0.2"},
		testFix{cve: "CVE-2024-0003", patched: "34.0.3"},
		// This fix is already installed and must not reach the result.
		testFix{cve: "CVE-2020-9999", patched: "34.0.0"},
	)

	fixed, ok := testChecker(snapshot).Check("34.0.0.1", "34.0.3.1")
	if !ok {
		t.Fatal("Check() could not answer")
	}

	want := []string{"CVE-2026-0001", "CVE-2025-0002", "CVE-2024-0003"}
	if len(fixed) != len(want) {
		t.Fatalf("fixed = %v, want %v", fixed, want)
	}

	for i := range want {
		if fixed[i] != want[i] {
			t.Fatalf("fixed = %v, want %v", fixed, want)
		}
	}
}

// Check is called on every scrape, so an identical result must not be repeated in the
// log. The line has to appear once and then stay silent until the result changes.
func TestCheckLogsOnlyOnChange(t *testing.T) {
	snapshot := testSnapshotOf(testFix{cve: "CVE-2026-0001", patched: "34.0.1"})
	checker, buf := testCheckerWithLog(snapshot)

	for range 5 {
		checker.Check("34.0.0.1", "34.0.3.1")
	}

	if got := countLines(buf); got != 1 {
		t.Errorf("five identical checks produced %d log lines, want 1:\n%s", got, buf.String())
	}

	if !strings.Contains(buf.String(), "CVE-2026-0001") {
		t.Errorf("the log has no vulnerability number:\n%s", buf.String())
	}

	// The Nextcloud version changed, so the result differs and the line must appear.
	buf.Reset()
	checker.Check("34.0.2.1", "34.0.3.1")

	if got := countLines(buf); got != 1 {
		t.Errorf("after the version change there were %d log lines, want 1:\n%s", got, buf.String())
	}

	// And it goes quiet again while the result stays the same.
	buf.Reset()
	checker.Check("34.0.2.1", "34.0.3.1")

	if got := countLines(buf); got != 0 {
		t.Errorf("repeating the same result produced %d log lines, want 0:\n%s", got, buf.String())
	}
}

// The warning about unavailable data must not repeat on every scrape either.
func TestCheckWarningLogsOnlyOnce(t *testing.T) {
	checker, buf := testCheckerWithLog(nil)

	for range 3 {
		checker.Check("34.0.0.1", "34.0.3.1")
	}

	if got := countLines(buf); got != 1 {
		t.Errorf("three checks without data produced %d log lines, want 1:\n%s", got, buf.String())
	}
}

// refresh parses the GitHub data and must print the verdict again even when its wording
// matches the previous one: the list of vulnerabilities has to reach stdout after every
// fetch, not once per process lifetime.
func TestRefreshLogsAdvisoriesAndRepeatsResult(t *testing.T) {
	const page = `[{
		"ghsa_id": "GHSA-1",
		"cve_id": "CVE-2026-0001",
		"vulnerabilities": [{
			"package": {"ecosystem": "nextcloud", "name": "Server"},
			"patched_versions": "34.0.1"
		}]
	}]`

	checker, buf := testCheckerWithLog(nil)
	checker.fetcher = testFetcher(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, page)
	})

	if err := checker.refresh(context.Background()); err != nil {
		t.Fatalf("refresh() failed: %s", err)
	}

	checker.Check("34.0.0.1", "34.0.3.1")

	if !strings.Contains(buf.String(), "loaded 1 advisories") {
		t.Errorf("the log has no message about the load:\n%s", buf.String())
	}

	if !strings.Contains(buf.String(), "CVE-2026-0001") {
		t.Errorf("the log has no vulnerability number:\n%s", buf.String())
	}

	// The same result after a new fetch must appear in the log again.
	buf.Reset()

	if err := checker.refresh(context.Background()); err != nil {
		t.Fatalf("second refresh() failed: %s", err)
	}

	checker.Check("34.0.0.1", "34.0.3.1")

	if !strings.Contains(buf.String(), "CVE-2026-0001") {
		t.Errorf("the verdict was not printed again after a repeated fetch:\n%s", buf.String())
	}
}

// The verdict has to reach the log on the fact of the advisories being loaded, with no
// scrape involved: the line listing the CVEs must not depend on whether anyone pulled
// /metrics.
func TestRefreshLogsResultWithoutScrape(t *testing.T) {
	const page = `[{
		"ghsa_id": "GHSA-1",
		"cve_id": "CVE-2026-61527",
		"vulnerabilities": [{
			"package": {"ecosystem": "nextcloud", "name": "Server"},
			"patched_versions": "33.0.8"
		}]
	}]`

	checker, buf := testCheckerWithLog(nil)
	checker.fetcher = testFetcher(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, page)
	})

	// The single scrape reports the versions and prints the verdict: before it the fetch
	// had nothing to say about the server.
	checker.Check("33.0.4.1", "33.0.8.2")

	// There are no scrapes after this, and the next fetch must print the verdict itself.
	buf.Reset()

	if err := checker.refresh(context.Background()); err != nil {
		t.Fatalf("refresh() failed: %s", err)
	}

	if !strings.Contains(buf.String(), "CVE-2026-61527") {
		t.Errorf("the fetch did not print the verdict without a scrape:\n%s", buf.String())
	}

	if !strings.Contains(buf.String(), "33.0.4.1 -> 33.0.8.2") {
		t.Errorf("the verdict is missing the version pair from the last scrape:\n%s", buf.String())
	}
}

// A response without a single usable Nextcloud Server record is broken data, not "there
// are no vulnerabilities". The old snapshot must survive such a fetch.
func TestRefreshKeepsSnapshotOnUnusableResponse(t *testing.T) {
	checker, _ := testCheckerWithLog(testSnapshot("34.0.1"))
	checker.fetcher = testFetcher(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[{"ghsa_id":"GHSA-talk","vulnerabilities":[{"package":{"ecosystem":"nextcloud","name":"Talk"},"patched_versions":"21.0.1"}]}]`)
	})

	if err := checker.refresh(context.Background()); err == nil {
		t.Fatal("refresh() succeeded on a response without usable advisories, want an error")
	}

	if !checker.Available() {
		t.Error("Available() = false after a failed refresh, the previous snapshot must survive")
	}
}

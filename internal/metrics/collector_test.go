package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/xperimental/nextcloud-exporter/serverinfo"
)

// collectedUpdate runs collectUpdate and parses the single metric it produces.
func collectedUpdate(t *testing.T, current, available string, updateAvailable bool, security *SecurityChecker) (float64, map[string]string) {
	t.Helper()

	status := &serverinfo.ServerInfo{}
	status.Data.Nextcloud.System.Version = current
	status.Data.Nextcloud.System.Update.Available = updateAvailable
	status.Data.Nextcloud.System.Update.AvailableVersion = available

	// A buffered channel: collectUpdate writes to it synchronously and the test has no reader.
	ch := make(chan prometheus.Metric, 4)
	if err := collectUpdate(ch, status, security); err != nil {
		t.Fatalf("collectUpdate() failed: %s", err)
	}
	close(ch)

	metric := <-ch
	if metric == nil {
		t.Fatal("collectUpdate() emitted no metric")
	}

	var parsed dto.Metric
	if err := metric.Write(&parsed); err != nil {
		t.Fatalf("can not read metric: %s", err)
	}

	labels := make(map[string]string, len(parsed.Label))
	for _, label := range parsed.Label {
		labels[label.GetName()] = label.GetValue()
	}

	return parsed.GetGauge().GetValue(), labels
}

func TestCollectUpdate(t *testing.T) {
	fresh := testSnapshotOf(testFix{cve: "CVE-2026-0001", patched: "34.0.1"})
	stale := testSnapshotOf(testFix{cve: "CVE-2026-0001", patched: "34.0.1"})
	stale.fetchedAt = time.Now().Add(-advisoriesMaxAge - time.Hour)

	// Five fixes inside the update range.
	many := testSnapshotOf(
		testFix{cve: "CVE-2022-0005", patched: "34.0.1"},
		testFix{cve: "CVE-2026-0001", patched: "34.0.1"},
		testFix{cve: "CVE-2025-0002", patched: "34.0.2"},
		testFix{cve: "CVE-2023-0004", patched: "34.0.2"},
		testFix{cve: "CVE-2024-0003", patched: "34.0.3"},
	)

	tt := []struct {
		desc            string
		security        *SecurityChecker
		current         string
		available       string
		updateAvailable bool
		wantValue       float64
		wantAvailable   string
	}{
		{
			desc:            "no checker at all",
			security:        nil,
			current:         "34.0.0.1",
			available:       "34.0.3.1",
			updateAvailable: true,
			wantValue:       1,
			wantAvailable:   "false",
		},
		{
			desc:            "no data yet, report the update",
			security:        testChecker(nil),
			current:         "34.0.0.1",
			available:       "34.0.3.1",
			updateAvailable: true,
			wantValue:       1,
			wantAvailable:   "false",
		},
		{
			desc:            "data is stale, report the update",
			security:        testChecker(stale),
			current:         "34.0.2.1",
			available:       "34.0.3.1",
			updateAvailable: true,
			wantValue:       1,
			wantAvailable:   "false",
		},
		{
			desc:            "a security fix is present",
			security:        testChecker(fresh),
			current:         "34.0.0.1",
			available:       "34.0.3.1",
			updateAvailable: true,
			wantValue:       1,
			wantAvailable:   "true",
		},
		{
			desc:            "update without security fixes",
			security:        testChecker(fresh),
			current:         "34.0.2.1",
			available:       "34.0.3.1",
			updateAvailable: true,
			wantValue:       0,
			wantAvailable:   "true",
		},
		{
			// Several fixes at once: this does not affect the metric value, the list goes
			// to the log.
			desc:            "several security fixes",
			security:        testChecker(many),
			current:         "34.0.0.1",
			available:       "34.0.3.1",
			updateAvailable: true,
			wantValue:       1,
			wantAvailable:   "true",
		},
		{
			// The label describes the state of the source, so it is meaningful even when
			// there is no update.
			desc:            "no update at all",
			security:        testChecker(fresh),
			current:         "34.0.3.1",
			available:       "",
			updateAvailable: false,
			wantValue:       0,
			wantAvailable:   "true",
		},
		{
			// Nextcloud sets the update flag even when the version is the same.
			desc:            "update flag with matching versions",
			security:        testChecker(fresh),
			current:         "34.0.3.1",
			available:       "34.0.3.1",
			updateAvailable: true,
			wantValue:       0,
			wantAvailable:   "true",
		},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			value, labels := collectedUpdate(t, tc.current, tc.available, tc.updateAvailable, tc.security)

			if value != tc.wantValue {
				t.Errorf("value = %v, want %v", value, tc.wantValue)
			}

			if got := labels["advisories_available"]; got != tc.wantAvailable {
				t.Errorf("advisories_available = %q, want %q", got, tc.wantAvailable)
			}

			// The existing labels must stay in place and keep their meaning.
			if got := labels["version"]; got != tc.current {
				t.Errorf("version = %q, want %q", got, tc.current)
			}

			if got := labels["available_version"]; got != tc.available {
				t.Errorf("available_version = %q, want %q", got, tc.available)
			}
		})
	}
}

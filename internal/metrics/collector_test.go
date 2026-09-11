package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/xperimental/nextcloud-exporter/serverinfo"
)

// collectedUpdate прогоняет collectUpdate и разбирает единственную полученную метрику.
func collectedUpdate(t *testing.T, current, available string, updateAvailable bool, security *SecurityChecker) (float64, map[string]string) {
	t.Helper()

	status := &serverinfo.ServerInfo{}
	status.Data.Nextcloud.System.Version = current
	status.Data.Nextcloud.System.Update.Available = updateAvailable
	status.Data.Nextcloud.System.Update.AvailableVersion = available

	// Канал с буфером: collectUpdate пишет в него синхронно, читателя в тесте нет.
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

	// Пять исправлений в диапазоне обновления.
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
			desc:            "проверяльщика нет",
			security:        nil,
			current:         "34.0.0.1",
			available:       "34.0.3.1",
			updateAvailable: true,
			wantValue:       1,
			wantAvailable:   "false",
		},
		{
			desc:            "данных ещё нет, сообщаем об обновлении",
			security:        testChecker(nil),
			current:         "34.0.0.1",
			available:       "34.0.3.1",
			updateAvailable: true,
			wantValue:       1,
			wantAvailable:   "false",
		},
		{
			desc:            "данные просрочены, сообщаем об обновлении",
			security:        testChecker(stale),
			current:         "34.0.2.1",
			available:       "34.0.3.1",
			updateAvailable: true,
			wantValue:       1,
			wantAvailable:   "false",
		},
		{
			desc:            "есть исправление безопасности",
			security:        testChecker(fresh),
			current:         "34.0.0.1",
			available:       "34.0.3.1",
			updateAvailable: true,
			wantValue:       1,
			wantAvailable:   "true",
		},
		{
			desc:            "обновление без исправлений безопасности",
			security:        testChecker(fresh),
			current:         "34.0.2.1",
			available:       "34.0.3.1",
			updateAvailable: true,
			wantValue:       0,
			wantAvailable:   "true",
		},
		{
			// Несколько исправлений сразу: на значение метрики это не влияет, список
			// уходит в лог.
			desc:            "несколько исправлений безопасности",
			security:        testChecker(many),
			current:         "34.0.0.1",
			available:       "34.0.3.1",
			updateAvailable: true,
			wantValue:       1,
			wantAvailable:   "true",
		},
		{
			// Метка описывает состояние источника, поэтому осмысленна и когда обновления нет.
			desc:            "обновления нет вовсе",
			security:        testChecker(fresh),
			current:         "34.0.3.1",
			available:       "",
			updateAvailable: false,
			wantValue:       0,
			wantAvailable:   "true",
		},
		{
			// Nextcloud выставляет флаг обновления и когда версия та же самая.
			desc:            "флаг обновления при совпадающих версиях",
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

			// Существующие метки должны остаться на месте и не поменять смысл.
			if got := labels["version"]; got != tc.current {
				t.Errorf("version = %q, want %q", got, tc.current)
			}

			if got := labels["available_version"]; got != tc.available {
				t.Errorf("available_version = %q, want %q", got, tc.available)
			}
		})
	}
}

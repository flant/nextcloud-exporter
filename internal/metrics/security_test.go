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

// testChecker собирает SecurityChecker вручную, минуя NewSecurityChecker, чтобы задать
// снимок напрямую. Тесты лежат в том же пакете, поэтому неэкспортированные поля доступны.
func testChecker(snapshot *advisorySnapshot) *SecurityChecker {
	log := logrus.New()
	// io.Discard, а не nil: logrus пишет в этот writer безусловно и на nil падает.
	log.SetOutput(io.Discard)

	return &SecurityChecker{log: log, snapshot: snapshot}
}

// testCheckerWithLog отдаёт проверяльщик вместе с буфером, куда пишется лог.
func testCheckerWithLog(snapshot *advisorySnapshot) (*SecurityChecker, *bytes.Buffer) {
	var buf bytes.Buffer

	log := logrus.New()
	log.SetOutput(&buf)

	return &SecurityChecker{log: log, snapshot: snapshot}, &buf
}

// countLines считает непустые строки в логе.
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

// testFix — одна запись для снимка: номер уязвимости и версия, где она исправлена.
type testFix struct {
	cve     string
	patched string
}

// testSnapshotOf собирает снимок из нескольких записей. Порядок записей в снимке
// намеренно не совпадает с ожидаемым порядком в результате: Check обязан сортировать сам.
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
		{"снимка ещё нет", nil, false},
		{"снимок свежий", fresh, true},
		{"снимок просрочен", stale, false},
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

// Проверяльщик равен nil, когда метрика обновления выключена. Вызывающий не обязан
// проверять это сам, поэтому методы обязаны отвечать "не знаю", а не падать.
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
		{"снимка ещё нет", nil, "34.0.0.1", "34.0.3.1", nil, false},
		{"снимок просрочен", stale, "34.0.0.1", "34.0.3.1", nil, false},
		{"версия не разобралась", withCVE, "34.0.0 RC1", "34.0.3.1", nil, false},
		{"исправление найдено", withCVE, "34.0.0.1", "34.0.3.1", []string{"CVE-2026-0001"}, true},
		{"исправлений нет", withCVE, "34.0.2.1", "34.0.3.1", nil, true},
		{
			// У части записей номер CVE не присвоен, тогда в результат идёт GHSA.
			desc:      "без номера CVE используется GHSA",
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

// Check обязан собрать все совпадения, а не остановиться на первом, и отдать их в
// детерминированном порядке: список уходит в лог, и переставленный порядок читался бы
// как новый результат.
func TestCheckCollectsAllSortedNewestFirst(t *testing.T) {
	snapshot := testSnapshotOf(
		testFix{cve: "CVE-2025-0002", patched: "34.0.1"},
		testFix{cve: "CVE-2026-0001", patched: "34.0.2"},
		testFix{cve: "CVE-2024-0003", patched: "34.0.3"},
		// Это исправление уже установлено, в результат попасть не должно.
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

// Check вызывается на каждый скрейп, поэтому одинаковый результат не должен повторяться
// в логе. Строка обязана появиться один раз и потом молчать, пока результат не изменится.
func TestCheckLogsOnlyOnChange(t *testing.T) {
	snapshot := testSnapshotOf(testFix{cve: "CVE-2026-0001", patched: "34.0.1"})
	checker, buf := testCheckerWithLog(snapshot)

	for range 5 {
		checker.Check("34.0.0.1", "34.0.3.1")
	}

	if got := countLines(buf); got != 1 {
		t.Errorf("пять одинаковых проверок дали %d строк лога, ожидалась 1:\n%s", got, buf.String())
	}

	if !strings.Contains(buf.String(), "CVE-2026-0001") {
		t.Errorf("в логе нет номера уязвимости:\n%s", buf.String())
	}

	// Изменилась версия Nextcloud — результат другой, значит строка должна появиться.
	buf.Reset()
	checker.Check("34.0.2.1", "34.0.3.1")

	if got := countLines(buf); got != 1 {
		t.Errorf("после смены версии получено %d строк лога, ожидалась 1:\n%s", got, buf.String())
	}

	// И снова молчит, пока результат тот же.
	buf.Reset()
	checker.Check("34.0.2.1", "34.0.3.1")

	if got := countLines(buf); got != 0 {
		t.Errorf("повтор того же результата дал %d строк лога, ожидалось 0:\n%s", got, buf.String())
	}
}

// Предупреждение о недоступных данных тоже не должно повторяться на каждом скрейпе.
func TestCheckWarningLogsOnlyOnce(t *testing.T) {
	checker, buf := testCheckerWithLog(nil)

	for range 3 {
		checker.Check("34.0.0.1", "34.0.3.1")
	}

	if got := countLines(buf); got != 1 {
		t.Errorf("три проверки без данных дали %d строк лога, ожидалась 1:\n%s", got, buf.String())
	}
}

// refresh разбирает данные GitHub и обязан заново вывести разбор, даже если словесно
// результат совпал с предыдущим: список уязвимостей должен попадать в stdout после
// каждой выкачки, а не один раз за жизнь процесса.
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
		t.Errorf("в логе нет сообщения о загрузке:\n%s", buf.String())
	}

	if !strings.Contains(buf.String(), "CVE-2026-0001") {
		t.Errorf("в логе нет номера уязвимости:\n%s", buf.String())
	}

	// Тот же результат после новой выкачки обязан появиться в логе снова.
	buf.Reset()

	if err := checker.refresh(context.Background()); err != nil {
		t.Fatalf("second refresh() failed: %s", err)
	}

	checker.Check("34.0.0.1", "34.0.3.1")

	if !strings.Contains(buf.String(), "CVE-2026-0001") {
		t.Errorf("после повторной выкачки разбор не выведен заново:\n%s", buf.String())
	}
}

// Ответ без единой пригодной записи про Nextcloud Server — это сломанные данные, а не
// "уязвимостей нет". Старый снимок обязан пережить такую выкачку.
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

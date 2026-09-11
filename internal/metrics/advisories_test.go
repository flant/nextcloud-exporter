package metrics

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsNextcloudServer(t *testing.T) {
	accepted := []advisoryPackage{
		{Ecosystem: "nextcloud", Name: "Server"},
		{Ecosystem: "Nextcloud", Name: "server"},
		{Ecosystem: " nextcloud ", Name: " Nextcloud Server "},
		{Ecosystem: "nextcloud", Name: "nextcloud/server"},
		// Примерно у пятой части записей ecosystem не заполнен, продукт назван полным
		// именем. Без этого терялся 21 реальный advisory.
		{Ecosystem: "", Name: "Nextcloud Server"},
	}
	for _, pkg := range accepted {
		if !isNextcloudServer(pkg) {
			t.Errorf("isNextcloudServer(%+v) = false, want true", pkg)
		}
	}

	rejected := []advisoryPackage{
		// Платная редакция: версии из четырёх чисел без публичных релизов.
		{Ecosystem: "nextcloud enterprise", Name: "Server"},
		{Ecosystem: "nextcloud entreprise", Name: "Server"},
		{Ecosystem: "nextcloud", Name: "Enterprise Server"},
		// Другие продукты Nextcloud с пересекающимися номерами версий.
		{Ecosystem: "nextcloud", Name: "Talk"},
		{Ecosystem: "nextcloud", Name: "Deck"},
		{Ecosystem: "composer", Name: "nextcloud/server"},
		// Пустой ecosystem не должен пропускать чужие продукты.
		{Ecosystem: "", Name: "Nextcloud Talk"},
		{Ecosystem: "", Name: "Nextcloud Mail"},
		{Ecosystem: "", Name: "Nextcloud Android Client"},
	}
	for _, pkg := range rejected {
		if isNextcloudServer(pkg) {
			t.Errorf("isNextcloudServer(%+v) = true, want false", pkg)
		}
	}
}

func TestParsePatchedVersions(t *testing.T) {
	tt := []struct {
		desc string
		vuln advisoryVulnerability
		want []string
	}{
		{
			desc: "обычный список по одной версии на ветку",
			vuln: advisoryVulnerability{
				VulnerableVersionRange: ">= 32.0.10, >= 33.0.4, >= 34.0.0",
				PatchedVersions:        "32.0.12, 33.0.6, 34.0.1",
			},
			want: []string{"32.0.12", "33.0.6", "34.0.1"},
		},
		{
			desc: "одна версия без оператора",
			vuln: advisoryVulnerability{PatchedVersions: "31.0.1"},
			want: []string{"31.0.1"},
		},
		{
			// CVE-2025-47791: поля перепутаны местами.
			desc: "перепутанные поля берутся из диапазона",
			vuln: advisoryVulnerability{
				VulnerableVersionRange: "28.0.13, 29.0.10, 30.0.3",
				PatchedVersions:        ">= 28.0.0, >= 29.0.0, >= 30.0.0",
			},
			want: []string{"28.0.13", "29.0.10", "30.0.3"},
		},
		{
			desc: "неравенства в обоих полях дают пусто",
			vuln: advisoryVulnerability{
				VulnerableVersionRange: ">=32.0.0, >=33.0.0",
				PatchedVersions:        ">= 32.0.0",
			},
			want: nil,
		},
		{
			desc: "пробел в начале не мешает",
			vuln: advisoryVulnerability{PatchedVersions: " 29.0.13, 30.0.7"},
			want: []string{"29.0.13", "30.0.7"},
		},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			got := parsePatchedVersions(tc.vuln)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d versions %v, want %d %v", len(got), got, len(tc.want), tc.want)
			}

			for i, raw := range tc.want {
				if got[i].compare(mustParseVersion(t, raw)) != 0 {
					t.Errorf("version %d = %v, want %s", i, got[i], raw)
				}
			}
		})
	}
}

func TestParseFixes(t *testing.T) {
	withdrawn := "2025-01-01T00:00:00Z"
	serverVuln := advisoryVulnerability{
		Package:         advisoryPackage{Ecosystem: "nextcloud", Name: "Server"},
		PatchedVersions: "34.0.1",
	}

	tt := []struct {
		desc      string
		advisory  advisory
		wantFixes int
	}{
		{"обычная запись", advisory{GHSAID: "GHSA-ok", Vulnerabilities: []advisoryVulnerability{serverVuln}}, 1},
		{"отозванная отбрасывается", advisory{GHSAID: "GHSA-w", WithdrawnAt: &withdrawn, Vulnerabilities: []advisoryVulnerability{serverVuln}}, 0},
		{
			desc: "только платная редакция",
			advisory: advisory{GHSAID: "GHSA-ent", Vulnerabilities: []advisoryVulnerability{{
				Package:         advisoryPackage{Ecosystem: "nextcloud enterprise", Name: "Server"},
				PatchedVersions: "31.0.14.5",
			}}},
			wantFixes: 0,
		},
		{
			desc: "без разобранных версий",
			advisory: advisory{GHSAID: "GHSA-none", Vulnerabilities: []advisoryVulnerability{{
				Package:                advisoryPackage{Ecosystem: "nextcloud", Name: "Server"},
				VulnerableVersionRange: ">= 32.0.0",
				PatchedVersions:        ">= 32.0.0",
			}}},
			wantFixes: 0,
		},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			if got := parseFixes([]advisory{tc.advisory}); len(got) != tc.wantFixes {
				t.Errorf("parseFixes() returned %d fixes, want %d", len(got), tc.wantFixes)
			}
		})
	}
}

func TestAdvisoryFixID(t *testing.T) {
	withCVE := advisoryFix{ghsaID: "GHSA-x", cveID: "CVE-2026-0001"}
	if got := withCVE.id(); got != "CVE-2026-0001" {
		t.Errorf("id() = %q, want the CVE number", got)
	}

	// У части записей номер CVE ещё не присвоен.
	withoutCVE := advisoryFix{ghsaID: "GHSA-x"}
	if got := withoutCVE.id(); got != "GHSA-x" {
		t.Errorf("id() = %q, want the GHSA identifier", got)
	}
}

func TestAdvisoryFixFixes(t *testing.T) {
	// Реальная запись GHSA-99gw-ww6p-f2rr (CVE-2026-61527): исправлена в 32.0.12,
	// 33.0.6 и 34.0.1.
	threeBranches := []string{"32.0.12", "33.0.6", "34.0.1"}

	tt := []struct {
		desc      string
		patched   []string
		current   string
		available string
		want      bool
	}{
		{"исправление приедет с обновлением", threeBranches, "32.0.5.2", "32.0.14.1", true},
		{"исправление уже установлено", threeBranches, "32.0.12.1", "32.0.14.1", false},
		{"исправление приедет, другая ветка", threeBranches, "34.0.0.12", "34.0.3.1", true},
		{"исправление уже установлено, другая ветка", threeBranches, "34.0.2.1", "34.0.3.1", false},

		// Переход между ветками: правило про "уже установлено" обязано отбросить запись,
		// иначе актуальная старая ветка вечно давала бы ложное срабатывание.
		{"актуальны на старой ветке, переход на новую", threeBranches, "32.0.14.1", "33.0.6.1", false},
		{"устарели на старой ветке, переход на новую", threeBranches, "32.0.10.1", "33.0.6.1", true},

		{"исправление дальше доступной версии", threeBranches, "32.0.10.1", "32.0.11.1", false},
		{"все исправления ниже установленной", threeBranches, "34.0.1.1", "34.0.3.1", false},

		// Две версии одной ветки: сравнивать надо с большей, иначе 31.0.7 потеряется.
		{"две версии одной ветки", []string{"31.0.1", "31.0.7"}, "31.0.3.1", "31.0.9.1", true},
		{"две версии одной ветки, обе установлены", []string{"31.0.1", "31.0.7"}, "31.0.8.1", "31.0.9.1", false},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			fix := advisoryFix{ghsaID: "GHSA-test"}
			for _, raw := range tc.patched {
				fix.patchedVersions = append(fix.patchedVersions, mustParseVersion(t, raw))
			}

			got := fix.fixes(mustParseVersion(t, tc.current), mustParseVersion(t, tc.available))
			if got != tc.want {
				t.Errorf("fixes(%s -> %s) = %v, want %v", tc.current, tc.available, got, tc.want)
			}
		})
	}
}

func TestNextPageURL(t *testing.T) {
	const current = "https://api.github.com/repos/nextcloud/security-advisories/security-advisories?per_page=100"

	tt := []struct {
		desc    string
		header  string
		want    string
		wantErr bool
	}{
		{
			// GitHub отдаёт следующую страницу по другому пути, с числовым
			// идентификатором репозитория. Сверять путь нельзя, обход сломается.
			desc:   "другой путь на том же хосте принимается",
			header: `<https://api.github.com/repositories/63675426/security-advisories?after=xyz>; rel="next"`,
			want:   "https://api.github.com/repositories/63675426/security-advisories?after=xyz",
		},
		{
			// Отвергнутая ссылка это ошибка, а не конец списка: иначе обход молча
			// вернул бы только уже прочитанные страницы.
			desc:    "посторонний хост это ошибка",
			header:  `<https://evil.example.com/security-advisories?after=xyz>; rel="next"`,
			wantErr: true,
		},
		{
			desc:    "испорченная ссылка это ошибка",
			header:  `https://api.github.com/a?p=2; rel="next"`,
			wantErr: true,
		},
		{
			desc:   "next среди нескольких ссылок",
			header: `<https://api.github.com/a?p=1>; rel="prev", <https://api.github.com/a?p=3>; rel="next"`,
			want:   "https://api.github.com/a?p=3",
		},
		// Отсутствие ссылки на следующую страницу это нормальный конец обхода.
		{desc: "без rel=next", header: `<https://api.github.com/a>; rel="last"`},
		{desc: "пустой заголовок"},
		{desc: "мусор", header: "garbage"},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			got, err := nextPageURL(current, tc.header)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("nextPageURL() = %q, want an error", got)
				}

				return
			}

			if err != nil {
				t.Fatalf("nextPageURL() failed: %s", err)
			}

			if got != tc.want {
				t.Errorf("nextPageURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

// Обход не должен уходить на посторонний хост, но и молча останавливаться на нём тоже:
// уже прочитанные страницы это самые старые записи, и на них все свежие обновления
// безопасности выглядели бы как рядовые.
func TestFetchAllFailsOnForeignNextLink(t *testing.T) {
	fetcher := testFetcher(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", `<https://evil.example.com/advisories?after=xyz>; rel="next"`)
		fmt.Fprint(w, `[{"ghsa_id":"GHSA-1"}]`)
	})

	advisories, err := fetcher.fetchAll(context.Background())
	if err == nil {
		t.Fatalf("fetchAll() succeeded with %d advisories, want an error", len(advisories))
	}

	if advisories != nil {
		t.Errorf("fetchAll() returned %d advisories alongside the error, want none", len(advisories))
	}
}

// testFetcher отдаёт проверяльщику локальный сервер вместо GitHub.
func testFetcher(t *testing.T, handler http.HandlerFunc) *advisoryFetcher {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	fetcher := newAdvisoryFetcher("test-agent")
	fetcher.url = server.URL

	return fetcher
}

// Список advisories не помещается на одну страницу, поэтому обход обязан идти по
// заголовку Link и склеивать страницы.
func TestFetchAllFollowsPagination(t *testing.T) {
	var seenAgent string

	fetcher := testFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		seenAgent = r.Header.Get("User-Agent")

		switch r.URL.Query().Get("page") {
		case "":
			w.Header().Set("Link", fmt.Sprintf(`<http://%s/?page=2>; rel="next"`, r.Host))
			fmt.Fprint(w, `[{"ghsa_id":"GHSA-1"},{"ghsa_id":"GHSA-2"}]`)
		case "2":
			// Последняя страница: заголовка Link нет, обход должен остановиться.
			fmt.Fprint(w, `[{"ghsa_id":"GHSA-3"}]`)
		default:
			t.Errorf("unexpected page %q", r.URL.Query().Get("page"))
		}
	})

	advisories, err := fetcher.fetchAll(context.Background())
	if err != nil {
		t.Fatalf("fetchAll() failed: %s", err)
	}

	want := []string{"GHSA-1", "GHSA-2", "GHSA-3"}
	if len(advisories) != len(want) {
		t.Fatalf("got %d advisories, want %d", len(advisories), len(want))
	}

	for i, id := range want {
		if advisories[i].GHSAID != id {
			t.Errorf("advisory %d = %q, want %q", i, advisories[i].GHSAID, id)
		}
	}

	if seenAgent != "test-agent" {
		t.Errorf("User-Agent = %q, want %q", seenAgent, "test-agent")
	}
}

// Неполный список выглядел бы как отсутствие уязвимостей и мог бы скрыть обновление
// безопасности, поэтому ошибка на любой странице обязана отменить всю выкачку.
func TestFetchAllFailsOnPartialResult(t *testing.T) {
	tt := []struct {
		desc     string
		second   func(w http.ResponseWriter)
		wantText string
	}{
		{
			desc:     "вторая страница отвечает ошибкой",
			second:   func(w http.ResponseWriter) { w.WriteHeader(http.StatusForbidden) },
			wantText: "403",
		},
		{
			desc: "вторая страница отвечает мусором",
			second: func(w http.ResponseWriter) {
				fmt.Fprint(w, `not json`)
			},
			wantText: "can not parse",
		},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			fetcher := testFetcher(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("page") == "2" {
					tc.second(w)
					return
				}

				w.Header().Set("Link", fmt.Sprintf(`<http://%s/?page=2>; rel="next"`, r.Host))
				fmt.Fprint(w, `[{"ghsa_id":"GHSA-1"}]`)
			})

			advisories, err := fetcher.fetchAll(context.Background())
			if err == nil {
				t.Fatalf("fetchAll() succeeded with %d advisories, want an error", len(advisories))
			}

			if advisories != nil {
				t.Errorf("fetchAll() returned %d advisories alongside the error, want none", len(advisories))
			}
		})
	}
}

// Зацикленный на себя Link не должен приводить к бесконечному обходу.
func TestFetchAllStopsOnTooManyPages(t *testing.T) {
	fetcher := testFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", fmt.Sprintf(`<http://%s/?page=next>; rel="next"`, r.Host))
		fmt.Fprint(w, `[{"ghsa_id":"GHSA-1"}]`)
	})

	if _, err := fetcher.fetchAll(context.Background()); err == nil {
		t.Fatal("fetchAll() succeeded on an endless list, want an error")
	}
}

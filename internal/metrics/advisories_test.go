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
		// In roughly a fifth of the records the ecosystem is not filled in and the product
		// is named in full. Without this, 21 real advisories were lost.
		{Ecosystem: "", Name: "Nextcloud Server"},
	}
	for _, pkg := range accepted {
		if !isNextcloudServer(pkg) {
			t.Errorf("isNextcloudServer(%+v) = false, want true", pkg)
		}
	}

	rejected := []advisoryPackage{
		// The paid edition: four-number versions with no public releases.
		{Ecosystem: "nextcloud enterprise", Name: "Server"},
		{Ecosystem: "nextcloud entreprise", Name: "Server"},
		{Ecosystem: "nextcloud", Name: "Enterprise Server"},
		// Other Nextcloud products whose version numbers overlap with the server ones.
		{Ecosystem: "nextcloud", Name: "Talk"},
		{Ecosystem: "nextcloud", Name: "Deck"},
		{Ecosystem: "composer", Name: "nextcloud/server"},
		// An empty ecosystem must not let foreign products through.
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
			desc: "an ordinary list with one version per branch",
			vuln: advisoryVulnerability{
				VulnerableVersionRange: ">= 32.0.10, >= 33.0.4, >= 34.0.0",
				PatchedVersions:        "32.0.12, 33.0.6, 34.0.1",
			},
			want: []string{"32.0.12", "33.0.6", "34.0.1"},
		},
		{
			desc: "a single version without an operator",
			vuln: advisoryVulnerability{PatchedVersions: "31.0.1"},
			want: []string{"31.0.1"},
		},
		{
			// CVE-2025-47791: the fields are swapped.
			desc: "swapped fields are taken from the range",
			vuln: advisoryVulnerability{
				VulnerableVersionRange: "28.0.13, 29.0.10, 30.0.3",
				PatchedVersions:        ">= 28.0.0, >= 29.0.0, >= 30.0.0",
			},
			want: []string{"28.0.13", "29.0.10", "30.0.3"},
		},
		{
			desc: "inequalities in both fields yield nothing",
			vuln: advisoryVulnerability{
				VulnerableVersionRange: ">=32.0.0, >=33.0.0",
				PatchedVersions:        ">= 32.0.0",
			},
			want: nil,
		},
		{
			desc: "a leading space does not get in the way",
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
		{"an ordinary record", advisory{GHSAID: "GHSA-ok", Vulnerabilities: []advisoryVulnerability{serverVuln}}, 1},
		{"a withdrawn one is discarded", advisory{GHSAID: "GHSA-w", WithdrawnAt: &withdrawn, Vulnerabilities: []advisoryVulnerability{serverVuln}}, 0},
		{
			desc: "the paid edition only",
			advisory: advisory{GHSAID: "GHSA-ent", Vulnerabilities: []advisoryVulnerability{{
				Package:         advisoryPackage{Ecosystem: "nextcloud enterprise", Name: "Server"},
				PatchedVersions: "31.0.14.5",
			}}},
			wantFixes: 0,
		},
		{
			desc: "no parsable versions",
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

	// Some records have no CVE number assigned yet.
	withoutCVE := advisoryFix{ghsaID: "GHSA-x"}
	if got := withoutCVE.id(); got != "GHSA-x" {
		t.Errorf("id() = %q, want the GHSA identifier", got)
	}
}

func TestAdvisoryFixFixes(t *testing.T) {
	// The real record GHSA-99gw-ww6p-f2rr (CVE-2026-61527): fixed in 32.0.12, 33.0.6
	// and 34.0.1.
	threeBranches := []string{"32.0.12", "33.0.6", "34.0.1"}

	tt := []struct {
		desc      string
		patched   []string
		current   string
		available string
		want      bool
	}{
		{"the fix arrives with the update", threeBranches, "32.0.5.2", "32.0.14.1", true},
		{"the fix is already installed", threeBranches, "32.0.12.1", "32.0.14.1", false},
		{"the fix arrives, a different branch", threeBranches, "34.0.0.12", "34.0.3.1", true},
		{"the fix is already installed, a different branch", threeBranches, "34.0.2.1", "34.0.3.1", false},

		// Moving between branches: the "already installed" rule has to discard the record,
		// otherwise an up-to-date old branch would produce a false positive forever.
		{"up to date on the old branch, moving to the new one", threeBranches, "32.0.14.1", "33.0.6.1", false},
		{"behind on the old branch, moving to the new one", threeBranches, "32.0.10.1", "33.0.6.1", true},

		{"the fix is beyond the available version", threeBranches, "32.0.10.1", "32.0.11.1", false},
		{"every fix is below the installed version", threeBranches, "34.0.1.1", "34.0.3.1", false},

		// Two versions of one branch: the higher one is what to compare against, otherwise
		// 31.0.7 is lost.
		{"two versions of one branch", []string{"31.0.1", "31.0.7"}, "31.0.3.1", "31.0.9.1", true},
		{"two versions of one branch, both installed", []string{"31.0.1", "31.0.7"}, "31.0.8.1", "31.0.9.1", false},
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
			// GitHub serves the next page under a different path, with the numeric
			// repository identifier. Checking the path would break the walk.
			desc:   "a different path on the same host is accepted",
			header: `<https://api.github.com/repositories/63675426/security-advisories?after=xyz>; rel="next"`,
			want:   "https://api.github.com/repositories/63675426/security-advisories?after=xyz",
		},
		{
			// A rejected link is an error, not the end of the list: otherwise the walk
			// would silently return only the pages already read.
			desc:    "a foreign host is an error",
			header:  `<https://evil.example.com/security-advisories?after=xyz>; rel="next"`,
			wantErr: true,
		},
		{
			desc:    "a malformed link is an error",
			header:  `https://api.github.com/a?p=2; rel="next"`,
			wantErr: true,
		},
		{
			desc:   "next among several links",
			header: `<https://api.github.com/a?p=1>; rel="prev", <https://api.github.com/a?p=3>; rel="next"`,
			want:   "https://api.github.com/a?p=3",
		},
		// The absence of a next-page link is the normal end of the walk.
		{desc: "no rel=next", header: `<https://api.github.com/a>; rel="last"`},
		{desc: "an empty header"},
		{desc: "garbage", header: "garbage"},
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

// The walk must not wander off to a foreign host, but it must not silently stop there
// either: the pages already read are the oldest records, and against them every recent
// security update would look like an ordinary one.
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

// testFetcher hands the checker a local server instead of GitHub.
func testFetcher(t *testing.T, handler http.HandlerFunc) *advisoryFetcher {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	fetcher := newAdvisoryFetcher("test-agent")
	fetcher.url = server.URL

	return fetcher
}

// The advisory list does not fit on a single page, so the walk has to follow the Link
// header and stitch the pages together.
func TestFetchAllFollowsPagination(t *testing.T) {
	var seenAgent string

	fetcher := testFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		seenAgent = r.Header.Get("User-Agent")

		switch r.URL.Query().Get("page") {
		case "":
			w.Header().Set("Link", fmt.Sprintf(`<http://%s/?page=2>; rel="next"`, r.Host))
			fmt.Fprint(w, `[{"ghsa_id":"GHSA-1"},{"ghsa_id":"GHSA-2"}]`)
		case "2":
			// The last page: there is no Link header and the walk must stop.
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

// An incomplete list would look like an absence of vulnerabilities and could hide a
// security update, so an error on any page has to cancel the entire fetch.
func TestFetchAllFailsOnPartialResult(t *testing.T) {
	tt := []struct {
		desc     string
		second   func(w http.ResponseWriter)
		wantText string
	}{
		{
			desc:     "the second page answers with an error",
			second:   func(w http.ResponseWriter) { w.WriteHeader(http.StatusForbidden) },
			wantText: "403",
		},
		{
			desc: "the second page answers with garbage",
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

// A Link header pointing at itself must not lead to an endless walk.
func TestFetchAllStopsOnTooManyPages(t *testing.T) {
	fetcher := testFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", fmt.Sprintf(`<http://%s/?page=next>; rel="next"`, r.Host))
		fmt.Fprint(w, `[{"ghsa_id":"GHSA-1"}]`)
	})

	if _, err := fetcher.fetchAll(context.Background()); err == nil {
		t.Fatal("fetchAll() succeeded on an endless list, want an error")
	}
}

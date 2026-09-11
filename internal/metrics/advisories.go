package metrics

// Fetching and parsing the security advisories of the nextcloud/security-advisories
// repository.
//
// This is the only source that answers the question "in which version was the
// vulnerability fixed". The global GitHub Advisory Database and OSV.dev are empty for
// Nextcloud, and the release notes do not mention security fixes at all, because such
// changes are merged from private forks and never reach the changelog.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// advisoriesURL is the entry point into the list of advisories.
	//
	// Sorting by publication date in ascending order is deliberate: pagination here is
	// cursor-based, and in that order new records are appended at the end while pages
	// already served do not shift. Sorting by updated would let a record edited in the
	// middle of the walk be skipped.
	advisoriesURL = "https://api.github.com/repos/nextcloud/security-advisories/security-advisories" +
		"?per_page=100&sort=published&direction=asc"

	// advisoriesHTTPTimeout is the timeout for a single request to GitHub.
	//
	// This is a separate timeout, unrelated to --timeout: that one bounds the wait for
	// Nextcloud inside a scrape and is usually measured in seconds, while this request
	// runs in the background and is in no hurry.
	advisoriesHTTPTimeout = 30 * time.Second

	// advisoriesMaxPages is a safeguard against walking pages forever.
	// There are three pages at the moment, so the margin is tenfold.
	advisoriesMaxPages = 10
)

// advisoryFix is the result of parsing one record: the versions in which the
// vulnerability is fixed. Parsing happens once per fetch, not on every scrape.
type advisoryFix struct {
	ghsaID          string
	cveID           string
	patchedVersions []version
}

// id returns the CVE number, or the GHSA identifier when there is none.
func (f advisoryFix) id() string {
	if f.cveID != "" {
		return f.cveID
	}

	return f.ghsaID
}

// fixes decides whether the vulnerability is closed by moving from current to available.
//
// A vulnerability record lists the versions in which it is fixed, one per supported
// branch, for example 32.0.12, 33.0.6 and 34.0.1. There are two rules.
//
// First: if the fix is already installed on our branch, the record does not concern us.
// The version to check is the highest one on our branch, not just any: if a record lists
// 31.0.1 and 31.0.7 while 31.0.3 is installed, 31.0.1 makes us look patched even though
// we do not have the 31.0.7 we need.
//
// Second: otherwise the vulnerability is closed if one of the patched versions is greater
// than the current one and no greater than the available one.
//
// Together the rules give the right answer across a branch change as well. Example:
// 32.0.14 is installed, 33.0.6 is available, and the fixes are listed as 32.0.12 and
// 33.0.6. The second rule on its own would call the update necessary, because 33.0.6 is
// greater than 32.0.14. But the first rule sees that we already have 32.0.12 and discards
// the record. Without it anyone who is fine on an older branch would get a false positive
// on every scrape.
func (f advisoryFix) fixes(current, available version) bool {
	var highestOnCurrentBranch version
	for _, patched := range f.patchedVersions {
		if patched.major() != current.major() {
			continue
		}

		if highestOnCurrentBranch == nil || patched.compare(highestOnCurrentBranch) > 0 {
			highestOnCurrentBranch = patched
		}
	}

	// The first rule.
	if highestOnCurrentBranch != nil && highestOnCurrentBranch.compare(current) <= 0 {
		return false
	}

	// The second rule.
	for _, patched := range f.patchedVersions {
		if current.compare(patched) < 0 && patched.compare(available) <= 0 {
			return true
		}
	}

	return false
}

// advisory is the subset of fields we need from one record of the GitHub response.
// The remaining fields are discarded: encoding/json ignores anything absent from the
// struct.
type advisory struct {
	GHSAID string `json:"ghsa_id"`

	// CVEID is not always filled in: some records have no CVE number assigned yet, and
	// then the field arrives as null. GHSAID is used in those cases, see advisoryFix.id.
	CVEID string `json:"cve_id"`

	// WithdrawnAt is a pointer so that a missing value (nil) can be told apart from a
	// filled one. A filled one means the record was withdrawn and must be ignored.
	WithdrawnAt *string `json:"withdrawn_at"`

	Vulnerabilities []advisoryVulnerability `json:"vulnerabilities"`
}

// advisoryVulnerability describes one affected product inside a record.
type advisoryVulnerability struct {
	Package advisoryPackage `json:"package"`

	// VulnerableVersionRange and PatchedVersions are free-form text filled in by hand, so
	// parsing has to tolerate garbage. See parsePatchedVersions for the details.
	VulnerableVersionRange string `json:"vulnerable_version_range"`
	PatchedVersions        string `json:"patched_versions"`
}

type advisoryPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// parseFixes turns the GitHub response into a list of fixes suitable for comparing
// versions. Withdrawn records and records with no parsable versions are discarded.
func parseFixes(advisories []advisory) []advisoryFix {
	var result []advisoryFix

	for _, item := range advisories {
		if item.WithdrawnAt != nil {
			continue
		}

		var patched []version
		for _, vulnerability := range item.Vulnerabilities {
			if !isNextcloudServer(vulnerability.Package) {
				continue
			}

			patched = append(patched, parsePatchedVersions(vulnerability)...)
		}

		if len(patched) == 0 {
			continue
		}

		result = append(result, advisoryFix{
			ghsaID:          item.GHSAID,
			cveID:           item.CVEID,
			patchedVersions: patched,
		})
	}

	return result
}

// nextcloudServerNames holds the names this data uses for Nextcloud Server itself.
//
// Matching against a list rather than searching for the substring "Server" matters: the
// same repository publishes advisories for the other Nextcloud products — Talk, Desktop,
// Deck, Tables — and their version numbers overlap with the server ones. A loose search
// would drag foreign versions into the comparison and produce false positives.
var nextcloudServerNames = map[string]bool{
	"server":           true,
	"nextcloud server": true,
	"nextcloud/server": true,
	"nextcloud":        true,
}

// isNextcloudServer picks out the records about the free edition of Nextcloud Server.
//
// The paid edition is published separately, under the ecosystem "nextcloud enterprise"
// (and in some records with the typo "nextcloud entreprise"), and its versions consist of
// four numbers that match no public release. It is not wanted here, and the ecosystem
// comparison cuts it off.
//
// An empty ecosystem is accepted: in roughly a fifth of the records that field is not
// filled in, and the product is named in full there instead ("Nextcloud Server",
// "Nextcloud Talk"). Selection by name handles those, whereas demanding a non-empty
// ecosystem would silently throw them away along with the vulnerabilities they
// describe.
func isNextcloudServer(pkg advisoryPackage) bool {
	ecosystem := strings.ToLower(strings.TrimSpace(pkg.Ecosystem))
	if ecosystem != "" && ecosystem != "nextcloud" {
		return false
	}

	return nextcloudServerNames[strings.ToLower(strings.TrimSpace(pkg.Name))]
}

// parsePatchedVersions extracts the patched versions from one vulnerability record.
//
// The patched_versions field is filled in by people and arrives in various shapes:
// "32.0.12, 33.0.6", ">=32.0.0, >=33.0.0" (no space), " >= 29.0.0, ..." (leading space),
// or plain "31.0.1". In some records the fields are swapped: patched_versions holds the
// inequalities while the versions themselves sit in vulnerable_version_range. Such
// records are recognised by the fact that patched_versions yielded no version at all
// while vulnerable_version_range yielded a clean list of numbers. A normal
// vulnerable_version_range almost always contains a comparison sign, so this fallback
// does not trigger on well-formed records.
func parsePatchedVersions(vulnerability advisoryVulnerability) []version {
	if versions := parseVersionList(vulnerability.PatchedVersions); len(versions) > 0 {
		return versions
	}

	return parseVersionList(vulnerability.VulnerableVersionRange)
}

// parseVersionList parses a comma-separated list of versions, discarding everything that
// is not a version: inequalities such as ">= 32.0.0", empty items, arbitrary text.
func parseVersionList(raw string) []version {
	var result []version

	for _, token := range strings.Split(raw, ",") {
		token = strings.TrimSpace(token)

		// This is what filters out range boundaries, which are not versions.
		if token == "" || strings.ContainsAny(token, "<>=~^") {
			continue
		}

		if parsed, ok := parseVersion(token); ok {
			result = append(result, parsed)
		}
	}

	return result
}

// advisoryFetcher downloads the list of advisories from GitHub.
type advisoryFetcher struct {
	client    *http.Client
	userAgent string

	// url is the address of the first page of the list. It is a field rather than the
	// constant used directly so that tests can substitute a local server for GitHub.
	url string
}

func newAdvisoryFetcher(userAgent string) *advisoryFetcher {
	return &advisoryFetcher{
		userAgent: userAgent,
		url:       advisoriesURL,
		client: &http.Client{
			Timeout: advisoriesHTTPTimeout,
			// Transport is deliberately left unset, so the default one is used and TLS
			// certificate verification stays on. The --tls-skip-verify flag applies to the
			// user's own Nextcloud server and must not extend to GitHub.
		},
	}
}

// fetchAll downloads every page of the advisory list.
//
// An error on any page stops the walk and returns nothing: an incomplete list would look
// like an absence of vulnerabilities and could hide a security update.
func (f *advisoryFetcher) fetchAll(ctx context.Context) ([]advisory, error) {
	var result []advisory

	next := f.url
	for page := 0; next != ""; page++ {
		if page >= advisoriesMaxPages {
			return nil, fmt.Errorf("too many pages, stopped after %d", advisoriesMaxPages)
		}

		advisories, link, err := f.fetchPage(ctx, next)
		if err != nil {
			return nil, err
		}

		result = append(result, advisories...)
		next = link
	}

	return result, nil
}

// fetchPage requests a single page and returns its contents together with the link to
// the next page (an empty string means this was the last one).
func (f *advisoryFetcher) fetchPage(ctx context.Context, pageURL string) ([]advisory, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", f.userAgent)

	res, err := f.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		// Exhausting the GitHub rate limit shows up as a 403 or a 429. It needs no special
		// handling: the next attempt follows after advisoriesRetryInterval, and the
		// remaining quota goes into the message so the reason is visible in the log.
		return nil, "", fmt.Errorf("unexpected status code %d (rate limit remaining: %q)",
			res.StatusCode, res.Header.Get("X-RateLimit-Remaining"))
	}

	var advisories []advisory
	if err := json.NewDecoder(res.Body).Decode(&advisories); err != nil {
		return nil, "", fmt.Errorf("can not parse advisories: %w", err)
	}

	next, err := nextPageURL(pageURL, res.Header.Get("Link"))
	if err != nil {
		return nil, "", err
	}

	return advisories, next, nil
}

// nextPageURL extracts the address of the next page from the Link header, which looks
// like this:
//
//	<https://api.github.com/repositories/63675426/security-advisories?after=...>; rel="next"
//
// An empty string with no error means this was the last page. An unusable link is an
// error rather than the end of the walk: stopping silently would hand over part of the
// list as if it were complete, and since it is sorted by ascending date, the oldest
// records would be the ones that survived and every recent security update would look
// like an ordinary one.
//
// Only the scheme and the host are checked. The path must not be: GitHub serves the next
// page under a different path, with the numeric repository identifier instead of its
// name. The host check is there so an intermediate proxy cannot divert the fetch to a
// foreign address.
func nextPageURL(currentURL, linkHeader string) (string, error) {
	current, err := url.Parse(currentURL)
	if err != nil {
		return "", fmt.Errorf("can not parse current page address %q: %w", currentURL, err)
	}

	for _, link := range strings.Split(linkHeader, ",") {
		parts := strings.Split(strings.TrimSpace(link), ";")
		if len(parts) < 2 {
			continue
		}

		isNext := false
		for _, part := range parts[1:] {
			if strings.EqualFold(strings.TrimSpace(part), `rel="next"`) {
				isNext = true
				break
			}
		}
		if !isNext {
			continue
		}

		address := strings.TrimSpace(parts[0])
		if !strings.HasPrefix(address, "<") || !strings.HasSuffix(address, ">") {
			return "", fmt.Errorf("malformed next link %q", address)
		}

		next, err := url.Parse(strings.Trim(address, "<>"))
		if err != nil {
			return "", fmt.Errorf("can not parse next link %q: %w", address, err)
		}

		if next.Scheme != current.Scheme || next.Host != current.Host {
			return "", fmt.Errorf("next link %q leaves host %q", next.String(), current.Host)
		}

		return next.String(), nil
	}

	return "", nil
}

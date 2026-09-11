package metrics

// Comparison of Nextcloud versions.
//
// Versions arrive here with a differing number of components: Nextcloud reports its own
// version as four numbers ("34.0.2.1"), while advisories name the patched versions with
// three ("34.0.1"). They cannot be compared as strings: "34.0.10" sorts below "34.0.9"
// lexicographically even though it is the later version.

import (
	"strconv"
	"strings"
)

// version is a version parsed into its numeric components.
type version []int

// parseVersion parses "34.0.2.1" into [34, 0, 2, 1].
// The second return value is false if the string is not a version.
func parseVersion(raw string) (version, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, false
	}

	parts := strings.Split(raw, ".")
	result := make(version, 0, len(parts))
	for _, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 {
			return nil, false
		}

		result = append(result, number)
	}

	return result, true
}

// major returns the branch number, which is the first component of the version.
func (v version) major() int {
	if len(v) == 0 {
		return -1
	}

	return v[0]
}

// compare compares versions component by component and returns -1, 0 or 1.
//
// Missing components count as zero, so 34.0.1 and 34.0.1.0 are equal while 34.0.2.1 is
// greater than 34.0.2. That is what makes a four-component Nextcloud version comparable
// to a three-component one from the advisories.
func (v version) compare(other version) int {
	length := max(len(v), len(other))

	for i := range length {
		left, right := 0, 0
		if i < len(v) {
			left = v[i]
		}
		if i < len(other) {
			right = other[i]
		}

		if left < right {
			return -1
		}
		if left > right {
			return 1
		}
	}

	return 0
}

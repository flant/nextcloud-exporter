package metrics

import "testing"

func mustParseVersion(t *testing.T, raw string) version {
	t.Helper()

	parsed, ok := parseVersion(raw)
	if !ok {
		t.Fatalf("can not parse version %q", raw)
	}

	return parsed
}

func TestParseVersion(t *testing.T) {
	valid := map[string][]int{
		"34":         {34},
		"34.0.1":     {34, 0, 1},
		"34.0.2.1":   {34, 0, 2, 1},
		" 34.0.2.1 ": {34, 0, 2, 1},
	}

	for raw, want := range valid {
		got, ok := parseVersion(raw)
		if !ok {
			t.Errorf("parseVersion(%q) failed", raw)
			continue
		}

		if got.compare(want) != 0 {
			t.Errorf("parseVersion(%q) = %v, want %v", raw, got, want)
		}
	}

	for _, raw := range []string{"", "   ", "abc", "34..1", "-1.0", "34.0.1-beta", ">= 34.0.0"} {
		if _, ok := parseVersion(raw); ok {
			t.Errorf("parseVersion(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestVersionCompare(t *testing.T) {
	tt := []struct {
		desc string
		a    string
		b    string
		want int
	}{
		{"четыре компонента против трёх", "34.0.2.1", "34.0.2", 1},
		{"отсутствующий компонент это ноль", "34.0.1", "34.0.1.0", 0},
		{"числовое, а не строковое сравнение", "34.0.10", "34.0.9", 1},
		{"разные патчи", "32.0.5.2", "32.0.12", -1},
		{"разные ветки", "33.0.0.0", "32.0.14.1", 1},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			got := mustParseVersion(t, tc.a).compare(mustParseVersion(t, tc.b))
			if got != tc.want {
				t.Errorf("%s.compare(%s) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestVersionMajor(t *testing.T) {
	if got := mustParseVersion(t, "34.0.2.1").major(); got != 34 {
		t.Errorf("major() = %d, want 34", got)
	}

	// Пустая версия не должна совпасть по ветке ни с чем, включая другую пустую.
	if got := version(nil).major(); got != -1 {
		t.Errorf("major() of empty version = %d, want -1", got)
	}
}

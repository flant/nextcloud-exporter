package metrics

// Сравнение версий Nextcloud.
//
// Версии здесь приходят с разным числом компонентов: Nextcloud сообщает свою версию
// четырьмя числами ("34.0.2.1"), а advisories указывают исправленные версии тремя
// ("34.0.1"). Сравнивать их как строки нельзя: "34.0.10" меньше "34.0.9" в
// лексикографическом порядке, хотя по смыслу больше.

import (
	"strconv"
	"strings"
)

// version — версия, разобранная на числовые компоненты.
type version []int

// parseVersion разбирает "34.0.2.1" в [34, 0, 2, 1].
// Второе возвращаемое значение равно false, если строка версией не является.
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

// major возвращает номер ветки — первый компонент версии.
func (v version) major() int {
	if len(v) == 0 {
		return -1
	}

	return v[0]
}

// compare сравнивает версии покомпонентно и возвращает -1, 0 или 1.
//
// Отсутствующие компоненты считаются нулём, поэтому 34.0.1 и 34.0.1.0 равны, а 34.0.2.1
// больше 34.0.2. Это и позволяет сравнивать четырёхкомпонентную версию Nextcloud с
// трёхкомпонентной из advisories.
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

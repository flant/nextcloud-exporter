package metrics

// Выкачка и разбор списка security advisories репозитория nextcloud/security-advisories.
//
// Это единственный источник, отвечающий на вопрос "в какой версии уязвимость исправлена".
// Глобальный GitHub Advisory Database и OSV.dev по Nextcloud пусты, а release notes не
// упоминают исправления безопасности вовсе, потому что такие правки мержатся из приватных
// форков и в changelog не попадают.

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
	// advisoriesURL — точка входа в список advisories.
	//
	// Сортировка по дате публикации по возрастанию выбрана не случайно: пагинация здесь
	// курсорная, и при таком порядке новые записи дописываются в конец, а уже отданные
	// страницы не сдвигаются. При сортировке по updated запись, отредактированная в
	// середине обхода, может быть пропущена.
	advisoriesURL = "https://api.github.com/repos/nextcloud/security-advisories/security-advisories" +
		"?per_page=100&sort=published&direction=asc"

	// advisoriesHTTPTimeout — таймаут на один запрос к GitHub.
	//
	// Это отдельный таймаут, не связанный с --timeout: тот задаёт ожидание Nextcloud
	// внутри скрейпа и обычно измеряется секундами, а здесь запрос идёт в фоне и
	// торопиться некуда.
	advisoriesHTTPTimeout = 30 * time.Second

	// advisoriesMaxPages — предохранитель от бесконечного обхода страниц.
	// Сейчас страниц три, так что запас десятикратный.
	advisoriesMaxPages = 10
)

// advisoryFix — итог разбора одной записи: в каких версиях уязвимость исправлена.
// Разбор делается один раз при выкачке, а не на каждом скрейпе.
type advisoryFix struct {
	ghsaID          string
	cveID           string
	patchedVersions []version
}

// id возвращает номер CVE, а при его отсутствии — идентификатор GHSA.
func (f advisoryFix) id() string {
	if f.cveID != "" {
		return f.cveID
	}

	return f.ghsaID
}

// fixes определяет, будет ли уязвимость закрыта переходом с current на available.
//
// Запись про уязвимость перечисляет версии, в которых уязвимость исправлена, — по одной
// на каждую поддерживаемую ветку, например 32.0.12, 33.0.6 и 34.0.1. Правил два.
//
// Первое: если на нашей ветке исправление уже установлено, запись нас не касается.
// Проверять надо самую большую из версий нашей ветки, а не любую: если запись
// перечисляет 31.0.1 и 31.0.7, а установлена 31.0.3, то по 31.0.1 мы выглядим
// исправленными, хотя нужного 31.0.7 у нас нет.
//
// Второе: иначе уязвимость будет закрыта, если какая-то из исправленных версий больше
// текущей и не больше доступной.
//
// Вместе правила дают верный ответ и при переходе между ветками. Пример: установлена
// 32.0.14, доступна 33.0.6, исправления перечислены как 32.0.12 и 33.0.6. Второе правило
// само по себе сочло бы обновление нужным, потому что 33.0.6 больше 32.0.14. Но первое
// правило видит, что 32.0.12 у нас уже есть, и отбрасывает запись. Без этого любой, кто
// в порядке на старой ветке, получал бы ложное срабатывание на каждом скрейпе.
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

	// Правило первое.
	if highestOnCurrentBranch != nil && highestOnCurrentBranch.compare(current) <= 0 {
		return false
	}

	// Правило второе.
	for _, patched := range f.patchedVersions {
		if current.compare(patched) < 0 && patched.compare(available) <= 0 {
			return true
		}
	}

	return false
}

// advisory — нужное подмножество полей одной записи из ответа GitHub.
// Остальные поля ответа отбрасываются: encoding/json игнорирует всё, чего нет в структуре.
type advisory struct {
	GHSAID string `json:"ghsa_id"`

	// CVEID заполнен не всегда: у части записей номер CVE ещё не присвоен, и тогда
	// поле приходит как null. В таких случаях используется GHSAID, см. advisoryFix.id.
	CVEID string `json:"cve_id"`

	// WithdrawnAt — указатель, чтобы отличить отсутствующее значение (nil) от
	// заполненного. Заполненное означает, что запись отозвана и её нужно игнорировать.
	WithdrawnAt *string `json:"withdrawn_at"`

	Vulnerabilities []advisoryVulnerability `json:"vulnerabilities"`
}

// advisoryVulnerability — сведения об одном затронутом продукте внутри записи.
type advisoryVulnerability struct {
	Package advisoryPackage `json:"package"`

	// VulnerableVersionRange и PatchedVersions — свободный текст, заполняемый вручную,
	// поэтому разбор должен быть терпимым к мусору. Подробности в parsePatchedVersions.
	VulnerableVersionRange string `json:"vulnerable_version_range"`
	PatchedVersions        string `json:"patched_versions"`
}

type advisoryPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// parseFixes превращает ответ GitHub в список исправлений, пригодный для сравнения версий.
// Отозванные записи и записи без разобранных версий отбрасываются.
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

// nextcloudServerNames — как в этих данных называют сам Nextcloud Server.
//
// Сверяться со списком, а не искать подстроку "Server", важно: в этом же репозитории
// публикуются advisories по остальным продуктам Nextcloud — Talk, Desktop, Deck, Tables, —
// и их номера версий пересекаются с серверными. Свободный поиск затащил бы в сравнение
// чужие версии и дал ложные срабатывания.
var nextcloudServerNames = map[string]bool{
	"server":           true,
	"nextcloud server": true,
	"nextcloud/server": true,
	"nextcloud":        true,
}

// isNextcloudServer отбирает записи про бесплатную редакцию Nextcloud Server.
//
// Платная редакция публикуется отдельно, под ecosystem "nextcloud enterprise" (а в части
// записей — с опечаткой "nextcloud entreprise"), и её версии состоят из четырёх чисел,
// которым не соответствует ни один публичный релиз. Здесь она не нужна, и сравнение
// ecosystem её отсекает.
//
// Пустой ecosystem принимается: примерно у пятой части записей это поле не заполнено, и
// продукт в них назван полным именем ("Nextcloud Server", "Nextcloud Talk"). Отбор по
// имени с ними справляется, а требование непустого ecosystem молча выбрасывало бы эти
// записи вместе с уязвимостями, которые в них описаны.
func isNextcloudServer(pkg advisoryPackage) bool {
	ecosystem := strings.ToLower(strings.TrimSpace(pkg.Ecosystem))
	if ecosystem != "" && ecosystem != "nextcloud" {
		return false
	}

	return nextcloudServerNames[strings.ToLower(strings.TrimSpace(pkg.Name))]
}

// parsePatchedVersions достаёт исправленные версии из одной записи о уязвимости.
//
// Поле patched_versions заполняется людьми и приходит в разном виде: "32.0.12, 33.0.6",
// ">=32.0.0, >=33.0.0" (без пробела), " >= 29.0.0, ..." (с пробелом в начале), просто
// "31.0.1". У части записей поля перепутаны местами: в patched_versions лежат
// неравенства, а сами версии — в vulnerable_version_range. Такие записи распознаются по
// тому, что из patched_versions не удалось получить ни одной версии, а из
// vulnerable_version_range получился чистый список чисел. Нормальный
// vulnerable_version_range почти всегда содержит знак неравенства, поэтому на исправных
// записях этот запасной путь не срабатывает.
func parsePatchedVersions(vulnerability advisoryVulnerability) []version {
	if versions := parseVersionList(vulnerability.PatchedVersions); len(versions) > 0 {
		return versions
	}

	return parseVersionList(vulnerability.VulnerableVersionRange)
}

// parseVersionList разбирает список версий через запятую, отбрасывая всё, что версией не
// является: неравенства вида ">= 32.0.0", пустые элементы, произвольный текст.
func parseVersionList(raw string) []version {
	var result []version

	for _, token := range strings.Split(raw, ",") {
		token = strings.TrimSpace(token)

		// Так отсеиваются границы диапазонов, которые версиями не являются.
		if token == "" || strings.ContainsAny(token, "<>=~^") {
			continue
		}

		if parsed, ok := parseVersion(token); ok {
			result = append(result, parsed)
		}
	}

	return result
}

// advisoryFetcher выкачивает список advisories с GitHub.
type advisoryFetcher struct {
	client    *http.Client
	userAgent string

	// url — адрес первой страницы списка. Отдельным полем, а не константой напрямую,
	// чтобы тесты могли подставить локальный сервер вместо GitHub.
	url string
}

func newAdvisoryFetcher(userAgent string) *advisoryFetcher {
	return &advisoryFetcher{
		userAgent: userAgent,
		url:       advisoriesURL,
		client: &http.Client{
			Timeout: advisoriesHTTPTimeout,
			// Transport намеренно не задан, используется стандартный, то есть проверка
			// TLS-сертификата включена. Флаг --tls-skip-verify относится к серверу
			// Nextcloud пользователя и на GitHub распространяться не должен.
		},
	}
}

// fetchAll выкачивает все страницы списка advisories.
//
// Ошибка на любой странице прекращает обход и не возвращает ничего: неполный список
// выглядел бы как отсутствие уязвимостей и мог бы скрыть обновление безопасности.
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

// fetchPage запрашивает одну страницу и возвращает её содержимое вместе со ссылкой на
// следующую страницу (пустая строка означает, что страница последняя).
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
		// Исчерпание лимита GitHub выглядит как 403 или 429. Отдельной обработки не
		// требует: следующая попытка будет через advisoriesRetryInterval, а остаток
		// лимита попадает в сообщение, чтобы причину было видно в логе.
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

// nextPageURL достаёт адрес следующей страницы из заголовка Link, который выглядит так:
//
//	<https://api.github.com/repositories/63675426/security-advisories?after=...>; rel="next"
//
// Пустая строка без ошибки означает, что страница последняя. Непригодная ссылка — это
// именно ошибка, а не конец обхода: молча остановившись, мы отдали бы часть списка как
// полный, а поскольку он отсортирован по возрастанию даты, уцелели бы самые старые
// записи и все свежие обновления безопасности выглядели бы как рядовые.
//
// Сверяются только схема и хост. Путь сверять нельзя: GitHub отдаёт следующую страницу по
// другому пути, с числовым идентификатором репозитория вместо его имени. Проверка хоста
// нужна, чтобы промежуточный прокси не смог увести выкачку на посторонний адрес.
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

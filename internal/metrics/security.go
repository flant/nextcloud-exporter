package metrics

// Проверка того, содержит ли доступное обновление Nextcloud исправления безопасности.
//
// Nextcloud сообщает только "есть более новая версия", но не говорит, чинит ли она
// уязвимости, из-за чего метрика обновления поднимала алерт на каждый рядовой
// патч-релиз. Ответ на этот вопрос даёт список advisories, см. advisories.go.
//
// Список выкачивается в фоне раз в 12 часов и держится в памяти. Скрейп Prometheus
// никогда не ждёт GitHub: он читает уже готовый снимок.
//
// Логика намеренно смещена в сторону "сообщить об обновлении": если данных нет или они
// непригодны, метрика остаётся равной единице, то есть ведёт себя как до появления этой
// проверки.

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// advisoriesRefreshInterval — как часто обновлять список.
	//
	// GitHub без токена разрешает 60 запросов в час на IP-адрес. Полная выкачка стоит
	// три запроса, поэтому раз в 12 часов это шесть запросов в сутки — с большим запасом.
	advisoriesRefreshInterval = 12 * time.Hour

	// advisoriesRetryInterval — пауза перед повтором после неудачной выкачки.
	advisoriesRetryInterval = 15 * time.Minute

	// advisoriesMaxAge — после какого возраста снимок считается непригодным.
	//
	// Список advisories только пополняется, поэтому опасность устаревшего снимка в том,
	// что в нём не будет свежей записи, и метрика покажет ноль при реально нужном
	// обновлении безопасности. Это худшее из возможных поведений, поэтому у снимка есть
	// жёсткий срок годности: четыре пропущенных цикла обновления, и он перестаёт
	// использоваться.
	advisoriesMaxAge = 48 * time.Hour
)

// advisorySnapshot — неизменяемый результат одной успешной выкачки.
//
// После публикации снимок никогда не меняется: следующая выкачка создаёт новый и
// заменяет указатель. Благодаря этому читателям достаточно скопировать указатель под
// блокировкой, а дальше работать без неё.
type advisorySnapshot struct {
	fixes     []advisoryFix
	fetchedAt time.Time
}

// SecurityChecker хранит список advisories и отвечает на вопрос, несёт ли обновление
// исправления безопасности. Нулевое значение непригодно, создавайте через NewSecurityChecker.
//
// Методы допускают нулевой указатель в качестве получателя и в этом случае отвечают
// "не знаю", чтобы вызывающему не приходилось проверять на nil.
type SecurityChecker struct {
	log     logrus.FieldLogger
	fetcher *advisoryFetcher

	mu       sync.RWMutex
	snapshot *advisorySnapshot

	// results не даёт повторять в логе одну и ту же строку на каждом скрейпе.
	results changeOnlyLogger
}

// NewSecurityChecker создаёт проверяльщик. Обращений к сети не делает — за это отвечает Start.
func NewSecurityChecker(log logrus.FieldLogger, userAgent string) *SecurityChecker {
	return &SecurityChecker{
		log:     log,
		fetcher: newAdvisoryFetcher(userAgent),
	}
}

// Start запускает фоновое обновление списка и сразу возвращает управление.
//
// Обновление живёт в отдельной горутине, поэтому скрейп Prometheus никогда не ждёт
// GitHub. Пока первая выкачка не закончилась, снимка нет, Check отвечает "не знаю", и
// метрика ведёт себя как раньше.
//
// Горутина завершается при отмене ctx. Экспортёр не имеет процедуры graceful shutdown,
// поэтому на практике горутина живёт до конца процесса, но ctx нужен для http-запросов
// и делает поведение предсказуемым в тестах.
func (c *SecurityChecker) Start(ctx context.Context) {
	go c.refreshLoop(ctx)
}

// refreshLoop обновляет снимок, пока не отменят ctx.
func (c *SecurityChecker) refreshLoop(ctx context.Context) {
	for {
		// Пауза до следующей попытки зависит от того, удалась ли текущая.
		wait := advisoriesRefreshInterval
		if err := c.refresh(ctx); err != nil {
			c.log.Warnf("Security check: can not refresh advisories: %s", err)
			wait = advisoriesRetryInterval
		}

		timer := time.NewTimer(wait)

		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return
		}
	}
}

// refresh выкачивает список заново и заменяет снимок.
func (c *SecurityChecker) refresh(ctx context.Context) error {
	advisories, err := c.fetcher.fetchAll(ctx)
	if err != nil {
		return err
	}

	fixes := parseFixes(advisories)
	if len(fixes) == 0 {
		// Ни одной пригодной записи про Nextcloud Server. Так выглядит, например,
		// переименование ecosystem на стороне GitHub. Старый снимок при этом сохраняется,
		// а если его нет, проверка остаётся отключённой и метрика ведёт себя как раньше.
		// Считать, что уязвимостей нет, здесь нельзя — это молча спрятало бы обновления
		// безопасности.
		return fmt.Errorf("no usable advisories in %d records", len(advisories))
	}

	c.mu.Lock()
	c.snapshot = &advisorySnapshot{fixes: fixes, fetchedAt: time.Now()}
	c.mu.Unlock()

	c.log.Infof("Security check: loaded %d advisories for Nextcloud Server.", len(fixes))

	// Разбор закончен, данные новые — пусть ближайший скрейп выведет разбор целиком,
	// даже если словесно результат совпал с предыдущим.
	c.results.reset()

	return nil
}

// currentSnapshot возвращает пригодный к использованию снимок или nil.
//
// nil означает одно из двух: первая выкачка ещё не закончилась (или все попытки
// провалились), либо снимок просрочен.
func (c *SecurityChecker) currentSnapshot() *advisorySnapshot {
	if c == nil {
		return nil
	}

	c.mu.RLock()
	snapshot := c.snapshot
	c.mu.RUnlock()

	if snapshot == nil || time.Since(snapshot.fetchedAt) > advisoriesMaxAge {
		return nil
	}

	return snapshot
}

// Available сообщает, есть ли сейчас пригодные данные от GitHub.
//
// Используется как значение метки advisories_available у метрики обновления, чтобы по
// метрике было видно, выполнялась ли проверка вообще, или экспортёр сообщает о любом
// обновлении из-за недоступности источника.
func (c *SecurityChecker) Available() bool {
	return c.currentSnapshot() != nil
}

// Check возвращает номера уязвимостей, которые закрывает обновление current -> available.
// Пустой результат означает, что известных исправлений безопасности в обновлении нет.
//
// Второе возвращаемое значение — признак того, что ответ получен. Если оно false, ответа
// нет (проверка выключена, данных нет, версии не разобрались), и вызывающий обязан
// сообщить об обновлении, как делал до появления проверки.
//
// Список отсортирован по убыванию, то есть свежие уязвимости идут первыми: номера CVE
// начинаются с года. Сам список в метрику не попадает, он целиком пишется в лог.
func (c *SecurityChecker) Check(current, available string) (fixed []string, ok bool) {
	snapshot := c.currentSnapshot()
	if snapshot == nil {
		c.logResult(true, "Security check: no usable advisories, reporting update.")
		return nil, false
	}

	currentVersion, currentOK := parseVersion(current)
	availableVersion, availableOK := parseVersion(available)
	if !currentOK || !availableOK {
		c.logResult(true, "Security check: can not parse versions %q and %q, reporting update.", current, available)
		return nil, false
	}

	for _, fix := range snapshot.fixes {
		if fix.fixes(currentVersion, availableVersion) {
			fixed = append(fixed, fix.id())
		}
	}

	if len(fixed) == 0 {
		c.logResult(false, "Security check: update %s -> %s contains no known security fixes.", current, available)
		return nil, true
	}

	// Убывающий порядок: номера CVE начинаются с года, поэтому первыми оказываются
	// самые свежие.
	slices.Sort(fixed)
	slices.Reverse(fixed)

	c.logResult(false, "Security check: update %s -> %s contains fixes for %d vulnerabilities: %s.",
		current, available, len(fixed), strings.Join(fixed, ", "))

	return fixed, true
}

// logResult пишет строку в лог, только если она отличается от предыдущей.
func (c *SecurityChecker) logResult(warn bool, format string, args ...any) {
	if c == nil {
		return
	}

	message := fmt.Sprintf(format, args...)
	if !c.results.changed(message) {
		return
	}

	if warn {
		c.log.Warn(message)
		return
	}

	c.log.Info(message)
}

// changeOnlyLogger запоминает последнее сообщение, чтобы не повторять его.
//
// Check вызывается на каждый скрейп Prometheus, то есть раз в 15–60 секунд. Без этого
// одна и та же строка повторялась бы в логе бесконечно. Строка меняется, когда меняется
// версия Nextcloud, доступное обновление или сам список уязвимостей — то есть ровно
// тогда, когда о ней есть смысл сообщить.
type changeOnlyLogger struct {
	mu   sync.Mutex
	last string
}

// changed сообщает, стоит ли выводить сообщение, и запоминает его.
func (l *changeOnlyLogger) changed(message string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if message == l.last {
		return false
	}

	l.last = message

	return true
}

// reset забывает последнее сообщение, из-за чего следующее будет выведено в любом случае.
func (l *changeOnlyLogger) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.last = ""
}

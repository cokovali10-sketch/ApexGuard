// PulseFuzz — coverage-guided core.
// Динамический граф состояний API строится из трёх наблюдений:
//   Signature  — канонический хэш ответа (статус + нормализованный JSON-схлоп).
//   Transition — ребро (endpoint A → endpoint B) фиксируется при последовательности запросов.
//   Timing     — базовый p50 latency на endpoint для side-channel детекции.
package coverage

import (
	"encoding/json"
	"hash/fnv"
	"sort"
	"sync"
	"time"
)

// Signature — детерминированный слепок ответа сервера.
type Signature struct {
	Status   int
	BodyHash uint64
	BodyLen  int
}

// canonicalizeJSON: json.Marshal сам сортирует ключи map и нормализует числа
// (100.0 → "100"), что даёт повторяемый хэш без ручной рекурсии.
func canonicalizeJSON(body []byte) []byte {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return body
	}
	out, err := json.Marshal(v)
	if err != nil {
		return body
	}
	return out
}

func fnv64(data []byte) uint64 {
	h := fnv.New64a()
	_, _ = h.Write(data)
	return h.Sum64()
}

// SignatureOf вычисляет сигнатуру ответа.
func SignatureOf(status int, body []byte) Signature {
	canon := canonicalizeJSON(body)
	return Signature{
		Status:   status,
		BodyHash: fnv64(canon),
		BodyLen:  len(canon),
	}
}

// Input — seed, вызвавший интересное поведение.
type Input struct {
	ID      string // идентификатор seed (endpoint key)
	Path    string
	Payload []byte
	Score   float64 // энергия: число мутаций при следующей итерации
	Covered int     // сколько новых сигнатур порождено этим seed'ом
}

// StateNode — узел графа состояний API.
type StateNode struct {
	ID          string
	Baseline    time.Duration
	Hits        int
	Transitions map[string]int
}

// Corpus — потокобезопасный репозиторий покрытия.
type Corpus struct {
	mu      sync.RWMutex
	covered map[Signature]int
	seeds   []Input
	graph   map[string]*StateNode
}

func NewCorpus() *Corpus {
	return &Corpus{
		covered: make(map[Signature]int),
		graph:   make(map[string]*StateNode),
	}
}

func nodeKey(method, path string) string { return method + " " + path }

// Observe фиксирует сигнатуру и latency. Возвращает true при новом покрытии.
func (c *Corpus) Observe(method, path string, sig Signature, latency time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	k := nodeKey(method, path)
	n, ok := c.graph[k]
	if !ok {
		n = &StateNode{ID: k, Transitions: make(map[string]int)}
		c.graph[k] = n
	}
	n.Hits++
	if latency > 0 {
		if n.Baseline == 0 {
			n.Baseline = latency
		} else {
			n.Baseline = (n.Baseline*3 + latency) / 4 // EMA ≈ p50
		}
	}

	_, wasCovered := c.covered[sig]
	c.covered[sig]++
	return !wasCovered
}

// TimingAnomaly: latency заметно выше базовой для endpoint.
func (c *Corpus) TimingAnomaly(method, path string, latency time.Duration) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if n, ok := c.graph[nodeKey(method, path)]; ok && n.Baseline > 0 {
		return latency > n.Baseline*5
	}
	return false
}

// RecordTransition фиксирует ребро графа (переход между endpoint'ами).
func (c *Corpus) RecordTransition(method, path, nextMethod, nextPath string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	from := nodeKey(method, path)
	to := nodeKey(nextMethod, nextPath)
	if n, ok := c.graph[from]; ok {
		n.Transitions[to]++
	}
}

// InterestingSeeds — seed'ы, отсортированные по энергии (покрытию).
func (c *Corpus) InterestingSeeds() []Input {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Input, 0, len(c.seeds))
	out = append(out, c.seeds...)
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

// AddSeed регистрирует input, породивший новое покрытие.
func (c *Corpus) AddSeed(in Input) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seeds = append(c.seeds, in)
}

// BumpSeed усиливает энергию seed, породившего новое покрытие.
func (c *Corpus) BumpSeed(id int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if id >= 0 && id < len(c.seeds) {
		c.seeds[id].Score += 0.5
		c.seeds[id].Covered++
	}
}

// GraphDump — для метрик/консоли (JSON-сериализация графа).
func (c *Corpus) GraphDump() map[string]int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]int, len(c.graph))
	for k, n := range c.graph {
		out[k] = n.Hits
	}
	return out
}

// PulseFuzz — coverage-guided engine (main loop).
//
// Цикл:
//   1. Выбрать seed с максимальной энергией (или сгенерировать из спецификации).
//   2. Прогнать K мутаций (K = энергия seed'а).
//   3. Для каждого ответа вычислить Signature; новое покрытие → seed в корпус + boost.
//   4. Детекты: сигнатуры уязвимостей + timing side-channel + статус-политика.
//   5. Построение графа переходов между endpoint'ами.
package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"apexguard/pulsefuzz/internal/coverage"
	"apexguard/pulsefuzz/internal/mutator"
)

// Anomaly — найденная аномалия при фаззинге.
type Anomaly struct {
	Rule    string
	URL     string
	Payload string
	Status  int
	Latency time.Duration
	Method  string
}

// Engine — оркестратор coverage-guided фаззинга.
type Engine struct {
	client      *http.Client
	base        string
	corpus      *coverage.Corpus
	mutator     *mutator.Mutator
	concurrency int

	mu         sync.Mutex
	anomalies  []Anomaly
	iterations int
}

func New(client *http.Client, base string, corpus *coverage.Corpus, m *mutator.Mutator, concurrency int) *Engine {
	return &Engine{client: client, base: base, corpus: corpus, mutator: m, concurrency: concurrency}
}

// Anomalies возвращает накопленные аномалии.
func (e *Engine) Anomalies() []Anomaly {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Anomaly, len(e.anomalies))
	copy(out, e.anomalies)
	return out
}

// Iterations — число выполненных запросов.
func (e *Engine) Iterations() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.iterations
}

// CorpusDump — снимок графа покрытия (для метрик/консоли).
func (e *Engine) CorpusDump() map[string]int {
	return e.corpus.GraphDump()
}

// FuzzOperation гоняет мутации по одной операции. Возвращает число запросов.
func (e *Engine) FuzzOperation(method, path string, example map[string]any, params map[string]any) int {
	var seeds []coverage.Input

	// Начальный seed из примера схемы.
	seed := coverage.Input{
		ID:      method + " " + path,
		Path:    path,
		Payload: []byte(mustJSON(example)),
		Score:   1.0,
	}
	seeds = append(seeds, seed)
	// Интересные seed'ы из глобального корпуса, совпадающие по endpoint.
	for _, s := range e.corpus.InterestingSeeds() {
		if s.ID == method+" "+path {
			seeds = append(seeds, s)
		}
	}

	jobs := make(chan fuzzJob, 256)
	results := make(chan fuzzOutcome, 256)
	var wg sync.WaitGroup
	for i := 0; i < e.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				results <- e.sendOne(job)
			}
		}()
	}

	// Продюсер: мутации тела + query/path-параметров с энергетическим взвешиванием.
	go func() {
		noBody := methodNoBody(method)
		baseURL := e.base + path
		for _, s := range seeds {
			k := int(s.Score * 32)
			if k < 1 {
				k = 1
			}

			if noBody {
				// фаззинг query-параметров (GET/DELETE/HEAD/OPTIONS)
				q := queryParams(params)
				for i := 0; i < k; i++ {
					u := mutateQuery(baseURL, q, e.mutator)
					jobs <- fuzzJob{method: method, url: u, payload: nil}
				}
				continue
			}

			var base map[string]any
			if err := json.Unmarshal(s.Payload, &base); err != nil {
				base = example
			}
			mutated := e.mutator.MutateJSON(base)
			if len(mutated) > k {
				mutated = mutated[:k]
			}
			for _, m := range mutated {
				jobs <- fuzzJob{method: method, url: baseURL, payload: mustJSONBytes(m)}
			}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	count := 0
	for r := range results {
		count++
		e.mu.Lock()
		e.iterations++
		e.mu.Unlock()
		e.handleOutcome(r)
	}
	return count
}

type fuzzJob struct {
	method  string
	url     string
	payload []byte
}

type fuzzOutcome struct {
	method  string
	url     string
	payload []byte
	status  int
	body    []byte
	latency time.Duration
	err     error
}

func (e *Engine) sendOne(job fuzzJob) fuzzOutcome {
	start := time.Now()
	var req *http.Request
	var err error
	if job.payload == nil {
		req, err = http.NewRequest(job.method, job.url, nil)
	} else {
		req, err = http.NewRequest(job.method, job.url, bytes.NewReader(job.payload))
	}
	if err != nil {
		return fuzzOutcome{method: job.method, url: job.url, payload: job.payload, err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	lat := time.Since(start)
	if err != nil {
		return fuzzOutcome{method: job.method, url: job.url, payload: job.payload, latency: lat, err: err}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return fuzzOutcome{method: job.method, url: job.url, payload: job.payload, status: resp.StatusCode, body: body, latency: lat}
}

func (e *Engine) handleOutcome(r fuzzOutcome) {
	if r.err != nil {
		return
	}
	method := r.method
	path := pathOf(r.url, e.base)
	sig := coverage.SignatureOf(r.status, r.body)

	newCoverage := e.corpus.Observe(method, path, sig, r.latency)
	if newCoverage {
		e.corpus.AddSeed(coverage.Input{ID: method + " " + path, Path: path, Payload: r.payload, Score: 1.5})
	}

	// Детект аномалий.
	if e.corpus.TimingAnomaly(method, path, r.latency) && r.latency > 2*time.Second {
		e.recordAnomaly("timing-side-channel", r, r.latency.String())
	}
	if r.status == 500 {
		e.recordAnomaly("status:500", r, "")
	}
	if isAnomalousBody(r.body) {
		e.recordAnomaly("signature", r, "")
	}
}

func (e *Engine) recordAnomaly(rule string, r fuzzOutcome, detail string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.anomalies = append(e.anomalies, Anomaly{
		Rule:    rule,
		URL:     truncateStr(r.url, 200),
		Payload: truncateStr(string(r.payload), 200),
		Status:  r.status,
		Latency: r.latency,
		Method:  r.method,
	})
	_ = detail
}

func isAnomalousBody(body []byte) bool {
	low := strings.ToLower(string(body))
	for _, marker := range []string{
		"sqlerror", "sqlstate", "operationalerror", "mysql", "postgres",
		"traceback (most recent call last)", "jinja2", "undefineterror",
		"root:x:0:0", "invalid token", "jwt", "stacktrace", "stack trace",
		"panic: runtime error", "panic(", "at java.", "at com.",
		"<script", "</script>", "onerror=", "javascript:",
		"password", "passwd", "credit_card", "creditcard", "card number",
		"api_key", "apikey", "secret_key", "accesskey", "private key",
		"mongodb://", "redis://", "amqp://", "ldap://",
		"syntax error", "unexpected end of json", "invalid character",
	} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Утилиты
// ---------------------------------------------------------------------------

func mustJSON(v any) string {
	return string(mustJSONBytes(v))
}

func mustJSONBytes(v any) []byte {
	if b, err := json.Marshal(v); err == nil {
		return b
	}
	return []byte("{}")
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func methodNoBody(m string) bool {
	switch strings.ToUpper(m) {
	case "GET", "DELETE", "HEAD", "OPTIONS":
		return true
	}
	return false
}

// queryParams преобразует примеры параметров схемы в url.Values.
func queryParams(params map[string]any) url.Values {
	q := make(url.Values)
	for k, v := range params {
		if v == nil {
			continue
		}
		switch t := v.(type) {
		case string:
			q.Set(k, t)
		case float64:
			q.Set(k, fmt.Sprintf("%v", t))
		default:
			q.Set(k, fmt.Sprintf("%v", t))
		}
	}
	return q
}

// mutateQuery строит URL с мутированными query-параметрами.
func mutateQuery(base string, q url.Values, m *mutator.Mutator) string {
	out := make(url.Values, len(q))
	for k, vs := range q {
		out[k] = append([]string(nil), vs...)
	}
	// вносим 1-2 случайные инъекции/граничные значения
	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return base
	}
	k := keys[int(time.Now().UnixNano())%len(keys)]
	candidates := []string{
		"' OR '1'='1",
		"../../../../etc/passwd",
		"{{7*7}}",
		"-1",
		"1",
		"0",
		"00000000-0000-0000-0000-000000000001",
		"NaN",
		"%00",
	}
	out.Set(k, candidates[int(time.Now().UnixNano()/7)%len(candidates)])
	return base + "?" + out.Encode()
}

// pathOf извлекает путь из URL относительно базового адреса.
func pathOf(raw, base string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if b, err := url.Parse(base); err == nil && u.Host == b.Host {
		return u.Path
	}
	return u.Path
}

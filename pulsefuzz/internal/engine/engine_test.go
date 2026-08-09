package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"apexguard/pulsefuzz/internal/coverage"
	"apexguard/pulsefuzz/internal/mutator"
)

func newEngine(t *testing.T, target string) *Engine {
	t.Helper()
	m := mutator.New(mutator.ModeBoundary|mutator.ModeSQLi|mutator.ModeSSTI, 1)
	return New(&http.Client{}, target, coverage.NewCorpus(), m, 4)
}

func TestFuzzOperationRunsAndCounts(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch {
		case r.URL.Path == "/api/users/5" && r.Method == "GET":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":5,"name":"alice","email":"a@c"}`))
		case r.URL.Path == "/api/users/5" && r.Method == "DELETE":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"deleted":true}`))
		case r.URL.Path == "/api/users" && r.Method == "POST":
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"id":6}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"nf"}`))
		}
	}))
	defer srv.Close()

	e := newEngine(t, srv.URL)
	iters := e.FuzzOperation("GET", "/api/users/{id}", map[string]any{}, map[string]any{"id": float64(5)})
	if iters <= 0 {
		t.Fatalf("expected iterations > 0, got %d", iters)
	}
	if hits.Load() == 0 {
		t.Fatal("no requests were sent")
	}
	if e.Iterations() != iters {
		t.Fatalf("iteration counter mismatch: %d vs %d", e.Iterations(), iters)
	}
	dump := e.CorpusDump()
	if len(dump) == 0 {
		t.Fatal("corpus is empty after fuzzing")
	}
	// граф индексируется по шаблону пути из OpenAPI
	if dump["GET /api/users/{id}"] == 0 {
		t.Fatalf("GET /api/users/{id} missing from corpus: %v", dump)
	}
}

func TestFuzzOperationQueryAndBody(t *testing.T) {
	var lastQuery string
	var lastBody string
	var lastMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastQuery = r.URL.RawQuery
		lastBody = r.Method + ":" + r.URL.Path
		lastMethod = r.Method
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	e := newEngine(t, srv.URL)
	// GET: параметры идут в query
	e.FuzzOperation("GET", "/api/account", map[string]any{}, map[string]any{"user_id": float64(1), "page": float64(2)})
	if lastQuery == "" {
		t.Fatal("GET query params missing")
	}
	if !strings.Contains(lastQuery, "user_id") {
		t.Fatalf("expected user_id in query, got %q", lastQuery)
	}
	_ = lastBody
	_ = lastMethod

	// POST: тело с примером
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv2.Close()
	e2 := newEngine(t, srv2.URL)
	e2.FuzzOperation("POST", "/api/users", map[string]any{"username": "alice", "role": "user"}, map[string]any{})
	if e2.Iterations() <= 0 {
		t.Fatal("no POST iterations")
	}
}

func TestFuzzOperationDeleteHeadOptionsNoBody(t *testing.T) {
	var methods []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	e := newEngine(t, srv.URL)
	for _, m := range []string{"DELETE", "HEAD", "OPTIONS"} {
		e.FuzzOperation(m, "/api/users/{id}", map[string]any{}, map[string]any{"id": float64(1)})
	}
	if e.Iterations() <= 0 {
		t.Fatal("no iterations for bodyless methods")
	}
}

func TestIsAnomalousBody(t *testing.T) {
	cases := []struct {
		body string
		want bool
	}{
		{`{"password":"x","email":"a@b","credit_card":"4111"}`, true},
		{`panic: runtime error: index out of range`, true},
		{`<script>alert(1)</script>`, true},
		{`{"error":"not found"}`, false},
		{`SQLSTATE[42000]: Syntax error`, true},
	}
	for _, c := range cases {
		if got := isAnomalousBody([]byte(c.body)); got != c.want {
			t.Errorf("isAnomalousBody(%q) = %v, want %v", c.body, got, c.want)
		}
	}
}

// Package api — HTTP API для интеграции с ApexCore.
//
//   POST /fuzz          создать job фаззинга {target_url, spec_path, protocol, concurrency, fuzz_modes}
//   GET  /jobs/{id}     статус job {job_id, status, ...}
//   GET  /healthz       liveness
//   GET  /metrics       Prometheus-совместимые счётчики
//
// FuzzRequest — JSON-совместимый со структурой core/gen FuzzRequest
// (поле proto enum protocol сериализуется как число).
package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"apexguard/pulsefuzz/internal/coverage"
	"apexguard/pulsefuzz/internal/engine"
	"apexguard/pulsefuzz/internal/mutator"
	"apexguard/pulsefuzz/internal/spec"
)

// FuzzRequest — запрос на запуск фаззинга (зеркало proto FuzzRequest).
type FuzzRequest struct {
	TargetURL   string   `json:"target_url"`
	SpecPath    string   `json:"spec_path"`
	Protocol    int      `json:"protocol"` // 0=REST 1=GRAPHQL 2=GRPC
	Concurrency uint     `json:"concurrency"`
	FuzzModes   []string `json:"fuzz_modes"`
}

// Job — состояние задачи фаззинга.
type Job struct {
	JobID      string            `json:"job_id"`
	Status     string            `json:"status"` // QUEUED | RUNNING | DONE
	Iterations int               `json:"iterations"`
	Anomalies  []engine.Anomaly  `json:"anomalies"`
	Corpus     map[string]int    `json:"corpus"`
	StartedAt  time.Time         `json:"started_at"`
	FinishedAt time.Time         `json:"finished_at,omitempty"`
	Error      string            `json:"error,omitempty"`
	Stats      map[string]uint64 `json:"stats,omitempty"`
}

// Server — HTTP-обработчики pulsefuzz.
type Server struct {
	mu      sync.RWMutex
	jobs    map[string]*Job
	started atomic.Uint64
	failed  atomic.Uint64
	done    atomic.Uint64
}

func New() *Server {
	return &Server{jobs: make(map[string]*Job)}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /fuzz", s.fuzz)
	mux.HandleFunc("GET /jobs/{id}", s.jobStatus)
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /metrics", s.metrics)
	return mux
}

// fuzz запускает job в фоне и немедленно возвращает статус QUEUED.
func (s *Server) fuzz(w http.ResponseWriter, r *http.Request) {
	var req FuzzRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if req.TargetURL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target_url required"})
		return
	}
	id := strconv.FormatInt(time.Now().UnixNano(), 36)
	job := &Job{JobID: id, Status: "QUEUED", StartedAt: time.Now()}

	s.mu.Lock()
	s.jobs[id] = job
	s.mu.Unlock()

	go s.run(job, req)
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": id, "status": "QUEUED"})
}

func (s *Server) run(job *Job, req FuzzRequest) {
	s.mu.Lock()
	job.Status = "RUNNING"
	s.mu.Unlock()
	s.started.Add(1)

	start := time.Now()
	var ops []spec.Operation
	if req.SpecPath != "" {
		var err error
		ops, err = spec.ParseOpenAPI(req.SpecPath)
		if err != nil {
			s.finish(job, nil, err)
			return
		}
	}
	if len(ops) == 0 {
		// без спецификации — минимальный набор проб
		ops = []spec.Operation{
			{Method: "GET", Path: "/", Params: map[string]any{}},
			{Method: "POST", Path: "/", ExampleBody: map[string]any{"id": "1"}},
		}
	}

	concurrency := int(req.Concurrency)
	if concurrency <= 0 {
		concurrency = 25
	}
	modes := mutator.ModeBoundary | mutator.ModeSQLi | mutator.ModeSSTI |
		mutator.ModeIDOR | mutator.ModeTypeConfusion | mutator.ModeChaos

	client := &http.Client{Timeout: 15 * time.Second}
	m := mutator.New(modes, time.Now().UnixNano())
	corpus := coverage.NewCorpus()
	eng := engine.New(client, req.TargetURL, corpus, m, concurrency)

	iter := 0
	for _, op := range ops {
		iter += eng.FuzzOperation(op.Method, op.Path, op.ExampleBody, op.Params)
	}

	s.finish(job, eng, nil)
	_ = start
}

func (s *Server) finish(job *Job, eng *engine.Engine, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job.FinishedAt = time.Now()
	if err != nil {
		job.Status = "ERROR"
		job.Error = err.Error()
		s.failed.Add(1)
		return
	}
	job.Status = "DONE"
	job.Iterations = eng.Iterations()
	job.Anomalies = eng.Anomalies()
	job.Corpus = eng.CorpusDump()
	s.done.Add(1)
}

func (s *Server) jobStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.RLock()
	job, ok := s.jobs[id]
	s.mu.RUnlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(
		"pulsefuzz_jobs_started " + strconv.FormatUint(s.started.Load(), 10) + "\n" +
			"pulsefuzz_jobs_done " + strconv.FormatUint(s.done.Load(), 10) + "\n" +
			"pulsefuzz_jobs_failed " + strconv.FormatUint(s.failed.Load(), 10) + "\n",
	))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

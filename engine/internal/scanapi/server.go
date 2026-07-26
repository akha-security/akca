package scanapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/distributed"
	"github.com/akha-security/akca/engine/internal/report"
)

type Engine interface {
	StartScan(config.ScanConfig) error
	StopScan() error
	WaitScanDone(context.Context) error
	GenerateReport(report.Options) ([]byte, error)
}

type jobEngine interface {
	EnqueueDistributedJob(distributed.Spec) (string, error)
	LeaseDistributedJob(string) (distributed.Job, error)
	GetDistributedJob(string) (distributed.Job, error)
	HeartbeatDistributedJob(string, string) error
	CheckpointDistributedJob(string, string, json.RawMessage) error
	CompleteDistributedJob(string, string) error
	FailDistributedJob(string, string, string) error
	CancelDistributedJob(string) error
}

type Server struct {
	engine Engine
	token  string
	mu     sync.RWMutex
	state  state
}

type state struct {
	ScanID    string `json:"scan_id,omitempty"`
	Status    string `json:"status"`
	StartedAt string `json:"started_at,omitempty"`
	EndedAt   string `json:"ended_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

func New(engine Engine, bearerToken string) (*Server, error) {
	if engine == nil {
		return nil, errors.New("scan API engine is required")
	}
	if len(strings.TrimSpace(bearerToken)) < 24 {
		return nil, errors.New("AKCA_API_TOKEN must contain at least 24 characters")
	}
	return &Server{engine: engine, token: bearerToken, state: state{Status: "idle"}}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.health)
	mux.HandleFunc("POST /v1/scans", s.start)
	mux.HandleFunc("GET /v1/scans/current", s.current)
	mux.HandleFunc("POST /v1/scans/current/stop", s.stop)
	mux.HandleFunc("GET /v1/reports", s.report)
	mux.HandleFunc("POST /v1/jobs", s.enqueueJob)
	mux.HandleFunc("POST /v1/jobs/lease", s.leaseJob)
	mux.HandleFunc("GET /v1/jobs/{id}", s.getJob)
	mux.HandleFunc("POST /v1/jobs/{id}/heartbeat", s.heartbeatJob)
	mux.HandleFunc("POST /v1/jobs/{id}/checkpoint", s.checkpointJob)
	mux.HandleFunc("POST /v1/jobs/{id}/complete", s.completeJob)
	mux.HandleFunc("POST /v1/jobs/{id}/fail", s.failJob)
	mux.HandleFunc("POST /v1/jobs/{id}/cancel", s.cancelJob)
	return securityHeaders(s.authenticate(mux))
}

func (s *Server) enqueueJob(w http.ResponseWriter, r *http.Request) {
	engine, ok := s.engine.(jobEngine)
	if !ok {
		writeError(w, http.StatusNotImplemented, "distributed jobs are unavailable")
		return
	}
	var spec distributed.Spec
	if !decodeJSON(w, r, &spec) {
		return
	}
	id, err := engine.EnqueueDistributedJob(spec)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id})
}

func (s *Server) leaseJob(w http.ResponseWriter, r *http.Request) {
	engine, ok := s.engine.(jobEngine)
	if !ok {
		writeError(w, http.StatusNotImplemented, "distributed jobs are unavailable")
		return
	}
	var request struct {
		WorkerID string `json:"worker_id"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	job, err := engine.LeaseDistributedJob(request.WorkerID)
	if errors.Is(err, distributed.ErrNoJob) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request) {
	engine, ok := s.engine.(jobEngine)
	if !ok {
		writeError(w, http.StatusNotImplemented, "distributed jobs are unavailable")
		return
	}
	job, err := engine.GetDistributedJob(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) heartbeatJob(w http.ResponseWriter, r *http.Request) {
	s.workerMutation(w, r, func(engine jobEngine, worker string, _ json.RawMessage) error {
		return engine.HeartbeatDistributedJob(r.PathValue("id"), worker)
	})
}

func (s *Server) checkpointJob(w http.ResponseWriter, r *http.Request) {
	s.workerMutation(w, r, func(engine jobEngine, worker string, checkpoint json.RawMessage) error {
		if len(checkpoint) == 0 || !json.Valid(checkpoint) {
			return errors.New("valid checkpoint JSON is required")
		}
		return engine.CheckpointDistributedJob(r.PathValue("id"), worker, checkpoint)
	})
}

func (s *Server) completeJob(w http.ResponseWriter, r *http.Request) {
	s.workerMutation(w, r, func(engine jobEngine, worker string, _ json.RawMessage) error {
		return engine.CompleteDistributedJob(r.PathValue("id"), worker)
	})
}

func (s *Server) failJob(w http.ResponseWriter, r *http.Request) {
	engine, ok := s.engine.(jobEngine)
	if !ok {
		writeError(w, http.StatusNotImplemented, "distributed jobs are unavailable")
		return
	}
	var request struct {
		WorkerID string `json:"worker_id"`
		Error    string `json:"error"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if strings.TrimSpace(request.Error) == "" {
		writeError(w, http.StatusBadRequest, "error message is required")
		return
	}
	if err := engine.FailDistributedJob(r.PathValue("id"), request.WorkerID, request.Error); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "accepted"})
}

func (s *Server) cancelJob(w http.ResponseWriter, r *http.Request) {
	engine, ok := s.engine.(jobEngine)
	if !ok {
		writeError(w, http.StatusNotImplemented, "distributed jobs are unavailable")
		return
	}
	if err := engine.CancelDistributedJob(r.PathValue("id")); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "cancel_requested"})
}

func (s *Server) workerMutation(w http.ResponseWriter, r *http.Request,
	action func(jobEngine, string, json.RawMessage) error) {
	engine, ok := s.engine.(jobEngine)
	if !ok {
		writeError(w, http.StatusNotImplemented, "distributed jobs are unavailable")
		return
	}
	var request struct {
		WorkerID   string          `json:"worker_id"`
		Checkpoint json.RawMessage `json:"checkpoint,omitempty"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if strings.TrimSpace(request.WorkerID) == "" {
		writeError(w, http.StatusBadRequest, "worker_id is required")
		return
	}
	if err := action(engine, request.WorkerID, request.Checkpoint); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "accepted"})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) bool {
	if mediaType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])); mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type application/json required")
		return false
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		writeError(w, http.StatusBadRequest, "request must contain exactly one JSON document")
		return false
	}
	return true
}

func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(provided) != len(s.token) ||
			subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) != 1 {
			writeError(w, http.StatusUnauthorized, "valid bearer token required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) start(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	busy := s.state.Status == "running" || s.state.Status == "stopping"
	s.mu.RUnlock()
	if busy {
		writeError(w, http.StatusConflict, "a scan is already running")
		return
	}
	cfg := config.DefaultScanConfig()
	if !decodeJSON(w, r, &cfg) {
		return
	}
	if cfg.ScanID == "" {
		cfg.ScanID = fmt.Sprintf("api-scan-%d", time.Now().UnixNano())
	}
	cfg.SkipAutoReport = true
	if err := s.engine.StartScan(cfg); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	s.state = state{ScanID: cfg.ScanID, Status: "running", StartedAt: time.Now().UTC().Format(time.RFC3339)}
	s.mu.Unlock()
	go s.await(cfg.ScanID)
	writeJSON(w, http.StatusAccepted, s.snapshot())
}

func (s *Server) await(scanID string) {
	err := s.engine.WaitScanDone(context.Background())
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.ScanID != scanID {
		return
	}
	s.state.Status = "completed"
	if err != nil {
		s.state.Status = "failed"
		s.state.Error = err.Error()
	}
	s.state.EndedAt = time.Now().UTC().Format(time.RFC3339)
}

func (s *Server) current(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.snapshot())
}

func (s *Server) stop(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	if s.state.Status != "running" {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "no running scan")
		return
	}
	s.state.Status = "stopping"
	s.mu.Unlock()
	if err := s.engine.StopScan(); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, s.snapshot())
}

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimSpace(r.URL.Query().Get("scan_id"))
	if scanID == "" {
		writeError(w, http.StatusBadRequest, "scan_id is required")
		return
	}
	format, contentType, err := parseFormat(r.URL.Query().Get("format"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	data, err := s.engine.GenerateReport(report.Options{
		ScanID: scanID, Template: report.TemplateInternal, Format: format, Redact: true,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="akca-report-`+
		safeFilename(scanID)+`.`+extension(format)+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) snapshot() state {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func parseFormat(raw string) (report.Format, string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "json":
		return report.FormatJSON, "application/json", nil
	case "sarif":
		return report.FormatSARIF, "application/sarif+json", nil
	case "html":
		return report.FormatHTML, "text/html; charset=utf-8", nil
	case "csv":
		return report.FormatCSV, "text/csv; charset=utf-8", nil
	case "markdown", "md":
		return report.FormatMarkdown, "text/markdown; charset=utf-8", nil
	default:
		return "", "", fmt.Errorf("unsupported report format %q", raw)
	}
}

func extension(format report.Format) string {
	if format == report.FormatMarkdown {
		return "md"
	}
	return string(format)
}

func safeFilename(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return strconv.FormatInt(time.Now().Unix(), 10)
	}
	return b.String()
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message, "status": status})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

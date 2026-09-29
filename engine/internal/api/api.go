// Package api is the engine's control surface.
//
// It is a new way to reach the engine, so it is also a new way to reach
// whatever the engine can reach. Two things follow, and both are enforced
// here rather than left to deployment:
//
//   - The API grants no path around the safety layer. Starting a run takes
//     the same session config a command-line run takes, it goes through the
//     same safety.SessionConfig.Prepare, and the same guarded client is built
//     from it. There is no field that skips the authorisation acknowledgement,
//     no way to widen the scope after the fact, and no endpoint that sends a
//     request the caller composed.
//   - Every endpoint but the health check requires the shared token. The
//     orchestrator is the only intended caller and it is on an internal
//     network; the token is what makes that a requirement rather than an
//     assumption.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"mihakk/internal/aggregate"
	"mihakk/internal/audit"
	"mihakk/internal/corpus"
	"mihakk/internal/detect"
	"mihakk/internal/events"
	"mihakk/internal/mutate"
	"mihakk/internal/runner"
	"mihakk/internal/safety"
	"mihakk/internal/store"
)

// DefaultBufferCapacity is how many events one run retains for consumers that
// fall behind. Large enough that an orchestrator restart does not lose a
// normal run; bounded, because a stalled consumer must not grow memory
// without limit inside the process that is also sending traffic.
const DefaultBufferCapacity = 4096

// Config wires the server.
type Config struct {
	// Token is the shared secret. An empty token is refused: the control API
	// is unauthenticated without it, and an unauthenticated control API is a
	// way to make the engine send traffic on someone else's behalf.
	Token string

	EngineVersion  string
	Store          *store.Store
	Audit          *audit.Log
	BufferCapacity int

	Now func() time.Time
}

// Server holds the running and finished runs.
type Server struct {
	cfg  Config
	mu   sync.Mutex
	runs map[string]*run
	now  func() time.Time
}

// run is one execution and its event buffer.
type run struct {
	id       string
	buffer   *events.Buffer
	governor *safety.Governor
	cancel   context.CancelFunc

	mu       sync.Mutex
	status   string
	stopped  bool
	finished bool
}

// New validates the configuration and returns a server.
func New(cfg Config) (*Server, error) {
	if strings.TrimSpace(cfg.Token) == "" {
		return nil, errors.New("mihakk: the control API requires a shared token; " +
			"running it without one would let anything that can reach the port make the " +
			"engine send traffic")
	}
	if cfg.Store == nil {
		return nil, errors.New("mihakk: the control API needs a store")
	}
	if cfg.EngineVersion == "" {
		return nil, errors.New("mihakk: the control API needs an engine version")
	}
	if cfg.BufferCapacity <= 0 {
		cfg.BufferCapacity = DefaultBufferCapacity
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Server{cfg: cfg, runs: map[string]*run{}, now: now}, nil
}

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// The only unauthenticated endpoint. It reveals nothing but liveness.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "ok", "engine_version": s.cfg.EngineVersion,
		})
	})

	mux.Handle("POST /v1/runs", s.authed(s.handleStartRun))
	mux.Handle("GET /v1/runs/{id}", s.authed(s.handleRunStatus))
	mux.Handle("DELETE /v1/runs/{id}", s.authed(s.handleStopRun))
	mux.Handle("GET /v1/runs/{id}/events", s.authed(s.handleEvents))
	mux.Handle("GET /v1/runs/{id}/aggregate", s.authed(s.handleAggregate))
	mux.Handle("POST /v1/reproduce/{caseID}", s.authed(s.handleReproduce))

	return mux
}

// authed rejects anything without the shared token.
func (s *Server) authed(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.tokenOK(r) {
			// No detail: a caller without the token learns only that it needs
			// one, not whether the path or the run id exists.
			w.Header().Set("WWW-Authenticate", `Bearer realm="mihakk"`)
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error": "unauthorized", "detail": "a valid bearer token is required",
			})
			return
		}
		next(w, r)
	})
}

func (s *Server) tokenOK(r *http.Request) bool {
	header := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	presented := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	// Constant time, so the comparison does not leak the token by timing.
	return subtle.ConstantTimeCompare([]byte(presented), []byte(s.cfg.Token)) == 1
}

// StartRunRequest is the body of POST /v1/runs.
//
// It carries the same session config a command-line run takes. There is
// deliberately no way to express "skip the acknowledgement" or "widen the
// scope": the fields simply do not exist, so the API cannot be used to reach
// somewhere the configuration does not already authorise.
type StartRunRequest struct {
	SessionID string                `json:"session_id"`
	Config    *safety.SessionConfig `json:"config"`
	Corpus    *corpus.Corpus        `json:"corpus"`

	// OpenAPI, when set, is a document to build the corpus from instead.
	OpenAPI string `json:"openapi,omitempty"`
	BaseURL string `json:"base_url,omitempty"`

	Seed           string         `json:"seed"`
	MutationConfig *mutate.Config `json:"mutation_config,omitempty"`
	MaxCases       int            `json:"max_cases,omitempty"`
}

// StartRunResponse is returned on success.
type StartRunResponse struct {
	SessionID     string `json:"session_id"`
	EngineVersion string `json:"engine_version"`
	ScopeDigest   string `json:"scope_digest"`
	CorpusDigest  string `json:"corpus_digest"`
	ConfigDigest  string `json:"config_digest"`
	PlannedCases  int    `json:"planned_cases"`
	EventsURL     string `json:"events_url"`
}

func (s *Server) handleStartRun(w http.ResponseWriter, r *http.Request) {
	var req StartRunRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	// The session id becomes a directory name in the store. The store refuses an
	// unsafe one on its own, but refusing it here turns what would surface as an
	// internal write failure into a plain 400 that names the problem.
	if err := store.ValidSessionID(req.SessionID); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.Config == nil {
		writeError(w, http.StatusBadRequest, "authorization_required",
			"a session config carrying the authorisation acknowledgement is required")
		return
	}

	// The same gate a command-line run passes through: scope validated,
	// limits validated, acknowledgement current and bound to this scope.
	if err := req.Config.Prepare(s.now()); err != nil {
		status := http.StatusBadRequest
		code := "invalid_config"
		switch {
		case errors.Is(err, safety.ErrNoAuthorization),
			errors.Is(err, safety.ErrAuthorizationInvalid),
			errors.Is(err, safety.ErrAuthorizationScopeMismatch):
			status = http.StatusForbidden
			code = "authorization_required"
		}
		writeError(w, status, code, err.Error())
		return
	}

	c, err := resolveCorpus(&req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_corpus", err.Error())
		return
	}

	seed, err := decodeSeed(req.Seed)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	mutCfg := mutate.DefaultConfig()
	if req.MutationConfig != nil {
		mutCfg = *req.MutationConfig
	}
	plan, err := mutate.NewPlan(c, mutCfg, s.cfg.EngineVersion, seed)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_plan", err.Error())
		return
	}

	s.mu.Lock()
	if _, exists := s.runs[req.SessionID]; exists {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "already_exists",
			fmt.Sprintf("session %q already exists", req.SessionID))
		return
	}
	s.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	gov, err := safety.NewGovernor(ctx, req.Config.Limits, nil)
	if err != nil {
		cancel()
		writeError(w, http.StatusBadRequest, "invalid_config", err.Error())
		return
	}

	redactor := req.Config.NewRedactor()
	client, err := safety.NewClient(safety.ClientConfig{
		Scope:         &req.Config.Scope,
		Governor:      gov,
		Authorization: req.Config.Authorization,
		Redactor:      redactor,
	})
	if err != nil {
		gov.Stop()
		cancel()
		writeError(w, http.StatusForbidden, "authorization_required", err.Error())
		return
	}

	buffer := events.NewBuffer(req.SessionID, s.cfg.BufferCapacity, s.now)
	active := &run{
		id: req.SessionID, buffer: buffer, governor: gov,
		cancel: cancel, status: "running",
	}

	s.mu.Lock()
	s.runs[req.SessionID] = active
	s.mu.Unlock()

	r2, err := runner.New(runner.Options{
		SessionID: req.SessionID, EngineVersion: s.cfg.EngineVersion, Seed: seed,
		Client: client, Governor: gov, Plan: plan, Corpus: c, Config: req.Config,
		Detector: detect.New(detect.DefaultConfig()),
		Store:    s.cfg.Store, Audit: s.cfg.Audit, Redactor: redactor,
		MaxCases: req.MaxCases,
		OnEvent:  buffer.Append,
	})
	if err != nil {
		gov.Stop()
		cancel()
		s.removeRun(req.SessionID)
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	go s.execute(ctx, active, r2)

	// From the client that will enforce it, like the stored record and the audit
	// event. The orchestrator keeps this digest and later compares it against the
	// one in the aggregate; both must describe the scope that governed traffic,
	// not the configuration the request happened to carry.
	enforcedScope := client.Scope()

	writeJSON(w, http.StatusAccepted, StartRunResponse{
		SessionID:     req.SessionID,
		EngineVersion: s.cfg.EngineVersion,
		ScopeDigest:   enforcedScope.Digest(),
		CorpusDigest:  plan.CorpusDigest(),
		ConfigDigest:  plan.ConfigDigest(),
		PlannedCases:  plan.Total(),
		EventsURL:     "/v1/runs/" + req.SessionID + "/events",
	})
}

// execute runs the plan and closes the stream when it ends.
func (s *Server) execute(ctx context.Context, active *run, r *runner.Runner) {
	defer active.buffer.Close()
	defer active.cancel()

	result, err := r.Run(ctx)

	active.mu.Lock()
	active.finished = true
	switch {
	case err != nil:
		active.status = "failed"
	case result.Incomplete:
		active.status = store.SessionIncomplete
	case result.Stopped:
		active.status = store.SessionStopped
	default:
		active.status = store.SessionCompleted
	}
	status := active.status
	active.mu.Unlock()

	if err != nil {
		active.buffer.Append(events.Event{
			Type: events.Error,
			Error: &events.ErrorInfo{
				Code: "run_failed", Message: err.Error(), Fatal: true,
			},
		})
	}

	_, lastSeq, dropped, _ := active.buffer.Stats()
	// The done event carries the final sequence number, which is how a
	// consumer decides whether it has everything rather than guessing.
	active.buffer.Append(events.Event{
		Type: events.Done,
		Done: &events.DoneInfo{
			Status: status, TotalSeq: lastSeq + 1, EventsDropped: dropped,
		},
	})
}

func (s *Server) handleRunStatus(w http.ResponseWriter, r *http.Request) {
	active := s.lookup(r.PathValue("id"))
	if active == nil {
		writeError(w, http.StatusNotFound, "not_found", "no such run")
		return
	}
	firstSeq, lastSeq, dropped, closed := active.buffer.Stats()

	active.mu.Lock()
	status := active.status
	active.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"session_id":     active.id,
		"status":         status,
		"first_seq":      firstSeq,
		"last_seq":       lastSeq,
		"events_dropped": dropped,
		"stream_closed":  closed,
	})
}

func (s *Server) handleStopRun(w http.ResponseWriter, r *http.Request) {
	active := s.lookup(r.PathValue("id"))
	if active == nil {
		writeError(w, http.StatusNotFound, "not_found", "no such run")
		return
	}
	// The kill switch: this cancels in-flight requests, it does not wait for
	// them to finish.
	active.governor.Stop()
	active.cancel()

	active.mu.Lock()
	active.stopped = true
	active.mu.Unlock()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"session_id": active.id, "stopping": true,
	})
}

// handleEvents streams NDJSON from a sequence number.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	active := s.lookup(r.PathValue("id"))
	if active == nil {
		writeError(w, http.StatusNotFound, "not_found", "no such run")
		return
	}

	fromSeq := int64(0)
	if raw := r.URL.Query().Get("from_seq"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 0 {
			writeError(w, http.StatusBadRequest, "invalid_request",
				"from_seq must be a non-negative integer")
			return
		}
		fromSeq = parsed
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)

	// If the requested point has already been evicted, say so before sending
	// anything else. Handing over a later event without this notice would
	// present a gap as continuity.
	if missing := active.buffer.GapAfter(fromSeq); missing > 0 {
		if err := enc.Encode(active.buffer.GapNotice(missing)); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}

	for {
		batch := active.buffer.After(fromSeq)
		if batch == nil {
			return // the run ended and nothing is left
		}
		for _, e := range batch {
			if err := enc.Encode(e); err != nil {
				return // the consumer went away; the buffer keeps the events
			}
			fromSeq = e.Seq
		}
		if flusher != nil {
			flusher.Flush()
		}
		if r.Context().Err() != nil {
			return
		}
	}
}

// handleAggregate serves the run's grouped results.
//
// Read from the store, not from the in-memory run map. A finished run is gone
// from that map, and an engine that restarted never had it -- yet its files are
// on disk, so a report about it is perfectly answerable. Serving this from memory
// would make the aggregate available only for the runs that happen to be live,
// which is the opposite of what a report needs.
func (s *Server) handleAggregate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := store.ValidSessionID(id); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	sess, err := s.cfg.Store.LoadSession(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "no stored session with that id")
		return
	}
	cases, err := s.cfg.Store.Cases(id)
	if err != nil {
		// Unreadable cases are not an empty result set: answering with zero groups
		// would report a clean run that was never established.
		writeError(w, http.StatusInternalServerError, "unreadable_cases", err.Error())
		return
	}

	doc, err := aggregate.Build(sess, cases)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "aggregate_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

func (s *Server) handleReproduce(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("caseID")

	// A case id carries a session id, and it arrives straight off the URL path.
	if _, _, err := store.ParseCaseID(caseID); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	var req StartRunRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.Config == nil {
		writeError(w, http.StatusBadRequest, "authorization_required",
			"a session config carrying the authorisation acknowledgement is required")
		return
	}
	// Reproduction is re-authorised exactly like a fresh run.
	if err := req.Config.Prepare(s.now()); err != nil {
		writeError(w, http.StatusForbidden, "authorization_required", err.Error())
		return
	}

	c, err := resolveCorpus(&req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_corpus", err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	gov, err := safety.NewGovernor(ctx, req.Config.Limits, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_config", err.Error())
		return
	}
	defer gov.Stop()

	redactor := req.Config.NewRedactor()
	client, err := safety.NewClient(safety.ClientConfig{
		Scope: &req.Config.Scope, Governor: gov,
		Authorization: req.Config.Authorization, Redactor: redactor,
	})
	if err != nil {
		writeError(w, http.StatusForbidden, "authorization_required", err.Error())
		return
	}

	result, err := runner.Reproduce(ctx, runner.ReproduceOptions{
		CaseID: caseID, EngineVersion: s.cfg.EngineVersion,
		Client: client, Governor: gov, Config: req.Config, Corpus: c,
		Detector: detect.New(detect.DefaultConfig()),
		Store:    s.cfg.Store, Audit: s.cfg.Audit, Redactor: redactor,
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "reproduce_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) lookup(id string) *run {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runs[id]
}

func (s *Server) removeRun(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.runs, id)
}

// StopAll stops every run; used when the server shuts down.
func (s *Server) StopAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, active := range s.runs {
		active.governor.Stop()
		active.cancel()
	}
}

func resolveCorpus(req *StartRunRequest) (*corpus.Corpus, error) {
	switch {
	case req.Corpus != nil && req.OpenAPI != "":
		return nil, errors.New("pass either corpus or openapi, not both")
	case req.OpenAPI != "":
		result, err := corpus.LoadOpenAPI([]byte(req.OpenAPI), req.BaseURL)
		if err != nil {
			return nil, err
		}
		return result.Corpus, nil
	case req.Corpus != nil:
		req.Corpus.Normalize()
		if err := req.Corpus.Validate(); err != nil {
			return nil, err
		}
		return req.Corpus, nil
	default:
		return nil, errors.New("one of corpus or openapi is required")
	}
}

func decodeSeed(raw string) ([]byte, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("seed is required; a run with no recorded seed cannot be reproduced")
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("seed must be hex: %w", err)
	}
	if len(decoded) == 0 {
		return nil, errors.New("seed must not be empty")
	}
	return decoded, nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, code, detail string) {
	writeJSON(w, status, map[string]any{"error": code, "detail": detail})
}

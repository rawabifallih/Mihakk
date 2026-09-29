// Package audit records who ran what, against which targets, under which
// limits, and when it stopped.
//
// The log is append-only and separate from results: results answer "what did
// the tool find", the audit log answers "what did the tool do, on whose
// authority". Those are different questions, and the second one is the reason
// a defensive fuzzer is safe to operate at all.
//
// Everything written here passes through the redactor first. The log is the
// file most likely to be shared with someone who was not in the room, so it
// is the last place a bearer token should end up.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"mihakk/internal/safety"
)

// EventType names an auditable moment.
type EventType string

const (
	SessionStarted    EventType = "session_started"
	SessionStopped    EventType = "session_stopped"
	RequestRefused    EventType = "request_refused"
	ReproduceStarted  EventType = "reproduce_started"
	ReproduceFinished EventType = "reproduce_finished"
)

// Event is one line of the audit log.
type Event struct {
	At   time.Time `json:"at"`
	Type EventType `json:"type"`

	SessionID string `json:"session_id,omitempty"`
	CaseID    string `json:"case_id,omitempty"`

	// Authorisation, recorded verbatim: who accepted responsibility, the
	// exact words they accepted, and when.
	Operator    string     `json:"operator,omitempty"`
	Statement   string     `json:"statement,omitempty"`
	AckedAt     *time.Time `json:"authorisation_acked_at,omitempty"`
	ScopeDigest string     `json:"scope_digest,omitempty"`

	EngineVersion string   `json:"engine_version,omitempty"`
	ConfigDigest  string   `json:"config_digest,omitempty"`
	CorpusDigest  string   `json:"corpus_digest,omitempty"`
	Seed          string   `json:"seed,omitempty"`
	Targets       []string `json:"targets,omitempty"`

	Limits *safety.Limits `json:"limits,omitempty"`

	Outcome string         `json:"outcome,omitempty"`
	Reason  string         `json:"reason,omitempty"`
	Detail  string         `json:"detail,omitempty"`
	Stats   map[string]any `json:"stats,omitempty"`
}

// Log is an append-only audit log.
type Log struct {
	mu       sync.Mutex
	path     string
	redactor *safety.Redactor
	now      func() time.Time
}

// Open creates or appends to the audit log at path.
func Open(path string, redactor *safety.Redactor) (*Log, error) {
	if redactor == nil {
		redactor = safety.NewRedactor()
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("mihakk: creating audit directory: %w", err)
		}
	}
	// Touch the file now so a permission problem surfaces before a session
	// starts, not after it has already sent traffic.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("mihakk: opening audit log: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return &Log{path: path, redactor: redactor, now: time.Now}, nil
}

// Path is where the log is being written.
func (l *Log) Path() string { return l.path }

// Write appends one event, filling in the timestamp and redacting the fields
// that could carry secrets.
func (l *Log) Write(e Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if e.At.IsZero() {
		e.At = l.now().UTC()
	}
	e.Reason = l.redactor.String(e.Reason)
	e.Detail = l.redactor.String(e.Detail)
	e.Outcome = l.redactor.String(e.Outcome)
	for i, t := range e.Targets {
		e.Targets[i] = l.redactor.String(t)
	}
	if e.Stats != nil {
		cleaned := make(map[string]any, len(e.Stats))
		for k, v := range e.Stats {
			if s, ok := v.(string); ok {
				cleaned[k] = l.redactor.String(s)
				continue
			}
			cleaned[k] = v
		}
		e.Stats = cleaned
	}

	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("mihakk: encoding audit event: %w", err)
	}

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("mihakk: opening audit log: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("mihakk: writing audit event: %w", err)
	}
	// An audit record that is still in a buffer when the process is killed
	// did not happen, so each event is durable before Write returns.
	return f.Sync()
}

// Read returns every event in the log, oldest first. Used by tests and by
// anyone inspecting what a run did.
func Read(path string) ([]Event, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var events []Event
	dec := json.NewDecoder(newLineReader(raw))
	for {
		var e Event
		if err := dec.Decode(&e); err != nil {
			break
		}
		events = append(events, e)
	}
	return events, nil
}

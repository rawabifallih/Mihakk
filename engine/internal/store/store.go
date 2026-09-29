// Package store persists sessions and the cases worth keeping.
//
// A case is stored as a regeneration recipe rather than as the bytes that
// were sent. The engine can rebuild the exact request from the seed, the case
// index and the digests, which means credentials supplied at run time never
// reach the disk at all -- not redacted, simply never written. What is stored
// alongside, for a human to read, is a redacted summary.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"mihakk/internal/detect"
	"mihakk/internal/mutate"
	"mihakk/internal/safety"
)

// Reproduction is everything needed to regenerate the request.
type Reproduction struct {
	EngineVersion string `json:"engine_version"`
	MasterSeed    string `json:"master_seed"`
	CaseIndex     int    `json:"case_index"`
	CorpusDigest  string `json:"corpus_digest"`
	ConfigDigest  string `json:"config_digest"`
	Target        string `json:"target"`
}

// RequestSummary is the redacted, human-readable view of what was prepared for
// an attempt. A transport error can mean no HTTP bytes reached the target.
type RequestSummary struct {
	Method      string              `json:"method"`
	URL         string              `json:"url"`
	Headers     map[string][]string `json:"headers,omitempty"`
	BodyPreview string              `json:"body_preview,omitempty"`
	BodyBytes   int                 `json:"body_bytes"`
	Redacted    bool                `json:"redacted"`
}

// ResponseSummary is what came back.
type ResponseSummary struct {
	StatusCode *int     `json:"status_code"`
	LatencyMS  *float64 `json:"latency_ms"`
	BodyBytes  *int     `json:"body_bytes"`
	Truncated  bool     `json:"truncated"`
	Error      *string  `json:"error"`
}

// Accounting is what became of a run's requests, beyond the case counts.
//
// "Attempted" means the safety layer let it through, not that the target got
// it: a refused connection is an attempt. "Answered" means a response was
// observed. Cases and HTTP requests are separate units -- a redirected case is
// one case and several requests.
type Accounting struct {
	// CasesAttempted can overlap a refused case when an earlier redirect hop was
	// attempted before a later hop was locally refused. CasesAnswered and
	// BaselineAnswered count requests that completed with a final response.
	// HTTPAnswered counts every response, including redirect hops.
	CasesAttempted    int   `json:"cases_attempted"`
	CasesAnswered     int   `json:"cases_answered"`
	BaselineAttempted int   `json:"baseline_attempted"`
	BaselineRefused   int   `json:"baseline_refused"`
	BaselineAnswered  int   `json:"baseline_answered"`
	HTTPAnswered      int64 `json:"http_answered"`
	HTTPUnanswered    int64 `json:"http_unanswered"`
	HTTPRefused       int64 `json:"http_refused"`
}

// Case is one saved indicator-bearing request.
type Case struct {
	CaseID     string    `json:"case_id"`
	SessionID  string    `json:"session_id"`
	ObservedAt time.Time `json:"observed_at"`

	Reproduction    Reproduction       `json:"reproduction"`
	RequestSummary  RequestSummary     `json:"request_summary"`
	Indicators      []detect.Indicator `json:"indicators"`
	ResponseSummary ResponseSummary    `json:"response_summary"`

	// Status is a constant reminder of what this record is. Nothing in the
	// engine decides a case is a vulnerability, and the stored record should
	// not be readable as though it had.
	Status string `json:"status"`
}

// StatusNeedsVerification is the only status the engine ever assigns.
const StatusNeedsVerification = "indicator_needs_verification"

// Session is the record of one run.
type Session struct {
	SessionID     string     `json:"session_id"`
	EngineVersion string     `json:"engine_version"`
	StartedAt     time.Time  `json:"started_at"`
	EndedAt       *time.Time `json:"ended_at,omitempty"`
	Status        string     `json:"status"`

	Operator string `json:"operator"`

	// Scope is a copy of the scope the guarded client enforced for this run,
	// taken from that client rather than from the configuration it was built out
	// of. ScopeDigest and Targets are derived from this same copy, so no part of
	// the record can describe a different scope from another part.
	//
	// Absent in sessions written before the engine recorded it. A reader must
	// then fall back to Targets alone and must not present it as the full scope.
	Scope *safety.Scope `json:"scope,omitempty"`

	ScopeDigest  string   `json:"scope_digest"`
	ConfigDigest string   `json:"config_digest"`
	CorpusDigest string   `json:"corpus_digest"`
	MasterSeed   string   `json:"master_seed"`
	Targets      []string `json:"targets"`

	PlannedCases  int `json:"planned_cases"`
	ExecutedCases int `json:"executed_cases"`
	SavedCases    int `json:"saved_cases"`
	RefusedCases  int `json:"refused_cases"`

	// What became of the run's requests. A pointer, and absent from sessions an
	// engine before this field wrote: nil means NOT COUNTED, which is not zero,
	// and every reader downstream has to be able to tell the two apart.
	Accounting *Accounting `json:"accounting,omitempty"`

	// Indicators that were observed but could not be written down, and audit
	// events that could not be recorded. Either one means the stored result
	// is a subset of what the run actually saw, so the session is reported as
	// incomplete rather than completed.
	UnsavedCases     int    `json:"unsaved_cases"`
	AuditFailures    int    `json:"audit_failures"`
	IncompleteReason string `json:"incomplete_reason,omitempty"`

	StopReason string `json:"stop_reason,omitempty"`

	// MutationConfig is part of the reproduction recipe. The case index only
	// means anything against a plan built with these settings: mutations per
	// target decides how many cases exist, so a reproduce that guessed at
	// defaults would regenerate the wrong request, or none.
	MutationConfig mutate.Config `json:"mutation_config"`

	// Baselines are kept so a later reproduce can compare against the same
	// sense of normal the original run used, rather than a fresh one that may
	// have drifted.
	Baselines map[string]*detect.Baseline `json:"baselines,omitempty"`
}

// Session statuses.
const (
	SessionCompleted = "completed"
	SessionStopped   = "stopped"
	SessionFailed    = "failed"

	// SessionIncomplete means the run finished but something it observed was
	// not recorded: a case that could not be written, an audit event that
	// could not be appended. "completed" would claim the stored results are
	// everything the run found, which would then be untrue.
	//
	// This covers storage failing directly. Losing events in transit between
	// the engine and the orchestrator is a separate matter, handled by the
	// completeness contract in schemas/session.schema.json.
	SessionIncomplete = "incomplete"
)

// Store is a directory of sessions.
type Store struct {
	mu   sync.Mutex
	root string

	// sessions is an open handle on <root>/sessions. Every file operation goes
	// through it, and it refuses any path that leaves that directory -- including
	// one that leaves through a symlink. Because the handle is a descriptor on
	// the directory itself, the refusal happens inside the same syscall that
	// opens the file, so there is no moment between checking and opening in
	// which a link could be swapped.
	sessions *os.Root
}

// ErrInvalidSessionID is returned for any session id that is not a plain name.
var ErrInvalidSessionID = errors.New("mihakk: invalid session id")

// maxSessionIDLength is generous for a human-chosen name and short enough that a
// session id can never approach a filesystem path limit.
const maxSessionIDLength = 128

// ValidSessionID is the first of three independent defences on the one place a
// caller-supplied string becomes a filesystem path.
//
// A session id arrives from POST /v1/runs, from a case id in a reproduce URL, and
// from the command line. Before this existed it was joined straight into a path,
// and filepath.Join cleans as it joins: an id of "../../x" resolved outside the
// store entirely, which was demonstrated to read and to overwrite files there.
//
// This is an allowlist, and it refuses rather than sanitises. Stripping the parts
// it dislikes would invite an encoding that survives the stripping; a name that
// is not already safe is simply not accepted.
func ValidSessionID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: it is empty", ErrInvalidSessionID)
	}
	if len(id) > maxSessionIDLength {
		return fmt.Errorf("%w: it is longer than %d characters", ErrInvalidSessionID, maxSessionIDLength)
	}
	if id == "." || id == ".." {
		return fmt.Errorf("%w: %q names a directory rather than a session", ErrInvalidSessionID, id)
	}
	// A leading dot hides the directory; a leading dash is read as a flag by
	// anything that later passes the id to a command.
	if id[0] == '.' || id[0] == '-' {
		return fmt.Errorf("%w: %q starts with %q", ErrInvalidSessionID, id, id[0:1])
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return fmt.Errorf("%w: %q contains %q; only letters, digits, dot, underscore and dash are allowed",
				ErrInvalidSessionID, id, r)
		}
	}
	return nil
}

// containedIn is the second defence: a lexical check that a resolved path still
// sits beneath the directory it is supposed to.
//
// It is deliberately independent of ValidSessionID rather than trusting it, and
// it is independent of the os.Root handle too. It catches a lexical escape even
// if the allowlist is ever loosened, and it gives a clear error before any
// syscall is attempted. It does NOT stop a symlink -- a planted link is lexically
// innocent -- which is why the third defence exists.
func containedIn(dir, candidate string) error {
	absDir, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return fmt.Errorf("mihakk: resolving %q: %w", dir, err)
	}
	absCandidate, err := filepath.Abs(filepath.Clean(candidate))
	if err != nil {
		return fmt.Errorf("mihakk: resolving %q: %w", candidate, err)
	}
	if absCandidate == absDir {
		return fmt.Errorf("%w: it resolves to the sessions directory itself", ErrInvalidSessionID)
	}
	if !strings.HasPrefix(absCandidate+string(filepath.Separator),
		absDir+string(filepath.Separator)) {
		return fmt.Errorf("%w: it resolves to %q, outside %q",
			ErrInvalidSessionID, absCandidate, absDir)
	}
	return nil
}

// Open prepares a store rooted at dir.
func Open(dir string) (*Store, error) {
	sessions := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(sessions, 0o750); err != nil {
		return nil, fmt.Errorf("mihakk: creating store: %w", err)
	}
	// Opened once, held for the store's lifetime. Re-opening per operation would
	// re-resolve the sessions directory each time, so a swap of that directory
	// itself would be followed; a held descriptor pins the directory it opened.
	root, err := os.OpenRoot(sessions)
	if err != nil {
		return nil, fmt.Errorf("mihakk: opening store root: %w", err)
	}
	return &Store{root: dir, sessions: root}, nil
}

// Close releases the store's directory handle.
func (s *Store) Close() error {
	if s.sessions == nil {
		return nil
	}
	return s.sessions.Close()
}

// sessionsDir is the directory every session lives beneath.
func (s *Store) sessionsDir() string { return filepath.Join(s.root, "sessions") }

// checkSessionID applies the first two defences to an id.
//
// It deliberately returns no path. An earlier version handed back the directory
// it had just validated, which is how a textual path came to be used for the
// session listing instead of the rooted handle; with nothing to hand back, that
// slip has nowhere to start.
func (s *Store) checkSessionID(id string) error {
	if err := ValidSessionID(id); err != nil {
		return err
	}
	return containedIn(s.sessionsDir(), filepath.Join(s.sessionsDir(), id))
}

// sessionFile is the store-root-relative path of one file inside a session.
// Slash-separated: the id is validated to contain no separator of any kind.
func sessionFile(id, name string) string { return id + "/" + name }

// CaseID builds the stable identifier for a case: session plus case index, so
// it can be typed by hand into `mihakk reproduce`.
func CaseID(sessionID string, index int) string {
	return fmt.Sprintf("%s-%06d", sessionID, index)
}

// ParseCaseID splits a case id back into its parts.
//
// The session half is validated here, not only where a session id arrives on its
// own: a case id comes straight off a reproduce URL path, so it is a second door
// into the same filesystem join.
func ParseCaseID(caseID string) (sessionID string, index int, err error) {
	i := strings.LastIndex(caseID, "-")
	if i < 0 {
		return "", 0, fmt.Errorf("mihakk: %q is not a case id", caseID)
	}
	if _, err := fmt.Sscanf(caseID[i+1:], "%d", &index); err != nil {
		return "", 0, fmt.Errorf("mihakk: %q is not a case id", caseID)
	}
	sessionID = caseID[:i]
	if err := ValidSessionID(sessionID); err != nil {
		return "", 0, fmt.Errorf("mihakk: %q is not a case id: %w", caseID, err)
	}
	return sessionID, index, nil
}

// SaveSession writes (or rewrites) the session record.
func (s *Store) SaveSession(sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.checkSessionID(sess.SessionID); err != nil {
		return err
	}
	if err := s.mkdirSession(sess.SessionID); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(sess, "", "  ")
	if err != nil {
		return fmt.Errorf("mihakk: encoding session: %w", err)
	}
	return s.writeFile(sessionFile(sess.SessionID, "session.json"), append(raw, '\n'))
}

// LoadSession reads a session record.
func (s *Store) LoadSession(id string) (*Session, error) {
	if err := s.checkSessionID(id); err != nil {
		return nil, err
	}
	raw, err := s.readFile(sessionFile(id, "session.json"))
	if err != nil {
		return nil, fmt.Errorf("mihakk: reading session %q: %w", id, err)
	}
	var sess Session
	if err := json.Unmarshal(raw, &sess); err != nil {
		return nil, fmt.Errorf("mihakk: decoding session %q: %w", id, err)
	}
	return &sess, nil
}

// AppendCase adds one case to the session's case log.
func (s *Store) AppendCase(c *Case) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if c.Status == "" {
		c.Status = StatusNeedsVerification
	}
	if err := s.checkSessionID(c.SessionID); err != nil {
		return err
	}
	if err := s.mkdirSession(c.SessionID); err != nil {
		return err
	}
	line, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("mihakk: encoding case: %w", err)
	}
	f, err := s.sessions.OpenFile(sessionFile(c.SessionID, "cases.jsonl"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("mihakk: opening case log: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("mihakk: writing case: %w", err)
	}
	return nil
}

// Cases returns every case saved for a session, in the order written.
func (s *Store) Cases(sessionID string) ([]*Case, error) {
	if err := s.checkSessionID(sessionID); err != nil {
		return nil, err
	}
	raw, err := s.readFile(sessionFile(sessionID, "cases.jsonl"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("mihakk: reading cases: %w", err)
	}
	var cases []*Case
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var c Case
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			return nil, fmt.Errorf("mihakk: decoding case: %w", err)
		}
		cases = append(cases, &c)
	}
	return cases, nil
}

// FindCase locates one case by id.
func (s *Store) FindCase(caseID string) (*Case, *Session, error) {
	sessionID, _, err := ParseCaseID(caseID)
	if err != nil {
		return nil, nil, err
	}
	sess, err := s.LoadSession(sessionID)
	if err != nil {
		return nil, nil, err
	}
	cases, err := s.Cases(sessionID)
	if err != nil {
		return nil, nil, err
	}
	for _, c := range cases {
		if c.CaseID == caseID {
			return c, sess, nil
		}
	}
	return nil, nil, fmt.Errorf("mihakk: no case %q in session %q", caseID, sessionID)
}

// Sessions lists stored session ids.
//
// Read through the same handle as every other operation, not by path. Reading it
// by path would resolve <data>/sessions afresh, so replacing that directory with
// a symlink after the store opened would have this listing report names from
// somewhere else while every other call still worked in the original directory.
// The handle is a descriptor on the directory it opened, so it keeps reading that
// one whatever the path now points at.
//
// Anything that is not a real directory with a valid id is skipped rather than
// reported: a symlink planted here is not a session, and listing it would invite
// every later call to try to follow it.
func (s *Store) Sessions() ([]string, error) {
	dir, err := s.sessions.Open(".")
	if err != nil {
		return nil, fmt.Errorf("mihakk: opening the sessions directory: %w", err)
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("mihakk: listing sessions: %w", err)
	}
	var ids []string
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 || !e.IsDir() {
			continue
		}
		if ValidSessionID(e.Name()) != nil {
			continue
		}
		ids = append(ids, e.Name())
	}
	return ids, nil
}

// --- the third defence: every file operation goes through the rooted handle ---
//
// os.Root refuses a path that leaves its directory, whether by dot-dot or by
// following a symlink, and it refuses inside the openat call itself. That closes
// the window a check-then-open pair would leave, in which a link could be
// swapped after the check and before the open.

func (s *Store) mkdirSession(id string) error {
	if err := s.sessions.Mkdir(id, 0o750); err != nil && !os.IsExist(err) {
		return fmt.Errorf("mihakk: creating session directory: %w", err)
	}
	return nil
}

func (s *Store) writeFile(rel string, data []byte) error {
	f, err := s.sessions.OpenFile(rel, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("mihakk: opening %s: %w", rel, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("mihakk: writing %s: %w", rel, err)
	}
	return f.Close()
}

func (s *Store) readFile(rel string) ([]byte, error) {
	f, err := s.sessions.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

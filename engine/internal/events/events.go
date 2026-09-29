// Package events defines the engine's outward event stream and the bounded
// buffer that holds it.
//
// The stream is the only way the orchestrator learns what a run is doing, so
// its honesty matters more than its throughput. Two rules follow from that:
//
//   - Sequence numbers are assigned by the buffer, contiguously, so a gap in
//     what a consumer receives is always a real loss and never an artefact of
//     how the producer numbered things.
//   - When the buffer has to evict, it says so. A consumer that resumes from
//     a point already evicted is told, in band, exactly how many events it
//     will never see, rather than being handed a later event as though it
//     followed the last one it had.
package events

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Type names a kind of event. These match schemas/event.schema.json.
type Type string

const (
	Started  Type = "started"
	Progress Type = "progress"
	Finding  Type = "finding"
	Error    Type = "error"
	Warning  Type = "warning"
	Done     Type = "done"
)

// GapSeq is the sequence number of an out-of-band notice.
//
// Real events are numbered from 1 and are contiguous. A notice that events
// were lost is not itself part of that sequence -- giving it a number would
// either leave a hole or renumber what follows -- so it carries 0, and a
// consumer must not count it towards contiguity.
const GapSeq int64 = 0

// ProgressInfo is the running count.
type ProgressInfo struct {
	RequestsUsed   int64 `json:"requests_used"`
	RequestsBudget int64 `json:"requests_budget"`
	Executed       int   `json:"executed"`
	Saved          int   `json:"saved"`
	Refused        int   `json:"refused"`
	Planned        int   `json:"planned"`
	// Attempted counts cases with at least one actual HTTP attempt. Unlike
	// Executed, it can overlap Refused when an answered redirect hop is followed
	// by a locally refused hop.
	Attempted int `json:"attempted"`
	// Cases that completed with a response. Executed counts cases the safety
	// layer let through, which is an attempt, not a delivery. HTTPAnswered below
	// counts every response, including intermediate redirect hops.
	Answered int `json:"answered"`
	// The baseline's unmutated requests, counted the same way.
	BaselineAttempted int `json:"baseline_attempted"`
	BaselineRefused   int `json:"baseline_refused"`
	BaselineAnswered  int `json:"baseline_answered"`
	// HTTP requests, one per redirect hop: the unit the budget is charged in.
	// Cases and requests are different counts and are never shown as one.
	HTTPAnswered   int64 `json:"http_answered"`
	HTTPUnanswered int64 `json:"http_unanswered"`
	HTTPRefused    int64 `json:"http_refused"`
	ElapsedMS      int64 `json:"elapsed_ms"`
}

// ErrorInfo describes a failure. The message is redacted before it gets here.
type ErrorInfo struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Fatal   bool   `json:"fatal"`
}

// WarningInfo describes something a consumer must not ignore.
type WarningInfo struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// EventsDropped is set on an events_dropped warning: the number of events
	// that existed and can no longer be delivered.
	EventsDropped int64 `json:"events_dropped,omitempty"`
}

// Warning codes.
const (
	WarnEventsDropped    = "events_dropped"
	WarnResponseTruncate = "response_truncated"
	WarnBaselineUnstable = "baseline_unstable"
)

// DoneInfo closes a run.
type DoneInfo struct {
	Status string `json:"status"`
	// TotalSeq is the last sequence number the engine emitted. A consumer
	// compares it with what it received to decide whether it has everything.
	TotalSeq      int64 `json:"total_seq"`
	EventsDropped int64 `json:"events_dropped"`
}

// Event is one line of the NDJSON stream.
type Event struct {
	Seq       int64     `json:"seq"`
	Type      Type      `json:"type"`
	SessionID string    `json:"session_id"`
	At        time.Time `json:"at"`

	Progress *ProgressInfo   `json:"progress,omitempty"`
	Finding  json.RawMessage `json:"finding,omitempty"`
	Error    *ErrorInfo      `json:"error,omitempty"`
	Warning  *WarningInfo    `json:"warning,omitempty"`
	Done     *DoneInfo       `json:"done,omitempty"`
}

// Buffer holds a run's events and hands them to consumers.
//
// It is bounded. An unbounded buffer would turn a slow or absent consumer
// into unbounded memory growth in the process that is also sending traffic at
// someone's application, which is the wrong thing to risk.
type Buffer struct {
	mu       sync.Mutex
	cond     *sync.Cond
	capacity int

	events  []Event
	nextSeq int64
	dropped int64
	closed  bool

	sessionID string
	now       func() time.Time
}

// NewBuffer creates a buffer holding at most capacity events.
func NewBuffer(sessionID string, capacity int, now func() time.Time) *Buffer {
	if capacity < 1 {
		capacity = 1
	}
	if now == nil {
		now = time.Now
	}
	b := &Buffer{
		capacity:  capacity,
		nextSeq:   1,
		sessionID: sessionID,
		now:       now,
	}
	b.cond = sync.NewCond(&b.mu)
	return b
}

// Append numbers an event and stores it, evicting the oldest if full.
func (b *Buffer) Append(e Event) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()

	e.Seq = b.nextSeq
	b.nextSeq++
	e.SessionID = b.sessionID
	if e.At.IsZero() {
		e.At = b.now().UTC()
	}

	b.events = append(b.events, e)
	if len(b.events) > b.capacity {
		evicted := len(b.events) - b.capacity
		b.events = b.events[evicted:]
		b.dropped += int64(evicted)
	}

	b.cond.Broadcast()
	return e.Seq
}

// Close marks the run finished; readers drain what is left and stop.
func (b *Buffer) Close() {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	b.cond.Broadcast()
}

// Stats reports what the buffer holds and what it lost.
func (b *Buffer) Stats() (firstSeq, lastSeq, dropped int64, closed bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.firstSeqLocked(), b.nextSeq - 1, b.dropped, b.closed
}

func (b *Buffer) firstSeqLocked() int64 {
	if len(b.events) == 0 {
		return b.nextSeq // nothing retained; the next event will be this
	}
	return b.events[0].Seq
}

// GapAfter reports how many events between fromSeq and the oldest retained
// event can no longer be delivered.
func (b *Buffer) GapAfter(fromSeq int64) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.gapAfterLocked(fromSeq)
}

func (b *Buffer) gapAfterLocked(fromSeq int64) int64 {
	if len(b.events) == 0 {
		return 0
	}
	wanted := fromSeq + 1
	if first := b.events[0].Seq; first > wanted {
		return first - wanted
	}
	return 0
}

// GapNotice builds the out-of-band event describing a gap.
func (b *Buffer) GapNotice(missing int64) Event {
	return Event{
		Seq:       GapSeq,
		Type:      Warning,
		SessionID: b.sessionID,
		At:        b.now().UTC(),
		Warning: &WarningInfo{
			Code:          WarnEventsDropped,
			EventsDropped: missing,
			Message: fmt.Sprintf("%d event(s) were evicted from the engine's buffer before "+
				"they could be delivered and are permanently lost; results derived from this "+
				"stream are a subset of what the run produced", missing),
		},
	}
}

// After returns events with a sequence number greater than fromSeq, blocking
// until at least one is available or the run is closed. It returns nil when
// the run has ended and nothing is left.
func (b *Buffer) After(fromSeq int64) []Event {
	b.mu.Lock()
	defer b.mu.Unlock()

	for {
		out := b.afterLocked(fromSeq)
		if len(out) > 0 {
			return out
		}
		if b.closed {
			return nil
		}
		b.cond.Wait()
	}
}

func (b *Buffer) afterLocked(fromSeq int64) []Event {
	var out []Event
	for _, e := range b.events {
		if e.Seq > fromSeq {
			out = append(out, e)
		}
	}
	return out
}

// Snapshot returns everything currently retained, for tests and diagnostics.
func (b *Buffer) Snapshot() []Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Event(nil), b.events...)
}

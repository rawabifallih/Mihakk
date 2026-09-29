package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"mihakk/internal/aggregate"
	"mihakk/internal/audit"
	"mihakk/internal/corpus"
	"mihakk/internal/events"
	"mihakk/internal/mutate"
	"mihakk/internal/safety"
	"mihakk/internal/store"
)

const testToken = "test-control-token-0123456789"
const testEngineVersion = "0.5.0-test"

// target is a loopback stand-in for an authorised application. Nothing in
// this file contacts anything else.
func newTarget(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/orders" {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if qty, ok := body["qty"]; ok {
				switch qty.(type) {
				case float64, string, bool:
				default:
					w.WriteHeader(500)
					_, _ = w.Write([]byte(`{"error":"internal_error","type":"TypeError"}`))
					return
				}
			}
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func newServer(t *testing.T, bufferCap int) (*httptest.Server, *store.Store, string) {
	t.Helper()
	dataDir := t.TempDir()
	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	auditLog, err := audit.Open(filepath.Join(dataDir, "audit.jsonl"), safety.NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	api, err := New(Config{
		Token: testToken, EngineVersion: testEngineVersion,
		Store: st, Audit: auditLog, BufferCapacity: bufferCap,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(api.StopAll)

	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return srv, st, dataDir
}

func scopeFor(t *testing.T, target *httptest.Server) safety.Scope {
	t.Helper()
	u, _ := url.Parse(target.URL)
	port, _ := strconv.Atoi(u.Port())
	s := safety.Scope{
		Targets: []safety.Target{{
			Scheme: u.Scheme, Host: u.Hostname(), Port: port,
			PathPrefixes:     []string{"/api"},
			Methods:          []string{"GET", "POST"},
			AllowedAddresses: []string{"127.0.0.1/32"},
		}},
		MaxRedirects: 2,
	}
	s.Normalize()
	return s
}

func startRequest(t *testing.T, target *httptest.Server, sessionID string) StartRunRequest {
	t.Helper()
	scope := scopeFor(t, target)
	raw := fmt.Sprintf(`{"corpus_version":"1","samples":[
	  {"id":"items","method":"GET","url":"%s/api/items?page=1&q=shoes",
	   "headers":{"Accept":["application/json"]}},
	  {"id":"orders","method":"POST","url":"%s/api/orders",
	   "headers":{"Content-Type":["application/json"]},
	   "body":"{\"sku\":\"A-1\",\"qty\":2}"}]}`, target.URL, target.URL)
	c, err := corpus.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	mutCfg := mutate.DefaultConfig()
	mutCfg.MutationsPerTarget = 12

	return StartRunRequest{
		SessionID: sessionID,
		Config: &safety.SessionConfig{
			ConfigVersion: safety.ConfigVersion,
			Scope:         scope,
			Limits: safety.Limits{
				RequestsPerSecond: 500, Burst: 100, MaxTotalRequests: 2000,
				MaxConcurrency: 4, MaxSessionDuration: safety.Duration(time.Minute),
				RequestTimeout: safety.Duration(5 * time.Second), MaxResponseBytes: 1 << 20,
			},
			Authorization: &safety.Authorization{
				Operator: "api-test", Statement: safety.RequiredStatement,
				AckedAt: time.Now(), ScopeDigest: scope.Digest(),
			},
		},
		Corpus:         c,
		Seed:           "a1b2c3d4",
		MutationConfig: &mutCfg,
	}
}

func do(t *testing.T, srv *httptest.Server, method, path, token string, body any) *http.Response {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, srv.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// --- The token -------------------------------------------------------------

func TestEveryEndpointButHealthNeedsTheToken(t *testing.T) {
	srv, _, _ := newServer(t, 0)

	guarded := []struct{ method, path string }{
		{"POST", "/v1/runs"},
		{"GET", "/v1/runs/anything"},
		{"DELETE", "/v1/runs/anything"},
		{"GET", "/v1/runs/anything/events"},
		{"GET", "/v1/runs/anything/aggregate"},
		{"POST", "/v1/reproduce/anything-000001"},
	}

	for _, ep := range guarded {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			for name, token := range map[string]string{
				"no token":      "",
				"wrong token":   "not-the-token",
				"empty bearer":  " ",
				"prefix of it":  testToken[:10],
				"token plus":    testToken + "x",
				"correct value": testToken,
			} {
				resp := do(t, srv, ep.method, ep.path, token, nil)
				resp.Body.Close()
				if name == "correct value" {
					if resp.StatusCode == http.StatusUnauthorized {
						t.Errorf("%s: the correct token was rejected", name)
					}
					continue
				}
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("%s: got %d, want 401", name, resp.StatusCode)
				}
			}
		})
	}

	// Health is open, and says nothing sensitive.
	resp := do(t, srv, "GET", "/healthz", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz without a token returned %d", resp.StatusCode)
	}
}

// A run must not start without a token, and the target must see nothing.
func TestAnUnauthenticatedStartSendsNothing(t *testing.T) {
	target, hits := newTarget(t)
	srv, _, _ := newServer(t, 0)

	resp := do(t, srv, "POST", "/v1/runs", "", startRequest(t, target, "unauth"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", resp.StatusCode)
	}
	time.Sleep(100 * time.Millisecond)
	if got := hits.Load(); got != 0 {
		t.Fatalf("the target received %d request(s) from an unauthenticated start", got)
	}
}

// --- No path around the safety layer ---------------------------------------

func TestStartRefusesWithoutAuthorization(t *testing.T) {
	target, hits := newTarget(t)
	srv, _, _ := newServer(t, 0)

	t.Run("no config at all", func(t *testing.T) {
		req := startRequest(t, target, "noconfig")
		req.Config = nil
		resp := do(t, srv, "POST", "/v1/runs", testToken, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("got %d, want 400", resp.StatusCode)
		}
	})

	t.Run("no acknowledgement", func(t *testing.T) {
		req := startRequest(t, target, "noack")
		req.Config.Authorization = nil
		resp := do(t, srv, "POST", "/v1/runs", testToken, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("got %d, want 403", resp.StatusCode)
		}
	})

	t.Run("acknowledgement for a different scope", func(t *testing.T) {
		req := startRequest(t, target, "wrongscope")
		req.Config.Authorization.ScopeDigest = "sha256:" + strings.Repeat("0", 64)
		resp := do(t, srv, "POST", "/v1/runs", testToken, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("got %d, want 403", resp.StatusCode)
		}
	})

	t.Run("stale acknowledgement", func(t *testing.T) {
		req := startRequest(t, target, "stale")
		req.Config.Authorization.AckedAt = time.Now().Add(-safety.MaxAckAge - time.Hour)
		resp := do(t, srv, "POST", "/v1/runs", testToken, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("got %d, want 403", resp.StatusCode)
		}
	})

	time.Sleep(100 * time.Millisecond)
	if got := hits.Load(); got != 0 {
		t.Fatalf("the target received %d request(s) from refused starts", got)
	}
}

// The API must not accept fields that would loosen the safety layer.
func TestStartRejectsUnknownFields(t *testing.T) {
	srv, _, _ := newServer(t, 0)

	body := `{"session_id":"x","skip_authorization":true,"config":{}}`
	req, _ := http.NewRequest("POST", srv.URL+"/v1/runs", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("an unknown field was accepted: %d", resp.StatusCode)
	}
}

// An out-of-scope corpus must leave the unauthorised target untouched.
func TestAnOutOfScopeCorpusReachesNothing(t *testing.T) {
	authorised, _ := newTarget(t)
	stranger, strangerHits := newTarget(t)
	srv, _, _ := newServer(t, 0)

	req := startRequest(t, authorised, "escape")
	raw := fmt.Sprintf(`{"corpus_version":"1","samples":[
	  {"id":"elsewhere","method":"GET","url":"%s/api/items?page=1",
	   "headers":{"Accept":["application/json"]}}]}`, stranger.URL)
	c, err := corpus.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Corpus = c

	resp := do(t, srv, "POST", "/v1/runs", testToken, req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("start returned %d", resp.StatusCode)
	}

	waitForDone(t, srv, "escape")
	if got := strangerHits.Load(); got != 0 {
		t.Fatalf("the unauthorised target received %d request(s)", got)
	}
}

// --- Events ----------------------------------------------------------------

// readEvents streams from a sequence number until `done` or the limit.
func readEvents(t *testing.T, srv *httptest.Server, id string, fromSeq int64, limit int) []events.Event {
	t.Helper()
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/v1/runs/%s/events?from_seq=%d", srv.URL, id, fromSeq), nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("events returned %d", resp.StatusCode)
	}

	var out []events.Event
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var e events.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("stream line is not valid JSON: %v\n%s", err, line)
		}
		out = append(out, e)
		if e.Type == events.Done || (limit > 0 && len(out) >= limit) {
			break
		}
	}
	return out
}

func waitForDone(t *testing.T, srv *httptest.Server, id string) []events.Event {
	t.Helper()
	return readEvents(t, srv, id, 0, 0)
}

func TestARunStreamsContiguousEventsAndFinishes(t *testing.T) {
	target, _ := newTarget(t)
	srv, _, _ := newServer(t, 0)

	resp := do(t, srv, "POST", "/v1/runs", testToken, startRequest(t, target, "stream"))
	var started StartRunResponse
	if err := json.NewDecoder(resp.Body).Decode(&started); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if started.PlannedCases == 0 {
		t.Fatal("the plan is empty")
	}

	received := waitForDone(t, srv, "stream")
	if len(received) == 0 {
		t.Fatal("no events were streamed")
	}

	// Sequence numbers must be contiguous from 1, so a gap always means a
	// real loss rather than a numbering artefact.
	var expected int64 = 1
	var done *events.DoneInfo
	seenTypes := map[events.Type]int{}
	for _, e := range received {
		if e.Seq == events.GapSeq {
			t.Fatalf("a gap notice appeared in a run that lost nothing: %+v", e.Warning)
		}
		if e.Seq != expected {
			t.Fatalf("expected seq %d, got %d", expected, e.Seq)
		}
		expected++
		seenTypes[e.Type]++
		if e.Type == events.Done {
			done = e.Done
		}
		if e.SessionID != "stream" {
			t.Errorf("event %d has session_id %q", e.Seq, e.SessionID)
		}
	}

	if seenTypes[events.Started] != 1 {
		t.Errorf("expected exactly one started event, got %d", seenTypes[events.Started])
	}
	if done == nil {
		t.Fatal("the stream never produced a done event")
	}
	if done.Status != store.SessionCompleted {
		t.Errorf("done status = %q", done.Status)
	}
	if done.TotalSeq != int64(len(received)) {
		t.Errorf("done.total_seq = %d but %d events arrived", done.TotalSeq, len(received))
	}
	if done.EventsDropped != 0 {
		t.Errorf("a run that fitted in the buffer reported %d dropped", done.EventsDropped)
	}
	t.Logf("%d events, types %v", len(received), seenTypes)
}

// Resuming from a sequence number must return the rest, in order, with no
// repeats and no holes.
func TestFromSeqResumesWithoutGapsOrRepeats(t *testing.T) {
	target, _ := newTarget(t)
	srv, _, _ := newServer(t, 0)

	resp := do(t, srv, "POST", "/v1/runs", testToken, startRequest(t, target, "resume"))
	resp.Body.Close()

	all := waitForDone(t, srv, "resume")
	if len(all) < 5 {
		t.Fatalf("only %d events; not enough to test a resume", len(all))
	}

	cut := len(all) / 2
	resumeFrom := all[cut-1].Seq
	rest := readEvents(t, srv, "resume", resumeFrom, 0)

	if len(rest) == 0 {
		t.Fatal("the resume returned nothing")
	}
	if rest[0].Seq != resumeFrom+1 {
		t.Fatalf("resume from %d began at %d", resumeFrom, rest[0].Seq)
	}
	for i, e := range rest {
		want := all[cut+i]
		if e.Seq != want.Seq || e.Type != want.Type {
			t.Fatalf("resumed event %d is %d/%s, want %d/%s", i, e.Seq, e.Type, want.Seq, want.Type)
		}
	}
	if last := rest[len(rest)-1]; last.Type != events.Done {
		t.Errorf("the resumed stream did not reach done: %s", last.Type)
	}
	t.Logf("resumed from %d and received %d more, ending at %d",
		resumeFrom, len(rest), rest[len(rest)-1].Seq)
}

// A consumer resuming from a point the buffer has evicted must be told, not
// handed a later event as though it followed.
func TestAResumeIntoAnEvictedRangeIsToldAboutTheGap(t *testing.T) {
	target, _ := newTarget(t)
	// A buffer far too small for the run, so eviction is certain.
	srv, _, _ := newServer(t, 8)

	resp := do(t, srv, "POST", "/v1/runs", testToken, startRequest(t, target, "tiny"))
	resp.Body.Close()

	// Let the run finish so eviction has definitely happened.
	final := waitForDone(t, srv, "tiny")
	if len(final) == 0 {
		t.Fatal("no events")
	}

	// Now ask for everything from the very beginning.
	fromStart := readEvents(t, srv, "tiny", 0, 0)
	if len(fromStart) == 0 {
		t.Fatal("no events on the second read")
	}

	first := fromStart[0]
	if first.Seq != events.GapSeq || first.Type != events.Warning {
		t.Fatalf("a resume into an evicted range began with %d/%s instead of a gap notice",
			first.Seq, first.Type)
	}
	if first.Warning == nil || first.Warning.Code != events.WarnEventsDropped {
		t.Fatalf("the first event is not an events_dropped warning: %+v", first.Warning)
	}
	if first.Warning.EventsDropped <= 0 {
		t.Error("the gap notice does not say how many events were lost")
	}
	if !strings.Contains(first.Warning.Message, "subset") {
		t.Errorf("the notice does not warn that results are partial: %q", first.Warning.Message)
	}
	t.Logf("gap notice: %d events lost — %s",
		first.Warning.EventsDropped, first.Warning.Message)

	// And the run's own done event admits the loss.
	var done *events.DoneInfo
	for _, e := range final {
		if e.Type == events.Done {
			done = e.Done
		}
	}
	if done == nil {
		t.Fatal("no done event")
	}
	if done.EventsDropped == 0 {
		t.Error("done reports no dropped events although the buffer evicted some")
	}
	// The status must not read as a complete result set.
	if done.TotalSeq <= int64(len(fromStart)) {
		t.Errorf("total_seq %d does not exceed the %d events actually deliverable, "+
			"so a consumer could not detect the loss", done.TotalSeq, len(fromStart))
	}
}

func TestStatusEndpointReportsDroppedEvents(t *testing.T) {
	target, _ := newTarget(t)
	srv, _, _ := newServer(t, 8)

	resp := do(t, srv, "POST", "/v1/runs", testToken, startRequest(t, target, "dropstatus"))
	resp.Body.Close()
	waitForDone(t, srv, "dropstatus")

	statusResp := do(t, srv, "GET", "/v1/runs/dropstatus", testToken, nil)
	defer statusResp.Body.Close()

	var status map[string]any
	if err := json.NewDecoder(statusResp.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	dropped, _ := status["events_dropped"].(float64)
	if dropped <= 0 {
		t.Fatalf("status reports %v dropped events after a tiny buffer overflowed", status["events_dropped"])
	}
}

// --- Stop ------------------------------------------------------------------

func TestStopEndsTheRunAndTheStream(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer slow.Close()

	srv, _, _ := newServer(t, 0)

	req := startRequest(t, slow, "stopme")
	mutCfg := mutate.DefaultConfig()
	mutCfg.MutationsPerTarget = 40
	req.MutationConfig = &mutCfg

	resp := do(t, srv, "POST", "/v1/runs", testToken, req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("start returned %d", resp.StatusCode)
	}

	// Give it long enough to be genuinely mid-flight.
	time.Sleep(200 * time.Millisecond)

	stoppedAt := time.Now()
	stopResp := do(t, srv, "DELETE", "/v1/runs/stopme", testToken, nil)
	stopResp.Body.Close()
	if stopResp.StatusCode != http.StatusAccepted {
		t.Fatalf("stop returned %d", stopResp.StatusCode)
	}

	received := waitForDone(t, srv, "stopme")
	elapsed := time.Since(stoppedAt)
	if elapsed > 5*time.Second {
		t.Fatalf("the stream took %v to close after stop", elapsed)
	}

	var done *events.DoneInfo
	for _, e := range received {
		if e.Type == events.Done {
			done = e.Done
		}
	}
	if done == nil {
		t.Fatal("no done event after stop")
	}
	if done.Status == store.SessionCompleted {
		t.Error("a stopped run reported itself completed")
	}
	t.Logf("stopped in %v with status %q", elapsed, done.Status)
}

func TestStopOnAnUnknownRunIs404(t *testing.T) {
	srv, _, _ := newServer(t, 0)
	resp := do(t, srv, "DELETE", "/v1/runs/nope", testToken, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("got %d, want 404", resp.StatusCode)
	}
}

// --- Redaction -------------------------------------------------------------

// Nothing secret may reach the stream. The engine redacts before storing, and
// the same redacted record is what goes on the wire.
func TestTheStreamCarriesNoSecrets(t *testing.T) {
	target, _ := newTarget(t)
	srv, _, _ := newServer(t, 0)

	req := startRequest(t, target, "secrets")
	raw := fmt.Sprintf(`{"corpus_version":"1","samples":[
	  {"id":"withsecrets","method":"POST","url":"%s/api/orders?access_token=tok-abcdefghijklmnop",
	   "headers":{
	     "Content-Type":["application/json"],
	     "Authorization":["Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SUPERSECRETSIGNATURE"],
	     "Cookie":["session=deadbeefdeadbeefdeadbeef"]},
	   "body":"{\"sku\":\"A-1\",\"qty\":null,\"password\":\"hunter2-secret\"}"}]}`, target.URL)
	c, err := corpus.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Corpus = c

	resp := do(t, srv, "POST", "/v1/runs", testToken, req)
	resp.Body.Close()

	received := waitForDone(t, srv, "secrets")
	encoded, err := json.Marshal(received)
	if err != nil {
		t.Fatal(err)
	}
	stream := string(encoded)

	for _, secret := range []string{
		"SUPERSECRETSIGNATURE", "deadbeefdeadbeefdeadbeef",
		"hunter2-secret", "tok-abcdefghijklmnop",
	} {
		if strings.Contains(stream, secret) {
			t.Errorf("the event stream carries the secret %q", secret)
		}
	}

	findings := 0
	for _, e := range received {
		if e.Type == events.Finding {
			findings++
		}
	}
	if findings == 0 {
		t.Fatal("no findings were streamed, so the redaction check proves nothing")
	}
	if !strings.Contains(stream, safety.Placeholder) {
		t.Error("no redaction marker appears in the stream; redaction may not have run")
	}
	t.Logf("%d findings streamed with no secrets", findings)
}

// --- Configuration ---------------------------------------------------------

func TestServerRefusesToStartWithoutAToken(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	_, err := New(Config{EngineVersion: "x", Store: st})
	if err == nil {
		t.Fatal("a control API was built with no token")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("the error does not explain the missing token: %v", err)
	}
}

func TestDuplicateSessionIDIsRejected(t *testing.T) {
	target, _ := newTarget(t)
	srv, _, _ := newServer(t, 0)

	first := do(t, srv, "POST", "/v1/runs", testToken, startRequest(t, target, "dup"))
	first.Body.Close()
	if first.StatusCode != http.StatusAccepted {
		t.Fatalf("first start returned %d", first.StatusCode)
	}
	second := do(t, srv, "POST", "/v1/runs", testToken, startRequest(t, target, "dup"))
	defer second.Body.Close()
	if second.StatusCode != http.StatusConflict {
		t.Fatalf("a duplicate session id returned %d, want 409", second.StatusCode)
	}
}

// A session id becomes a directory name in the store. The store refuses an
// unsafe one itself, but the control API is where one arrives from outside, so
// the refusal must be a plain 400 here rather than a write failure later.
func TestStartRunRefusesUnsafeSessionIDs(t *testing.T) {
	srv, _, _ := newServer(t, 0)
	target, hits := newTarget(t)

	for _, id := range []string{
		"../../escaped", "../escaped", "a/../../escaped", "..", ".",
		"nested/child", "/etc/passwd", ".hidden", "-rf", "",
		"sess ion", "sess\x00ion",
	} {
		req := startRequest(t, target, id)
		resp := do(t, srv, http.MethodPost, "/v1/runs", testToken, req)
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("session id %q: status %d, want 400 (body %v)", id, resp.StatusCode, body)
			continue
		}
		if body["error"] != "invalid_request" {
			t.Errorf("session id %q: error %v, want invalid_request", id, body["error"])
		}
	}

	// A refused run must not have reached the target at all.
	if n := hits.Load(); n != 0 {
		t.Errorf("a refused session id still sent %d request(s) to the target", n)
	}
}

// The reproduce path carries a session id inside the case id, straight off the
// URL. Two things refuse it, and which one does depends on the shape:
//
//   - a case id containing a separator never matches the route's single-segment
//     wildcard, so the mux answers 404 before any handler runs. That includes
//     percent-encoded separators, which are decoded before matching;
//   - one that does reach the handler is validated there and answered 400.
//
// Either way it is refused and nothing is opened, which is what this asserts.
// The 400 half is asserted separately, so a change that started routing
// multi-segment ids would not silently pass on the strength of the 404s.
func TestReproduceRefusesUnsafeCaseIDs(t *testing.T) {
	srv, _, _ := newServer(t, 0)
	target, hits := newTarget(t)
	req := startRequest(t, target, "reproduce-guard")

	withSeparator := []string{
		"../../escaped-000001", "../escaped-000001", "a/../../escaped-000001",
		"/etc/passwd-000001", "nested/child-000001",
		"%2e%2e%2f%2e%2e%2fescaped-000001", "..%2f..%2fescaped-000001",
		"%2fetc%2fpasswd-000001",
	}
	reachTheHandler := []string{
		"..-000001", ".-000001", ".hidden-000001", "-rf-000001",
		"sess ion-000001", "not-a-case-id",
	}

	for _, caseID := range append(append([]string{}, withSeparator...), reachTheHandler...) {
		resp := do(t, srv, http.MethodPost, "/v1/reproduce/"+caseID, testToken, req)
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Errorf("case id %q was not refused: status %d (body %v)",
				caseID, resp.StatusCode, body)
		}
	}

	// The ones the router does hand over must be refused by the validation, with
	// the reason named rather than a bare not-found.
	for _, caseID := range reachTheHandler {
		resp := do(t, srv, http.MethodPost, "/v1/reproduce/"+caseID, testToken, req)
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("case id %q: status %d, want 400 (body %v)", caseID, resp.StatusCode, body)
			continue
		}
		if body["error"] != "invalid_request" {
			t.Errorf("case id %q: error %v, want invalid_request", caseID, body["error"])
		}
	}

	if n := hits.Load(); n != 0 {
		t.Errorf("a refused case id still sent %d request(s) to the target", n)
	}
}

// --- the aggregate endpoint -------------------------------------------------

// It must answer for a run that is no longer in memory, because that is the
// normal case for a report: the run finished, or the engine restarted since.
func TestAggregateIsServedFromTheStoreNotFromMemory(t *testing.T) {
	srv, st, dataDir := newServer(t, 0)
	target, _ := newTarget(t)

	req := startRequest(t, target, "agg-session")
	resp := do(t, srv, http.MethodPost, "/v1/runs", testToken, req)
	resp.Body.Close()
	waitForDone(t, srv, "agg-session")

	// A second server over the same directory has never heard of the run: this is
	// an engine that restarted.
	fresh, err := New(Config{
		Token: testToken, EngineVersion: testEngineVersion,
		Store: st, BufferCapacity: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	restarted := httptest.NewServer(fresh.Handler())
	defer restarted.Close()
	_ = dataDir

	// The run is gone from memory, as the status endpoint confirms.
	status := do(t, restarted, http.MethodGet, "/v1/runs/agg-session", testToken, nil)
	status.Body.Close()
	if status.StatusCode != http.StatusNotFound {
		t.Fatalf("precondition: the restarted server should not know the run: %d", status.StatusCode)
	}

	// The aggregate is still answerable.
	agg := do(t, restarted, http.MethodGet, "/v1/runs/agg-session/aggregate", testToken, nil)
	defer agg.Body.Close()
	if agg.StatusCode != http.StatusOK {
		t.Fatalf("aggregate after a restart returned %d", agg.StatusCode)
	}

	var doc aggregate.Document
	if err := json.NewDecoder(agg.Body).Decode(&doc); err != nil {
		t.Fatalf("decoding the aggregate: %v", err)
	}
	if doc.AggregateVersion != aggregate.Version {
		t.Errorf("AggregateVersion = %q", doc.AggregateVersion)
	}
	if doc.Session.SessionID != "agg-session" {
		t.Errorf("Session.SessionID = %q", doc.Session.SessionID)
	}
	if doc.Note == "" {
		t.Error("the aggregate carries no note about what its results are")
	}
}

// The scope in the aggregate is the one the run enforced, described but not
// over-claimed, and it does not carry the authorised addresses.
func TestAggregateDescribesTheEnforcedScopeWithoutAddresses(t *testing.T) {
	srv, _, _ := newServer(t, 0)
	target, _ := newTarget(t)

	req := startRequest(t, target, "agg-scope")
	resp := do(t, srv, http.MethodPost, "/v1/runs", testToken, req)
	var started StartRunResponse
	if err := json.NewDecoder(resp.Body).Decode(&started); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	waitForDone(t, srv, "agg-scope")

	agg := do(t, srv, http.MethodGet, "/v1/runs/agg-scope/aggregate", testToken, nil)
	raw, err := io.ReadAll(agg.Body)
	agg.Body.Close()
	if err != nil {
		t.Fatal(err)
	}

	var doc aggregate.Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}

	if !doc.Scope.Recorded {
		t.Error("the aggregate does not record the scope")
	}
	if !doc.Scope.Consistent {
		t.Errorf("the scope should be coherent: %s", doc.Scope.InconsistencyReason)
	}
	// The digest the start response gave the caller, and the one in the aggregate,
	// describe the same enforced scope.
	if doc.Scope.Digest != started.ScopeDigest {
		t.Errorf("the aggregate's scope digest %s differs from the start response's %s",
			doc.Scope.Digest, started.ScopeDigest)
	}
	if doc.Scope.RecomputedDigest != doc.Scope.Digest {
		t.Errorf("the stored scope does not hash to its digest: %s vs %s",
			doc.Scope.RecomputedDigest, doc.Scope.Digest)
	}
	if len(doc.Scope.Targets) == 0 {
		t.Error("no targets described")
	}
	if len(doc.Scope.TargetsSummary) == 0 {
		t.Error("no target summary")
	}

	// The authorised address is what the scope test server runs on; it must not
	// travel in something meant to be shared.
	if strings.Contains(string(raw), "127.0.0.1/32") {
		t.Error("the aggregate carries an authorised address range")
	}
	var generic struct {
		Scope struct {
			Targets []map[string]any `json:"targets"`
		} `json:"scope"`
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	for i, tgt := range generic.Scope.Targets {
		if _, ok := tgt["allowed_addresses"]; ok {
			t.Errorf("target %d carries allowed_addresses", i)
		}
	}
}

func TestAggregateRefusesUnknownAndUnsafeIDs(t *testing.T) {
	srv, _, _ := newServer(t, 0)

	unknown := do(t, srv, http.MethodGet, "/v1/runs/never-ran/aggregate", testToken, nil)
	unknown.Body.Close()
	if unknown.StatusCode != http.StatusNotFound {
		t.Errorf("an unknown session returned %d, want 404", unknown.StatusCode)
	}

	// ".." never reaches the handler: the path is normalised before routing, so
	// /v1/runs/../aggregate is not this route at all. Refused, but by the router.
	for _, id := range []string{"..", "."} {
		resp := do(t, srv, http.MethodGet, "/v1/runs/"+id+"/aggregate", testToken, nil)
		resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Errorf("session id %q was not refused: %d", id, resp.StatusCode)
		}
	}

	// These do reach the handler, and must be answered with a named refusal
	// rather than a bare not-found -- otherwise a change that stopped validating
	// would look the same as one that did.
	for _, id := range []string{".hidden", "-rf", "sess ion", "nul%00byte"} {
		resp := do(t, srv, http.MethodGet, "/v1/runs/"+id+"/aggregate", testToken, nil)
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("session id %q returned %d, want 400 (body %v)", id, resp.StatusCode, body)
			continue
		}
		if body["error"] != "invalid_request" {
			t.Errorf("session id %q: error %v, want invalid_request", id, body["error"])
		}
	}
}

// The aggregate is a pure function of what is stored, so two fetches of a
// finished run must be identical bytes.
func TestAggregateIsByteIdenticalAcrossFetches(t *testing.T) {
	srv, _, _ := newServer(t, 0)
	target, _ := newTarget(t)

	req := startRequest(t, target, "agg-determinism")
	resp := do(t, srv, http.MethodPost, "/v1/runs", testToken, req)
	resp.Body.Close()
	waitForDone(t, srv, "agg-determinism")

	fetch := func() string {
		r := do(t, srv, http.MethodGet, "/v1/runs/agg-determinism/aggregate", testToken, nil)
		defer r.Body.Close()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}

	first := fetch()
	for i := 0; i < 5; i++ {
		if again := fetch(); again != first {
			t.Fatalf("fetch %d returned different bytes", i+2)
		}
	}
}

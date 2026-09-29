package runner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"mihakk/internal/corpus"
	"mihakk/internal/events"
	"mihakk/internal/mutate"
	"mihakk/internal/safety"
)

// What became of a run's requests has to be said in the stream and in the
// record, in three distinct words: refused (nothing left), attempted (the
// safety layer let it through -- which a refused connection also is), and
// answered (a response was observed). And in two distinct units: cases, and HTTP
// requests, of which a redirected case makes several.

type recordedEvents struct {
	mu     sync.Mutex
	events []events.Event
}

func (r *recordedEvents) add(e events.Event) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return int64(len(r.events))
}

func (r *recordedEvents) progress(t *testing.T) (first, last *events.ProgressInfo) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.events {
		if r.events[i].Type == events.Progress && r.events[i].Progress != nil {
			if first == nil {
				first = r.events[i].Progress
			}
			last = r.events[i].Progress
		}
	}
	if last == nil {
		t.Fatal("the stream carried no progress event at all")
	}
	return first, last
}

// These accounting tests are about whether requests crossed the safety layer,
// not whether an arbitrary mutated header is syntactically sendable. Three
// query-only samples retain the original baseline size while every generated
// request stays well-formed. The test server's random port changes the corpus
// digest, so a header-bearing fixture otherwise sometimes generates a locally
// refused case before the connection or redirect that the assertion measures.
func accountingCorpus(t *testing.T, srv *httptest.Server) *corpus.Corpus {
	t.Helper()
	raw := fmt.Sprintf(`{"corpus_version": "1", "samples": [
	  {"id": "one", "method": "GET", "url": "%s/api/items?q=one"},
	  {"id": "two", "method": "GET", "url": "%s/api/items?q=two"},
	  {"id": "three", "method": "GET", "url": "%s/api/items?q=three"}
	]}`, srv.URL, srv.URL, srv.URL)
	c, err := corpus.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// runAgainst runs a small plan against srv with the scope's addresses replaced.
func runAgainst(t *testing.T, srv *httptest.Server, allowed string, c *corpus.Corpus,
	maxRedirects int) (*Result, *recordedEvents) {
	t.Helper()
	mutCfg := mutate.DefaultConfig()
	mutCfg.MutationsPerTarget = 2
	h := newHarness(t, srv, generousLimits(), mutCfg, "0badcafe")
	if c == nil {
		c = accountingCorpus(t, srv)
	}
	plan, err := mutate.NewPlan(c, mutCfg, testEngineVersion, h.seed)
	if err != nil {
		t.Fatal(err)
	}
	h.corpus, h.plan = c, plan

	scope := scopeFor(t, srv)
	scope.MaxRedirects = maxRedirects
	for i := range scope.Targets {
		scope.Targets[i].AllowedAddresses = []string{allowed}
	}
	scope.Normalize()
	h.cfg = configFor(t, scope, generousLimits())
	client, err := safety.NewClient(safety.ClientConfig{
		Scope: &h.cfg.Scope, Governor: h.governor,
		Authorization: h.cfg.Authorization, Redactor: h.cfg.NewRedactor(),
	})
	if err != nil {
		t.Fatal(err)
	}
	h.client = client

	recorded := &recordedEvents{}
	r := h.runner(t, "accounting", func(o *Options) { o.OnEvent = recorded.add })
	result, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return result, recorded
}

// Every HTTP request charged to the budget ends one of three ways, so the three
// add up to the budget spent -- in the stream and in the record alike.
func assertHTTPAddsUp(t *testing.T, result *Result, last *events.ProgressInfo) {
	t.Helper()
	a := result.Accounting
	if got := a.HTTPAnswered + a.HTTPUnanswered + a.HTTPRefused; got != last.RequestsUsed {
		t.Errorf("answered %d + unanswered %d + refused %d = %d; the budget spent is %d",
			a.HTTPAnswered, a.HTTPUnanswered, a.HTTPRefused, got, last.RequestsUsed)
	}
	if last.HTTPAnswered != a.HTTPAnswered || last.HTTPUnanswered != a.HTTPUnanswered ||
		last.HTTPRefused != a.HTTPRefused {
		t.Errorf("the last progress event and the record disagree: %+v vs %+v", last, a)
	}
	if result.Session.Accounting == nil || *result.Session.Accounting != a {
		t.Errorf("the session record does not carry the accounting: %+v", result.Session.Accounting)
	}
	if last.Attempted != a.CasesAttempted || last.Answered != a.CasesAnswered {
		t.Errorf("case accounting in progress and the record disagree: %+v vs %+v", last, a)
	}
}

func TestARunWhoseEveryRequestIsRefusedSaysSoInTheStream(t *testing.T) {
	tb := newFakeTestbed(t)
	defer tb.Close()
	// The scope authorises 127.0.0.2; the server is on 127.0.0.1.
	result, recorded := runAgainst(t, tb.Server, "127.0.0.2/32", nil, 2)

	if got := tb.Requests.Load(); got != 0 {
		t.Fatalf("the target received %d request(s); none of its addresses is authorised", got)
	}
	first, last := recorded.progress(t)
	baselineWanted := 3 * BaselineRepeats // corpusFor has three samples

	// The baseline is reported on its own, before any case.
	if first.Executed+first.Refused != 0 || first.BaselineRefused != baselineWanted {
		t.Errorf("the first progress event is %+v; want the baseline alone, before any case", first)
	}
	if last.Executed != 0 || last.Refused != last.Planned || last.Planned == 0 ||
		last.Attempted != 0 || last.Answered != 0 || last.BaselineAttempted != 0 ||
		last.BaselineRefused != baselineWanted {
		t.Errorf("last progress %+v; want nothing attempted and everything refused", last)
	}
	if last.HTTPAnswered != 0 || last.HTTPUnanswered != 0 || last.HTTPRefused != last.RequestsUsed {
		t.Errorf("HTTP: %d answered, %d unanswered, %d refused of %d charged; want all refused",
			last.HTTPAnswered, last.HTTPUnanswered, last.HTTPRefused, last.RequestsUsed)
	}
	assertHTTPAddsUp(t, result, last)
}

// A target that refuses the connection: the safety layer let every request
// through, and none was answered. Attempted, never delivered, and never
// reported as "sent".
func TestATargetThatRefusesTheConnectionIsAttemptedNotAnswered(t *testing.T) {
	// A port that was listening a moment ago and is not now: connect is refused.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	closed := &httptest.Server{URL: "http://127.0.0.1:" + strconv.Itoa(port)}

	result, recorded := runAgainst(t, closed, "127.0.0.1/32", nil, 2)
	_, last := recorded.progress(t)

	if last.Executed == 0 || last.Executed != last.Planned || last.Attempted != last.Planned ||
		last.Refused != 0 {
		t.Errorf("executed %d of %d, refused %d; want every case attempted and none refused",
			last.Executed, last.Planned, last.Refused)
	}
	if last.Answered != 0 || last.BaselineAnswered != 0 || last.HTTPAnswered != 0 {
		t.Errorf("answered: cases %d, baseline %d, http %d; nothing can have been answered",
			last.Answered, last.BaselineAnswered, last.HTTPAnswered)
	}
	if last.HTTPUnanswered != last.RequestsUsed || last.HTTPUnanswered == 0 {
		t.Errorf("HTTP unanswered %d of %d charged; want every one", last.HTTPUnanswered, last.RequestsUsed)
	}
	assertHTTPAddsUp(t, result, last)
}

// A redirected case is one case and several HTTP requests. The budget, the
// target and the HTTP counts see the hops; the case counts do not, and must not
// be presented as if they did.
func TestARedirectChainIsOneCaseAndSeveralRequests(t *testing.T) {
	var hits atomic.Int64
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if r.URL.Path == "/api/hop" && n > 0 && n < 50 {
			http.Redirect(w, r, fmt.Sprintf("/api/hop?n=%d", n-1), http.StatusFound)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}))
	defer srv.Close()

	// Mutate only the query. A mutated Accept header can itself be refused
	// before dispatch, which tests header validity rather than redirect counts.
	c, err := corpus.Parse([]byte(fmt.Sprintf(`{"corpus_version": "1", "samples": [
	  {"id": "hop", "method": "GET", "url": "%s/api/hop?n=3"}
	]}`, srv.URL)))
	if err != nil {
		t.Fatal(err)
	}
	result, recorded := runAgainst(t, srv, "127.0.0.1/32", c, 3)
	_, last := recorded.progress(t)

	if got, answered := hits.Load(), last.HTTPAnswered; got != answered {
		t.Errorf("the target saw %d HTTP request(s); http_answered says %d", got, answered)
	}
	cases := int64(last.Executed + last.BaselineAttempted)
	if last.HTTPAnswered <= cases {
		t.Errorf("http_answered %d is not above the %d case/baseline attempts; the hops went uncounted",
			last.HTTPAnswered, cases)
	}
	// The unmutated baseline follows three hops: four requests each.
	if last.BaselineAttempted != BaselineRepeats || last.BaselineAnswered != BaselineRepeats {
		t.Errorf("baseline attempted %d answered %d; want %d each",
			last.BaselineAttempted, last.BaselineAnswered, BaselineRepeats)
	}
	if last.Attempted != last.Planned {
		t.Errorf("attempted %d of %d redirected cases", last.Attempted, last.Planned)
	}
	assertHTTPAddsUp(t, result, last)
}

// A case can be both attempted and locally refused: an earlier redirect hop got
// a response, then the next hop was outside scope. The terminal case outcome
// must not erase the HTTP request that really happened.
func TestARedirectRefusedAfterAnAnsweredHopStillCountsTheCaseAttempt(t *testing.T) {
	var sourceHits, outsideHits atomic.Int64
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outsideHits.Add(1)
		writeJSON(w, 200, map[string]any{"outside": true})
	}))
	defer outside.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceHits.Add(1)
		http.Redirect(w, r, outside.URL+"/api/outside", http.StatusFound)
	}))
	defer source.Close()

	// The harmless query keeps cases in the plan without mutating a header that
	// could be rejected locally before the answered first hop.
	c, err := corpus.Parse([]byte(fmt.Sprintf(`{"corpus_version": "1", "samples": [
	  {"id": "hop", "method": "GET", "url": "%s/api/start?q=ok"}
	]}`, source.URL)))
	if err != nil {
		t.Fatal(err)
	}
	result, recorded := runAgainst(t, source, "127.0.0.1/32", c, 3)
	_, last := recorded.progress(t)

	if outsideHits.Load() != 0 {
		t.Fatalf("the out-of-scope redirect received %d request(s)", outsideHits.Load())
	}
	if last.Attempted != last.Planned || last.Refused != last.Planned || last.Executed != 0 {
		t.Errorf("cases: attempted %d, refused %d, executed %d of %d; want attempted and refused",
			last.Attempted, last.Refused, last.Executed, last.Planned)
	}
	if last.BaselineAttempted != BaselineRepeats || last.BaselineRefused != BaselineRepeats {
		t.Errorf("baseline attempted %d refused %d; want %d each",
			last.BaselineAttempted, last.BaselineRefused, BaselineRepeats)
	}
	if got := sourceHits.Load(); got == 0 || last.HTTPAnswered != got ||
		last.HTTPUnanswered != 0 || last.HTTPRefused != 0 {
		t.Errorf("source got %d; HTTP answered/unanswered/refused = %d/%d/%d",
			got, last.HTTPAnswered, last.HTTPUnanswered, last.HTTPRefused)
	}
	assertHTTPAddsUp(t, result, last)
}

// The control: an authorised run against a server that answers everything.
func TestAnAuthorisedRunIsAttemptedAndAnsweredThroughout(t *testing.T) {
	tb := newFakeTestbed(t)
	defer tb.Close()
	result, recorded := runAgainst(t, tb.Server, "127.0.0.1/32", nil, 2)
	_, last := recorded.progress(t)

	if last.Refused != 0 || last.BaselineRefused != 0 || last.HTTPRefused != 0 {
		t.Errorf("an authorised run reported refusals: %+v", last)
	}
	if last.Executed != last.Planned || last.Attempted != last.Planned ||
		last.BaselineAttempted != 3*BaselineRepeats {
		t.Errorf("attempted %d of %d cases, %d baseline",
			last.Attempted, last.Planned, last.BaselineAttempted)
	}
	// What the target saw is what the HTTP count says was answered. Some cases
	// can time out against the fake's slow path, so answered is compared with
	// the target rather than with the plan.
	if got := tb.Requests.Load(); got != last.HTTPAnswered+last.HTTPUnanswered {
		t.Errorf("the target saw %d request(s); http counts say %d answered + %d unanswered",
			got, last.HTTPAnswered, last.HTTPUnanswered)
	}
	assertHTTPAddsUp(t, result, last)
}

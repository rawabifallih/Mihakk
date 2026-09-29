package aggregate

// The shared golden document.
//
// The aggregate is produced in Go and consumed in Python, and the two only meet
// over a socket. A field renamed on one side, or an encoding that changes shape,
// would pass every unit test on both sides and fail only in a live run -- which is
// slow, needs Docker, and is not where a rename should be caught.
//
// So one document is committed, this test asserts Go still produces it byte for
// byte, and a Python test asserts Python still understands it. Editing either side
// without the other fails one of the two immediately.
//
// Regenerate deliberately, never reflexively: a diff here is either a contract
// change that the Python side needs to hear about, or a bug.
//
//	scripts/go.sh test ./internal/aggregate/ -run TestGolden -update

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mihakk/internal/detect"
	"mihakk/internal/safety"
	"mihakk/internal/store"
)

var update = flag.Bool("update", false, "rewrite the golden aggregate document")

// goldenPath is outside the Go tree on purpose: it is a shared contract fixture,
// not a Go test detail, and the Python tests read the same file.
func goldenPath() string {
	return filepath.Join("..", "..", "..", "schemas", "examples", "aggregate.golden.json")
}

// goldenFixture is fixed in every respect that could vary: times, seeds, digests,
// and the order cases are passed in.
func goldenFixture() (*store.Session, []*store.Case) {
	scope := &safety.Scope{
		Targets: []safety.Target{{
			Scheme: "http", Host: "testbed", Port: 8000,
			PathPrefixes:     []string{"/api"},
			Methods:          []string{"GET", "POST"},
			AllowedAddresses: []string{"172.19.0.2/32"},
		}},
		MaxRedirects: 2,
	}
	scope.Normalize()

	started := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ended := started.Add(90 * time.Second)

	sess := &store.Session{
		SessionID: "golden", EngineVersion: "0.6.0-golden",
		StartedAt: started, EndedAt: &ended, Status: "completed",
		Operator: "golden-operator",
		Scope:    scope, ScopeDigest: scope.Digest(),
		CorpusDigest: "sha256:" + str64('b'),
		ConfigDigest: "sha256:" + str64('c'),
		MasterSeed:   "6d6968616b6b",
		Targets:      []string{"http://testbed:8000"},
		PlannedCases: 136, ExecutedCases: 134, SavedCases: 5, RefusedCases: 2,
		Accounting: &store.Accounting{
			CasesAttempted: 134, CasesAnswered: 130,
			BaselineAttempted: 9, BaselineRefused: 3, BaselineAnswered: 9,
			HTTPAnswered: 141, HTTPUnanswered: 4, HTTPRefused: 3,
		},
	}

	mk := func(index int, path string, status *int, at time.Time, target string,
		types ...detect.IndicatorType) *store.Case {
		inds := make([]detect.Indicator, 0, len(types))
		for _, ty := range types {
			inds = append(inds, detect.Indicator{
				Type:   ty,
				Reason: "the engine observed " + string(ty) + " on this request",
			})
		}
		bytesRead := 40
		latency := 12.5
		return &store.Case{
			CaseID: store.CaseID("golden", index), SessionID: "golden",
			ObservedAt: at,
			Reproduction: store.Reproduction{
				EngineVersion: "0.6.0-golden", MasterSeed: "6d6968616b6b",
				CaseIndex: index, CorpusDigest: "sha256:" + str64('b'),
				ConfigDigest: "sha256:" + str64('c'), Target: target,
			},
			RequestSummary: store.RequestSummary{
				Method: "GET", URL: "http://testbed:8000" + path + "?page=%00",
				BodyPreview: "", BodyBytes: 0, Redacted: true,
			},
			ResponseSummary: store.ResponseSummary{
				StatusCode: status, LatencyMS: &latency, BodyBytes: &bytesRead,
			},
			Indicators: inds,
			Status:     store.StatusNeedsVerification,
		}
	}

	five := 500
	ok := 200
	base := started.Add(time.Second)

	// Real targets carry the mutator that produced them. Two cases below differ
	// only by mutator and must land in one group; the fixture would not cover the
	// collapse at all if every target were the same string.
	cases := []*store.Case{
		mk(3, "/api/items", &five, base, "items query/page (type-confusion)",
			detect.HTTP5xx, detect.AppErrorPattern),
		mk(7, "/api/items", &five, base.Add(time.Second), "items query/page (null-byte)",
			detect.HTTP5xx),
		mk(11, "/api/items", &ok, base.Add(2*time.Second), "items query/page (truncate)",
			detect.LatencyAnomaly),
		mk(19, "/api/items", &ok, base.Add(3*time.Second), "items query/limit (oversize)",
			detect.LatencyAnomaly),
		mk(23, "/api/orders", &ok, base.Add(4*time.Second), "orders body/qty (boundary-int)",
			detect.LatencyAnomaly),
	}
	return sess, cases
}

func TestGoldenAggregateIsUnchanged(t *testing.T) {
	sess, cases := goldenFixture()
	doc, err := Build(sess, cases)
	if err != nil {
		t.Fatal(err)
	}
	produced, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	produced = append(produced, '\n')

	path := goldenPath()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, produced, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("rewrote %s (%d bytes)", path, len(produced))
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the golden document: %v\nrun with -update to create it", err)
	}
	if string(produced) != string(want) {
		t.Errorf("the aggregate no longer matches the committed golden document.\n"+
			"If this is a deliberate contract change, the Python side must be updated "+
			"too, then regenerate with:\n"+
			"  scripts/go.sh test ./internal/aggregate/ -run TestGolden -update\n"+
			"produced %d bytes, golden %d bytes", len(produced), len(want))
	}
}

// The fixture must exercise the parts of the contract worth guarding: several
// groups, a case carrying two indicators, a withheld address, and a status code in
// one signature but not another.
func TestGoldenFixtureCoversTheContract(t *testing.T) {
	sess, cases := goldenFixture()
	doc, err := Build(sess, cases)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Groups) < 3 {
		t.Errorf("the golden fixture makes %d groups; too few to guard the shape",
			len(doc.Groups))
	}
	if doc.Totals.IndicatorInstances <= doc.Totals.Cases {
		t.Error("the fixture should include a case carrying more than one indicator")
	}
	if !doc.Scope.Recorded || !doc.Scope.Consistent {
		t.Error("the fixture's scope should be recorded and coherent")
	}
	var withStatus, withoutStatus int
	for _, g := range doc.Groups {
		if g.Signature.StatusCode != nil {
			withStatus++
		} else {
			withoutStatus++
		}
	}
	if withStatus == 0 || withoutStatus == 0 {
		t.Errorf("the fixture should cover signatures with and without a status code "+
			"(%d with, %d without)", withStatus, withoutStatus)
	}
	// The collapse the live run showed was missing: several mutators, one group.
	collapsed := false
	for _, g := range doc.Groups {
		if len(g.Mutators) > 1 {
			collapsed = true
		}
	}
	if !collapsed {
		t.Error("no group in the fixture collapses more than one mutator, so the " +
			"golden document does not guard the grouping that matters")
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if contains(string(raw), "172.19.0.2") {
		t.Error("the golden document carries an authorised address")
	}
}

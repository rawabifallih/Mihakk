package aggregate

import (
	"encoding/json"
	"testing"
	"time"

	"mihakk/internal/detect"
	"mihakk/internal/safety"
	"mihakk/internal/store"
)

func intp(i int) *int { return &i }

// caseWith builds a stored case. The URL's query differs per index on purpose:
// that is what makes the raw URL useless as a grouping key.
func caseWith(index int, path string, status *int, types ...detect.IndicatorType) *store.Case {
	inds := make([]detect.Indicator, 0, len(types))
	for _, ty := range types {
		inds = append(inds, detect.Indicator{
			Type:   ty,
			Reason: string(ty) + " was observed",
		})
	}
	return &store.Case{
		CaseID:     store.CaseID("s", index),
		SessionID:  "s",
		ObservedAt: time.Unix(int64(1700000000+index), 0).UTC(),
		Reproduction: store.Reproduction{
			EngineVersion: "test", MasterSeed: "ab", CaseIndex: index,
			CorpusDigest: "sha256:" + str64('a'), ConfigDigest: "sha256:" + str64('b'),
			Target: "items.query.page",
		},
		RequestSummary: store.RequestSummary{
			Method: "GET", URL: "http://testbed:8000" + path + "?page=" + string(rune('A'+index%26)),
			Redacted: true,
		},
		ResponseSummary: store.ResponseSummary{StatusCode: status},
		Indicators:      inds,
		Status:          store.StatusNeedsVerification,
	}
}

func str64(c rune) string {
	out := make([]rune, 64)
	for i := range out {
		out[i] = c
	}
	return string(out)
}

func scopeFixture() *safety.Scope {
	s := &safety.Scope{
		Targets: []safety.Target{{
			Scheme: "http", Host: "testbed", Port: 8000,
			PathPrefixes:     []string{"/api"},
			Methods:          []string{"GET", "POST"},
			AllowedAddresses: []string{"172.19.0.2/32"},
		}},
		MaxRedirects: 2,
	}
	s.Normalize()
	return s
}

func sessionFixture(saved int) *store.Session {
	scope := scopeFixture()
	return &store.Session{
		SessionID: "s", EngineVersion: "test",
		StartedAt: time.Unix(1700000000, 0).UTC(),
		Status:    "completed", Operator: "tester",
		Scope: scope, ScopeDigest: scope.Digest(),
		CorpusDigest: "sha256:" + str64('a'), ConfigDigest: "sha256:" + str64('b'),
		MasterSeed:   "ab",
		Targets:      []string{"http://testbed:8000"},
		PlannedCases: 100, ExecutedCases: 98, SavedCases: saved,
	}
}

// --- conservation: the property that keeps grouping from becoming hiding ------

func TestEveryIndicatorInstanceIsAccountedFor(t *testing.T) {
	cases := []*store.Case{
		caseWith(1, "/api/items", intp(500), detect.HTTP5xx, detect.AppErrorPattern),
		caseWith(2, "/api/items", intp(500), detect.HTTP5xx),
		caseWith(3, "/api/items", intp(200), detect.LatencyAnomaly),
		caseWith(4, "/api/items", intp(200), detect.LatencyAnomaly),
		caseWith(5, "/api/orders", intp(503), detect.HTTP5xx),
	}
	doc, err := Build(sessionFixture(len(cases)), cases)
	if err != nil {
		t.Fatal(err)
	}

	sum := 0
	seen := map[string]bool{}
	for _, g := range doc.Groups {
		sum += g.Occurrences
		if g.Occurrences != len(g.CaseIDs) && g.Occurrences < len(g.CaseIDs) {
			t.Errorf("group %s claims %d occurrences but lists %d case ids",
				g.GroupID, g.Occurrences, len(g.CaseIDs))
		}
		for _, id := range g.CaseIDs {
			seen[id] = true
		}
	}

	wantInstances := 6 // case 1 carries two indicators
	if doc.Totals.IndicatorInstances != wantInstances {
		t.Errorf("IndicatorInstances = %d, want %d", doc.Totals.IndicatorInstances, wantInstances)
	}
	if sum != doc.Totals.IndicatorInstances {
		t.Errorf("occurrences sum to %d, totals declare %d", sum, doc.Totals.IndicatorInstances)
	}
	if len(seen) != len(cases) {
		t.Errorf("groups cover %d case(s), the session stored %d", len(seen), len(cases))
	}
	if doc.Totals.Cases != len(cases) {
		t.Errorf("Totals.Cases = %d, want %d", doc.Totals.Cases, len(cases))
	}
	if doc.Totals.Groups != len(doc.Groups) {
		t.Errorf("Totals.Groups = %d but there are %d groups", doc.Totals.Groups, len(doc.Groups))
	}
}

// The case the whole exercise is for: many mutations of one endpoint collapsing
// into one row that still accounts for all of them.
func TestManyMutationsOfOneEndpointCollapseWithoutLoss(t *testing.T) {
	var cases []*store.Case
	for i := 1; i <= 40; i++ {
		cases = append(cases, caseWith(i, "/api/items", intp(200), detect.LatencyAnomaly))
	}
	doc, err := Build(sessionFixture(len(cases)), cases)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Groups) != 1 {
		t.Fatalf("40 mutations of one endpoint made %d groups, want 1", len(doc.Groups))
	}
	g := doc.Groups[0]
	if g.Occurrences != 40 {
		t.Errorf("Occurrences = %d, want 40", g.Occurrences)
	}
	if len(g.CaseIDs) != 40 {
		t.Errorf("the group lists %d case ids, want all 40 -- a count without the ids is hiding",
			len(g.CaseIDs))
	}
	if g.Representative.CaseIndex != 1 {
		t.Errorf("Representative.CaseIndex = %d, want the lowest (1)", g.Representative.CaseIndex)
	}
}

func TestDifferentStatusCodesDoNotMerge(t *testing.T) {
	cases := []*store.Case{
		caseWith(1, "/api/items", intp(500), detect.HTTP5xx),
		caseWith(2, "/api/items", intp(503), detect.HTTP5xx),
	}
	doc, err := Build(sessionFixture(2), cases)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Groups) != 2 {
		t.Errorf("a 500 and a 503 merged into %d group(s); they are different failures", len(doc.Groups))
	}
}

func TestDifferentPathsDoNotMerge(t *testing.T) {
	cases := []*store.Case{
		caseWith(1, "/api/items", intp(500), detect.HTTP5xx),
		caseWith(2, "/api/orders", intp(500), detect.HTTP5xx),
	}
	doc, err := Build(sessionFixture(2), cases)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Groups) != 2 {
		t.Errorf("two endpoints merged into %d group(s)", len(doc.Groups))
	}
}

// --- determinism -------------------------------------------------------------

func TestTheDocumentIsByteIdenticalAcrossBuilds(t *testing.T) {
	var cases []*store.Case
	for i := 1; i <= 25; i++ {
		kinds := []detect.IndicatorType{detect.LatencyAnomaly}
		if i%3 == 0 {
			kinds = append(kinds, detect.HTTP5xx)
		}
		if i%5 == 0 {
			kinds = append(kinds, detect.AppErrorPattern)
		}
		path := "/api/items"
		if i%2 == 0 {
			path = "/api/orders"
		}
		cases = append(cases, caseWith(i, path, intp(500), kinds...))
	}

	first, err := Build(sessionFixture(len(cases)), cases)
	if err != nil {
		t.Fatal(err)
	}
	a, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}

	// Rebuilt several times: map iteration order varies between runs, so a single
	// comparison could pass by luck.
	for attempt := 0; attempt < 8; attempt++ {
		again, err := Build(sessionFixture(len(cases)), cases)
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(again)
		if err != nil {
			t.Fatal(err)
		}
		if string(a) != string(b) {
			t.Fatalf("attempt %d produced different bytes", attempt)
		}
	}

	if len(first.Groups) < 2 {
		t.Fatal("the fixture should make several groups, or determinism proves little")
	}
	for i := 1; i < len(first.Groups); i++ {
		if first.Groups[i-1].GroupID >= first.Groups[i].GroupID {
			t.Error("groups are not in a deterministic order")
		}
	}
}

func TestNoTimestampOfItsOwn(t *testing.T) {
	doc, err := Build(sessionFixture(0), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"generated_at", "created_at", "exported_at", "now"} {
		if _, ok := generic[key]; ok {
			t.Errorf("the document carries %q, so two exports can never be compared directly", key)
		}
	}
}

// --- the scope: two separate claims ------------------------------------------

func TestAConsistentScopeIsDescribedAndAllowedAddressesAreWithheld(t *testing.T) {
	doc, err := Build(sessionFixture(0), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := doc.Scope
	if !s.Recorded {
		t.Error("Recorded should be true when the session stored a scope")
	}
	if !s.Consistent {
		t.Errorf("Consistent should be true when the digests agree: %s", s.InconsistencyReason)
	}
	if s.RecomputedDigest != s.Digest {
		t.Errorf("recomputed %s, stored %s", s.RecomputedDigest, s.Digest)
	}
	if len(s.Targets) != 1 || s.Targets[0].Host != "testbed" {
		t.Fatalf("targets not described: %+v", s.Targets)
	}
	if len(s.TargetsSummary) != 1 {
		t.Errorf("TargetsSummary = %v", s.TargetsSummary)
	}

	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	// The address VALUE must not appear anywhere. The field NAME does appear, in
	// the withheld list -- saying what was left out is the point, so a test that
	// forbade the string outright would contradict the requirement it is checking.
	if contains(string(raw), "172.19.0.2") {
		t.Error("the shareable document contains an authorised address")
	}
	if !contains(string(raw), WithheldAllowedAddresses) {
		t.Error("the document should name the field it withheld")
	}

	// Structurally: no target object carries the field.
	var generic struct {
		Scope struct {
			Targets  []map[string]any `json:"targets"`
			Withheld []string         `json:"withheld"`
		} `json:"scope"`
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	if len(generic.Scope.Targets) == 0 {
		t.Fatal("no targets in the encoded document")
	}
	for i, target := range generic.Scope.Targets {
		if _, ok := target["allowed_addresses"]; ok {
			t.Errorf("target %d carries allowed_addresses", i)
		}
	}
	if len(generic.Scope.Withheld) != 1 || generic.Scope.Withheld[0] != WithheldAllowedAddresses {
		t.Errorf("Withheld = %v", generic.Scope.Withheld)
	}
}

// A scope that does not hash to its stored digest must not be presented as
// coherent, and the reason must be stated rather than implied by a flag.
func TestAScopeThatDoesNotMatchItsDigestIsNotPresentedAsConsistent(t *testing.T) {
	sess := sessionFixture(0)
	sess.ScopeDigest = "sha256:" + str64('9') // disagrees with the stored scope

	doc, err := Build(sess, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := doc.Scope
	if !s.Recorded {
		t.Error("the scope is still recorded; only its coherence is in doubt")
	}
	if s.Consistent {
		t.Fatal("a scope that does not hash to its digest was reported as consistent")
	}
	if s.InconsistencyReason == "" {
		t.Error("no reason was given for the inconsistency")
	}
	for _, want := range []string{"disagree", s.RecomputedDigest, sess.ScopeDigest} {
		if !contains(s.InconsistencyReason, want) {
			t.Errorf("the reason should mention %q: %s", want, s.InconsistencyReason)
		}
	}
}

func TestAMissingDigestIsAlsoNotConsistent(t *testing.T) {
	sess := sessionFixture(0)
	sess.ScopeDigest = ""
	doc, err := Build(sess, nil)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Scope.Consistent {
		t.Error("a scope with no digest to check against was reported as consistent")
	}
	if doc.Scope.InconsistencyReason == "" {
		t.Error("no reason was given")
	}
}

// A session written before the engine recorded the scope.
func TestAnUnrecordedScopeIsOnlyATargetsSummary(t *testing.T) {
	sess := sessionFixture(0)
	sess.Scope = nil

	doc, err := Build(sess, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := doc.Scope
	if s.Recorded {
		t.Error("Recorded should be false without a stored scope")
	}
	if s.Consistent {
		t.Error("Consistent must not be true without a stored scope")
	}
	if len(s.Targets) != 0 {
		t.Errorf("no structural targets should be claimed: %+v", s.Targets)
	}
	if len(s.TargetsSummary) != 1 {
		t.Errorf("the target authorities should still be available: %v", s.TargetsSummary)
	}
	if !contains(s.InconsistencyReason, "summary of targets") {
		t.Errorf("the reason should say this is a targets summary, not the full scope: %s",
			s.InconsistencyReason)
	}
}

// --- the engine's half of completeness ---------------------------------------

func TestTheCaseLogIsComparedAgainstTheRecordsOwnCount(t *testing.T) {
	cases := []*store.Case{caseWith(1, "/api/items", intp(500), detect.HTTP5xx)}

	ok, err := Build(sessionFixture(1), cases)
	if err != nil {
		t.Fatal(err)
	}
	if !ok.Completeness.Consistent {
		t.Errorf("one saved case and one stored case should agree: %s", ok.Completeness.Reason)
	}

	// The record claims more than the log holds.
	mismatch, err := Build(sessionFixture(5), cases)
	if err != nil {
		t.Fatal(err)
	}
	if mismatch.Completeness.Consistent {
		t.Error("a record claiming 5 saved cases over a log of 1 was reported as consistent")
	}
	if mismatch.Completeness.Reason == "" {
		t.Error("no reason given for the mismatch")
	}
	if mismatch.Completeness.CasesInStore != 1 || mismatch.Completeness.SavedCasesStated != 5 {
		t.Errorf("both numbers should be shown: %+v", mismatch.Completeness)
	}
}

func TestTheEnginesIncompleteReasonTravels(t *testing.T) {
	sess := sessionFixture(0)
	sess.UnsavedCases = 3
	sess.AuditFailures = 1
	sess.IncompleteReason = "three indicators could not be written down"

	doc, err := Build(sess, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := doc.Completeness
	if c.UnsavedCases != 3 || c.AuditFailures != 1 {
		t.Errorf("counts lost: %+v", c)
	}
	if c.IncompleteReason != sess.IncompleteReason {
		t.Errorf("IncompleteReason = %q", c.IncompleteReason)
	}
}

// --- no judgement here -------------------------------------------------------

func TestTheDocumentAssignsNoConfidenceAndClaimsNothing(t *testing.T) {
	cases := []*store.Case{caseWith(1, "/api/items", intp(500), detect.HTTP5xx)}
	doc, err := Build(sessionFixture(1), cases)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"confidence", "priority", "severity", "vulnerability", "exploit"} {
		if contains(string(raw), forbidden) {
			t.Errorf("the engine's aggregation contains %q; judging is the analysis phase's job",
				forbidden)
		}
	}
	if doc.Note != TheNote {
		t.Errorf("the note is missing: %q", doc.Note)
	}
}

func TestAnEmptySessionIsStillAValidDocument(t *testing.T) {
	doc, err := Build(sessionFixture(0), nil)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Totals.Cases != 0 || doc.Totals.Groups != 0 || doc.Totals.IndicatorInstances != 0 {
		t.Errorf("totals should all be zero: %+v", doc.Totals)
	}
	if doc.Groups == nil {
		t.Log("groups is null rather than an empty list; acceptable, but the schema must allow it")
	}
	if _, err := Build(nil, nil); err == nil {
		t.Error("Build(nil) should refuse rather than invent a document")
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		(func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		})()
}

// The failure a fixture hid: real cases record which mutator produced them, and
// grouping on the whole target string put every mutator in its own group. The
// live run aggregated 16 indicators into 16 groups while the fixtures here
// collapsed perfectly, because the fixtures used one mutator.
func TestManyMutatorsOnOneFieldStillCollapse(t *testing.T) {
	mutators := []string{
		"boundary-int", "type-confusion", "truncate", "encoding-corrupt",
		"separator", "oversize", "null-byte", "unicode-direction",
		"negative-zero", "hex-literal", "whitespace", "empty",
	}

	var cases []*store.Case
	for i, mutator := range mutators {
		c := caseWith(i+1, "/api/items", intp(200), detect.LatencyAnomaly)
		c.Reproduction.Target = "items query/page (" + mutator + ")"
		cases = append(cases, c)
	}

	doc, err := Build(sessionFixture(len(cases)), cases)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Groups) != 1 {
		t.Fatalf("%d mutators on one field made %d groups, want 1 -- the mutator is "+
			"not part of what makes two observations the same kind",
			len(mutators), len(doc.Groups))
	}

	g := doc.Groups[0]
	if g.Occurrences != len(mutators) {
		t.Errorf("Occurrences = %d, want %d", g.Occurrences, len(mutators))
	}
	if g.Signature.Target != "items query/page" {
		t.Errorf("the signature kept the mutator: %q", g.Signature.Target)
	}
	if len(g.Mutators) != len(mutators) {
		t.Errorf("the group lists %d mutators, want %d -- what grouping discards "+
			"should still be visible", len(g.Mutators), len(mutators))
	}
	for i := 1; i < len(g.Mutators); i++ {
		if g.Mutators[i-1] >= g.Mutators[i] {
			t.Error("the mutator list is not sorted, so the document is not deterministic")
		}
	}
}

// Different fields must still separate, or the fix would have gone too far.
func TestDifferentFieldsStillSeparate(t *testing.T) {
	a := caseWith(1, "/api/items", intp(200), detect.LatencyAnomaly)
	a.Reproduction.Target = "items query/page (truncate)"
	b := caseWith(2, "/api/items", intp(200), detect.LatencyAnomaly)
	b.Reproduction.Target = "items query/limit (truncate)"

	doc, err := Build(sessionFixture(2), []*store.Case{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Groups) != 2 {
		t.Errorf("two different fields merged into %d group(s)", len(doc.Groups))
	}
}

func TestSplitTargetHandlesOddShapes(t *testing.T) {
	for _, tc := range []struct{ in, field, mutator string }{
		{"items query/page (truncate)", "items query/page", "truncate"},
		{"items body/qty (type-confusion)", "items body/qty", "type-confusion"},
		{"no parenthesis here", "no parenthesis here", ""},
		{"trailing paren)", "trailing paren)", ""},
		{"", "", ""},
		{"a (b) (c)", "a (b)", "c"},
	} {
		field, mutator := splitTarget(tc.in)
		if field != tc.field || mutator != tc.mutator {
			t.Errorf("splitTarget(%q) = (%q, %q), want (%q, %q)",
				tc.in, field, mutator, tc.field, tc.mutator)
		}
	}
}

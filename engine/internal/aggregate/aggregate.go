// Package aggregate groups a session's stored cases without judging them.
//
// The split is deliberate. The engine says what it saw and how the observations
// relate to one another; deciding how much to trust each one, and writing it up
// for a person, happens in the orchestrator. So nothing here assigns a priority
// or a confidence, and nothing here phrases an indicator as a finding about the
// target's security.
//
// Two properties matter more than the shape of the document.
//
// It is a pure function of the stored session and cases. There is no timestamp,
// no map iteration reaching the output unsorted, and no dependence on how many
// workers ran: the same stored files produce the same bytes, so two exports can
// be compared directly rather than field by field.
//
// It is a view, never a filter. Grouping forty near-identical latency indicators
// into one row is only honest if the row still accounts for all forty and can
// still name them, so every group carries the complete list of case ids it covers
// and the document declares totals a reader can check the groups against. A
// grouping that dropped a case, or that summarised one away behind a count, would
// be hiding results while appearing to organise them.
package aggregate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"mihakk/internal/detect"
	"mihakk/internal/safety"
	"mihakk/internal/store"
)

// Version is the aggregate document's own contract version.
const Version = "1"

// TheNote travels with every document. The engine records observations; calling
// one a vulnerability is a judgement nothing here is entitled to make.
const TheNote = "Results are indicators that need verification, not confirmed vulnerabilities."

// WithheldAllowedAddresses names what a shareable document leaves out.
const WithheldAllowedAddresses = "allowed_addresses"

// Document is one session's aggregation.
type Document struct {
	AggregateVersion string       `json:"aggregate_version"`
	Session          SessionInfo  `json:"session"`
	Scope            ScopeInfo    `json:"scope"`
	Completeness     Completeness `json:"completeness"`
	Totals           Totals       `json:"totals"`
	Groups           []Group      `json:"groups"`
	Note             string       `json:"note"`
}

// SessionInfo is what the run was, without anything scope-shaped.
type SessionInfo struct {
	SessionID     string     `json:"session_id"`
	EngineVersion string     `json:"engine_version"`
	StartedAt     time.Time  `json:"started_at"`
	EndedAt       *time.Time `json:"ended_at,omitempty"`
	Status        string     `json:"status"`
	Operator      string     `json:"operator"`
	CorpusDigest  string     `json:"corpus_digest"`
	ConfigDigest  string     `json:"config_digest"`
	PlannedCases  int        `json:"planned_cases"`
	ExecutedCases int        `json:"executed_cases"`
	SavedCases    int        `json:"saved_cases"`
	RefusedCases  int        `json:"refused_cases"`
	// What became of the run's requests. Always present in the document, and
	// null when the session predates the count: a reader must see "not
	// counted", never a zero that looks like a count.
	Accounting *store.Accounting `json:"accounting"`
}

// ScopeTarget is one target, as a document meant to be shared may describe it.
//
// There is no AllowedAddresses field. Those are the operator's internal
// addressing, they tell a reader nothing about a finding, and a report is the
// kind of thing that gets forwarded. The digest below still covers them, so
// leaving them out cannot be used to make a different scope hash the same.
type ScopeTarget struct {
	Scheme       string   `json:"scheme"`
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	PathPrefixes []string `json:"path_prefixes"`
	Methods      []string `json:"methods"`
}

// ScopeInfo describes what the run was allowed to reach, and how far that
// description can be trusted.
//
// Recorded and Consistent are separate answers to separate questions, and neither
// implies the other. Recorded says the engine stored the scope its guarded client
// enforced. Consistent says that stored scope still hashes to the digest stored
// beside it -- which is a statement about the file being internally coherent, and
// nothing more. That the description matches what actually governed the traffic is
// established by the engine taking it from the enforcing client, and tested there;
// a matching digest is not evidence of it.
type ScopeInfo struct {
	// Recorded is false for sessions written before the engine stored the scope.
	// Such a document carries TargetsSummary only, and a reader must not present
	// it as the run's full scope.
	Recorded bool `json:"recorded"`

	// Consistent is meaningful only when Recorded. False means the stored scope
	// and the stored digest disagree: the record cannot be trusted to describe
	// itself, let alone the run.
	Consistent bool `json:"consistent"`

	// InconsistencyReason is set whenever Consistent is false, and says what
	// could not be established rather than leaving a bare flag.
	InconsistencyReason string `json:"inconsistency_reason,omitempty"`

	// Digest is what the session record stored. RecomputedDigest is what the
	// stored scope hashes to now. Both are shown so a reader can see the
	// comparison instead of taking Consistent on trust.
	Digest           string `json:"digest"`
	RecomputedDigest string `json:"recomputed_digest,omitempty"`

	MaxRedirects int           `json:"max_redirects,omitempty"`
	Targets      []ScopeTarget `json:"targets,omitempty"`

	// TargetsSummary is the readable authority list, always present. It is all a
	// pre-scope session has.
	TargetsSummary []string `json:"targets_summary"`

	// Withheld names fields deliberately left out of a shareable document.
	Withheld []string `json:"withheld,omitempty"`
}

// Completeness is the engine's own account of whether it wrote down everything it
// saw. It says nothing about whether a consumer received everything the engine
// emitted -- that is the orchestrator's half, and a report needs both.
type Completeness struct {
	EngineStatus     string `json:"engine_status"`
	SavedCasesStated int    `json:"saved_cases_stated"`
	CasesInStore     int    `json:"cases_in_store"`
	UnsavedCases     int    `json:"unsaved_cases"`
	AuditFailures    int    `json:"audit_failures"`
	IncompleteReason string `json:"incomplete_reason,omitempty"`

	// Consistent is whether the case log holds as many cases as the record says
	// were saved. A third comparison, independent of both status fields.
	Consistent bool `json:"consistent"`

	// Reason explains a false Consistent.
	Reason string `json:"reason,omitempty"`
}

// Totals are declared so the groups can be checked against them rather than
// believed. A consumer that finds them disagreeing must treat the document as
// broken, not reconcile it.
type Totals struct {
	Cases              int `json:"cases"`
	IndicatorInstances int `json:"indicator_instances"`
	Groups             int `json:"groups"`
}

// Signature is what makes two indicators the same kind of observation.
//
// The raw URL is useless as a key: every mutation changes the query string, so
// grouping on it would put each case in its own group and aggregate nothing. The
// path without its query, plus which sample and field the mutation was applied
// to, is what stays stable across the mutations of one endpoint.
type Signature struct {
	IndicatorType string `json:"indicator_type"`
	Target        string `json:"target"`
	Method        string `json:"method"`
	Path          string `json:"path"`

	// StatusCode separates a 500 from a 503 on the same endpoint, which are
	// different failures. Nil for indicator types where it would only add noise.
	StatusCode *int `json:"status_code"`
}

// Group is one signature and every case that produced it.
type Group struct {
	GroupID   string    `json:"group_id"`
	Signature Signature `json:"signature"`

	// Occurrences counts (case, indicator) pairs, which is what the totals count.
	Occurrences int `json:"occurrences"`

	// Mutators is every distinct mutation that produced this signature, sorted.
	// It is what grouping discards, kept because several unrelated mutators
	// provoking the same response says more than one doing it repeatedly.
	Mutators []string `json:"mutators,omitempty"`

	// CaseIDs is complete and sorted. Truncating it here would be the hiding this
	// package exists to avoid; a renderer may show fewer, and must say so.
	CaseIDs []string `json:"case_ids"`

	Representative Representative `json:"representative"`

	FirstObservedAt time.Time `json:"first_observed_at"`
	LastObservedAt  time.Time `json:"last_observed_at"`
}

// Representative is the case a reader should start from: the lowest case index in
// the group, because the mutation for an index is a pure function of it, so the
// earliest is the cheapest to regenerate.
type Representative struct {
	CaseID          string                  `json:"case_id"`
	CaseIndex       int                     `json:"case_index"`
	Reason          string                  `json:"reason"`
	Baseline        *detect.BaselineSummary `json:"baseline,omitempty"`
	Reproduction    store.Reproduction      `json:"reproduction"`
	RequestSummary  store.RequestSummary    `json:"request_summary"`
	ResponseSummary store.ResponseSummary   `json:"response_summary"`
}

// statusCodeMatters reports whether the response status belongs in the signature.
func statusCodeMatters(t detect.IndicatorType) bool {
	return t == detect.HTTP5xx
}

// Build assembles the document. It reads nothing but what it is given.
func Build(sess *store.Session, cases []*store.Case) (*Document, error) {
	if sess == nil {
		return nil, fmt.Errorf("mihakk: aggregate: no session record")
	}

	doc := &Document{
		AggregateVersion: Version,
		Session: SessionInfo{
			SessionID:     sess.SessionID,
			EngineVersion: sess.EngineVersion,
			StartedAt:     sess.StartedAt,
			EndedAt:       sess.EndedAt,
			Status:        sess.Status,
			Operator:      sess.Operator,
			CorpusDigest:  sess.CorpusDigest,
			ConfigDigest:  sess.ConfigDigest,
			PlannedCases:  sess.PlannedCases,
			ExecutedCases: sess.ExecutedCases,
			SavedCases:    sess.SavedCases,
			RefusedCases:  sess.RefusedCases,
			Accounting:    sess.Accounting,
		},
		Scope:        describeScope(sess),
		Completeness: describeCompleteness(sess, len(cases)),
		Note:         TheNote,
	}

	groups, instances := groupCases(cases)
	doc.Groups = groups
	doc.Totals = Totals{
		Cases:              len(cases),
		IndicatorInstances: instances,
		Groups:             len(groups),
	}
	return doc, nil
}

// describeScope renders the stored scope for sharing, and says how far it can be
// trusted.
func describeScope(sess *store.Session) ScopeInfo {
	info := ScopeInfo{
		Digest:         sess.ScopeDigest,
		TargetsSummary: append([]string(nil), sess.Targets...),
	}
	if info.TargetsSummary == nil {
		info.TargetsSummary = []string{}
	}

	if sess.Scope == nil {
		info.Recorded = false
		info.Consistent = false
		info.InconsistencyReason = "the engine that ran this session did not record the " +
			"scope its client enforced, so only the target authorities are available; " +
			"this is a summary of targets, not the session's full scope"
		return info
	}

	info.Recorded = true
	info.MaxRedirects = sess.Scope.MaxRedirects
	info.Withheld = []string{WithheldAllowedAddresses}
	for _, t := range sess.Scope.Targets {
		info.Targets = append(info.Targets, ScopeTarget{
			Scheme:       t.Scheme,
			Host:         t.Host,
			Port:         t.Port,
			PathPrefixes: append([]string(nil), t.PathPrefixes...),
			Methods:      append([]string(nil), t.Methods...),
		})
	}

	// Recomputed from the stored scope. This establishes that the record is
	// internally coherent; it is not evidence about what was enforced.
	recomputed := recomputeDigest(sess.Scope)
	info.RecomputedDigest = recomputed
	switch {
	case sess.ScopeDigest == "":
		info.Consistent = false
		info.InconsistencyReason = "the session record stores a scope but no digest to " +
			"check it against, so the stored scope cannot be shown to be coherent"
	case recomputed != sess.ScopeDigest:
		info.Consistent = false
		info.InconsistencyReason = fmt.Sprintf(
			"the stored scope hashes to %s but the record stores %s; the two disagree, "+
				"so this description is not a coherent record of the session's scope and "+
				"nothing here establishes what the run was allowed to reach",
			recomputed, sess.ScopeDigest)
	default:
		info.Consistent = true
	}
	return info
}

func recomputeDigest(scope *safety.Scope) string {
	c := scope.Clone()
	return c.Digest()
}

func describeCompleteness(sess *store.Session, inStore int) Completeness {
	c := Completeness{
		EngineStatus:     sess.Status,
		SavedCasesStated: sess.SavedCases,
		CasesInStore:     inStore,
		UnsavedCases:     sess.UnsavedCases,
		AuditFailures:    sess.AuditFailures,
		IncompleteReason: sess.IncompleteReason,
	}
	if inStore == sess.SavedCases {
		c.Consistent = true
		return c
	}
	c.Consistent = false
	c.Reason = fmt.Sprintf(
		"the record says %d case(s) were saved but the case log holds %d; "+
			"the stored results are not the set the run reported",
		sess.SavedCases, inStore)
	return c
}

// groupCases turns cases into groups, and returns how many (case, indicator)
// pairs went in. Every pair lands in exactly one group.
func groupCases(cases []*store.Case) ([]Group, int) {
	type accumulator struct {
		sig      Signature
		caseIDs  map[string]bool
		mutators map[string]bool
		pairs    int
		first    time.Time
		last     time.Time
		rep      *store.Case
		repInd   detect.Indicator
	}

	byID := map[string]*accumulator{}
	instances := 0

	for _, c := range cases {
		if c == nil {
			continue
		}
		for _, ind := range c.Indicators {
			instances++
			sig := signatureFor(c, ind)
			id := signatureID(sig)

			acc := byID[id]
			if acc == nil {
				acc = &accumulator{
					sig: sig, caseIDs: map[string]bool{}, mutators: map[string]bool{},
					first: c.ObservedAt, last: c.ObservedAt,
					rep: c, repInd: ind,
				}
				byID[id] = acc
			}
			acc.caseIDs[c.CaseID] = true
			if _, mutator := splitTarget(c.Reproduction.Target); mutator != "" {
				acc.mutators[mutator] = true
			}
			acc.pairs++
			if c.ObservedAt.Before(acc.first) {
				acc.first = c.ObservedAt
			}
			if c.ObservedAt.After(acc.last) {
				acc.last = c.ObservedAt
			}
			// The lowest case index represents the group: deterministic, and the
			// cheapest point to start regenerating from.
			if c.Reproduction.CaseIndex < acc.rep.Reproduction.CaseIndex {
				acc.rep, acc.repInd = c, ind
			}
		}
	}

	groups := make([]Group, 0, len(byID))
	for id, acc := range byID {
		ids := make([]string, 0, len(acc.caseIDs))
		for cid := range acc.caseIDs {
			ids = append(ids, cid)
		}
		sort.Strings(ids)

		mutators := make([]string, 0, len(acc.mutators))
		for m := range acc.mutators {
			mutators = append(mutators, m)
		}
		sort.Strings(mutators)

		groups = append(groups, Group{
			GroupID:     id,
			Signature:   acc.sig,
			Occurrences: acc.pairs,
			Mutators:    mutators,
			CaseIDs:     ids,
			Representative: Representative{
				CaseID:          acc.rep.CaseID,
				CaseIndex:       acc.rep.Reproduction.CaseIndex,
				Reason:          acc.repInd.Reason,
				Baseline:        acc.repInd.Baseline,
				Reproduction:    acc.rep.Reproduction,
				RequestSummary:  acc.rep.RequestSummary,
				ResponseSummary: acc.rep.ResponseSummary,
			},
			FirstObservedAt: acc.first,
			LastObservedAt:  acc.last,
		})
	}

	// Sorted by group id, which is a hash of the signature: stable across runs and
	// independent of map iteration order.
	sort.Slice(groups, func(i, j int) bool { return groups[i].GroupID < groups[j].GroupID })
	return groups, instances
}

// splitTarget separates "sample kind/name (mutator)" into the field that was
// mutated and the mutator that did it.
//
// Only the field belongs in a signature. The stored target carries both, and
// grouping on the whole string defeated the point: twenty mutators applied to one
// query parameter produced twenty groups, so a real run aggregated nothing at all
// while the unit fixtures -- which happened to use one mutator -- collapsed
// perfectly. The mutators are kept beside the group instead, where "twelve
// different mutators all produce this" is exactly what a reader wants to know.
func splitTarget(target string) (field, mutator string) {
	if !strings.HasSuffix(target, ")") {
		return target, ""
	}
	open := strings.LastIndex(target, " (")
	if open < 0 {
		return target, ""
	}
	return target[:open], target[open+2 : len(target)-1]
}

func signatureFor(c *store.Case, ind detect.Indicator) Signature {
	field, _ := splitTarget(c.Reproduction.Target)
	sig := Signature{
		IndicatorType: string(ind.Type),
		Target:        field,
		Method:        strings.ToUpper(c.RequestSummary.Method),
		Path:          pathWithoutQuery(c.RequestSummary.URL),
	}
	if statusCodeMatters(ind.Type) && c.ResponseSummary.StatusCode != nil {
		code := *c.ResponseSummary.StatusCode
		sig.StatusCode = &code
	}
	return sig
}

// pathWithoutQuery keeps the part of the URL that identifies the endpoint.
func pathWithoutQuery(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		// An unparseable URL still has to group somewhere, and grouping it under a
		// marker is better than grouping it under a string that happens to differ
		// per mutation.
		return "(unparseable url)"
	}
	if u.Path == "" {
		return "/"
	}
	return u.Path
}

// signatureID hashes the signature. Field order in a Go struct is fixed, so the
// encoding is stable, and the same signature hashes the same in any process.
func signatureID(sig Signature) string {
	raw, err := json.Marshal(sig)
	if err != nil {
		// Signature holds only strings and an int pointer; Marshal cannot fail.
		panic("mihakk: aggregate: signature digest: " + err.Error())
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

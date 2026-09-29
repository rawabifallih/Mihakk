package runner

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"mihakk/internal/audit"
	"mihakk/internal/corpus"
	"mihakk/internal/detect"
	"mihakk/internal/mutate"
	"mihakk/internal/safety"
	"mihakk/internal/store"
)

// Fidelity says how faithful a regenerated request is to the original.
type Fidelity string

const (
	// Exact: the engine version, corpus and config all still match the
	// recipe, so the regenerated request is byte-identical to the original.
	Exact Fidelity = "exact"
	// Drifted: at least one input changed. The request is a close relative
	// of the original, not the original, and the comparison must be read
	// with that in mind.
	Drifted Fidelity = "drifted"
)

// Drift names one input that changed since the case was recorded.
type Drift struct {
	Input    string `json:"input"`
	Recorded string `json:"recorded"`
	Current  string `json:"current"`
	Effect   string `json:"effect"`
}

// ReproduceResult is the outcome of re-sending a saved case.
type ReproduceResult struct {
	CaseID   string   `json:"case_id"`
	Fidelity Fidelity `json:"fidelity"`
	Drift    []Drift  `json:"drift,omitempty"`

	AuthorizationRevalidated bool   `json:"authorization_revalidated"`
	ScopeDigest              string `json:"scope_digest"`

	// IndicatorReappeared is nil when the request could not be sent at all.
	// A false is a real answer, not a failure: applications are allowed to
	// behave differently on a second look.
	IndicatorReappeared *bool `json:"indicator_reappeared"`

	OriginalIndicators []detect.Indicator `json:"original_indicators"`
	ReplayedIndicators []detect.Indicator `json:"replayed_indicators"`

	Original store.ResponseSummary `json:"original"`
	Replayed store.ResponseSummary `json:"replayed"`

	ComparisonNote string `json:"comparison_note"`

	// AuditFailures counts audit events this reproduce could not record. A
	// reproduce that ran but left no trace is not a complete reproduce, so it
	// is reported rather than passed over.
	AuditFailures int      `json:"audit_failures"`
	Warnings      []string `json:"warnings,omitempty"`
}

// auditIncomplete notes a failed audit write on the result.
func (r *ReproduceResult) auditIncomplete(err error) {
	if err == nil {
		return
	}
	r.AuditFailures++
	r.Warnings = append(r.Warnings, fmt.Sprintf(
		"an audit event could not be recorded (%v); this reproduce is not fully accounted for "+
			"in the audit log", err))
}

// ReproduceOptions carries everything needed for one reproduce.
type ReproduceOptions struct {
	CaseID        string
	EngineVersion string

	// Client and Governor are freshly built from the *current* config, so a
	// reproduce is bound by today's limits and today's scope, never by the
	// ones that happened to be in force when the case was first seen.
	Client   *safety.Client
	Governor *safety.Governor
	Config   *safety.SessionConfig
	Corpus   *corpus.Corpus

	Detector *detect.Detector
	Store    CaseFinder
	Audit    AuditSink
	Redactor *safety.Redactor

	Now func() time.Time
}

// Reproduce re-sends one saved case and reports whether the same indicator
// showed up again.
//
// Reproduction is not exempt from anything. The config it is given has
// already been through safety.SessionConfig.Prepare, which re-validates the
// authorisation acknowledgement and the scope; the client it is given cannot
// be constructed without them; and the governor it is given applies the full
// set of limits. The regenerated request goes out through the same guarded
// client as any other.
func Reproduce(ctx context.Context, opts ReproduceOptions) (*ReproduceResult, error) {
	switch {
	case opts.Client == nil:
		return nil, errors.New("mihakk: reproduce needs a guarded client")
	case opts.Governor == nil:
		return nil, errors.New("mihakk: reproduce needs a governor")
	case opts.Store == nil:
		return nil, errors.New("mihakk: reproduce needs a store")
	case opts.Config == nil:
		return nil, errors.New("mihakk: reproduce needs a session config")
	case opts.Corpus == nil:
		return nil, errors.New("mihakk: reproduce needs a corpus")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	redactor := opts.Redactor
	if redactor == nil {
		redactor = safety.NewRedactor()
	}
	detector := opts.Detector
	if detector == nil {
		detector = detect.New(detect.DefaultConfig())
	}

	saved, session, err := opts.Store.FindCase(opts.CaseID)
	if err != nil {
		return nil, err
	}

	result := &ReproduceResult{
		CaseID: opts.CaseID,
		// Getting this far means the config passed Prepare and the client was
		// built, both of which refuse without a current, scope-bound
		// acknowledgement.
		AuthorizationRevalidated: true,
		ScopeDigest:              opts.Config.Scope.Digest(),
		OriginalIndicators:       saved.Indicators,
		Original:                 saved.ResponseSummary,
	}

	if opts.Audit != nil {
		result.auditIncomplete(opts.Audit.Write(audit.Event{
			Type:          audit.ReproduceStarted,
			SessionID:     saved.SessionID,
			CaseID:        opts.CaseID,
			Operator:      opts.Config.Authorization.Operator,
			Statement:     opts.Config.Authorization.Statement,
			AckedAt:       &opts.Config.Authorization.AckedAt,
			ScopeDigest:   result.ScopeDigest,
			EngineVersion: opts.EngineVersion,
		}))
	}

	// Rebuild the plan from the current corpus and config, then regenerate
	// the case by index. Nothing is replayed from disk: the request is
	// recomputed, which is why credentials never had to be stored.
	seed, err := hex.DecodeString(saved.Reproduction.MasterSeed)
	if err != nil {
		return nil, fmt.Errorf("mihakk: case %q has an unreadable seed: %w", opts.CaseID, err)
	}

	// The plan is rebuilt with the settings the original run used, taken from
	// the stored session. Falling back to the defaults would silently change
	// the size of the plan, and the case index would then address a different
	// mutation -- or none at all.
	mutCfg := session.MutationConfig
	if mutCfg.MutationsPerTarget == 0 {
		// A session recorded before the mutation config was persisted. The
		// defaults are the best guess available, and any resulting mismatch
		// surfaces as an out-of-range case index rather than a wrong request.
		mutCfg = mutate.DefaultConfig()
	}
	plan, err := mutate.NewPlan(opts.Corpus, mutCfg, opts.EngineVersion, seed)
	if err != nil {
		return nil, fmt.Errorf("mihakk: rebuilding the plan for %q: %w", opts.CaseID, err)
	}

	result.Fidelity, result.Drift = compareInputs(saved, plan, opts.EngineVersion)

	generated, err := plan.Case(saved.Reproduction.CaseIndex)
	if err != nil {
		return nil, fmt.Errorf("mihakk: regenerating case %d: %w", saved.Reproduction.CaseIndex, err)
	}

	req, err := buildRequest(generated.Request.Method, generated.Request.URL,
		generated.Request.Headers, generated.Request.Body)
	if err != nil {
		return nil, err
	}

	started := now()
	resp, sendErr := opts.Client.Do(ctx, req)

	var obs detect.Observation
	if sendErr != nil {
		obs = detect.Observation{Err: sendErr, TimedOut: isTimeout(sendErr), Latency: now().Sub(started)}
	} else {
		obs = detect.Observation{
			StatusCode: resp.StatusCode,
			Latency:    resp.Latency,
			Body:       resp.Body,
			BodyBytes:  len(resp.Body),
			Truncated:  resp.Truncated,
		}
	}

	// A safety refusal leaves no final response to compare. A redirect can have
	// attempted and answered earlier hops before a later hop is refused, so do
	// not turn the terminal refusal into the false claim that nothing happened.
	if sendErr != nil && isSafetyRefusal(sendErr) {
		result.IndicatorReappeared = nil
		msg := redactor.String(sendErr.Error())
		result.Replayed = store.ResponseSummary{Error: &msg}
		outcome := "not_sent"
		if resp != nil && resp.Accounting.Attempted() {
			outcome = "refused_after_attempt"
			attempts := resp.Accounting.HTTPAnswered + resp.Accounting.HTTPUnanswered
			result.ComparisonNote = fmt.Sprintf(
				"the replay made %d HTTP attempt(s), then a later hop was refused by the "+
					"safety layer; no final response is available, so whether the indicator "+
					"still occurs is unknown: %s", attempts, msg)
		} else {
			result.ComparisonNote = "the request was refused by the safety layer and never sent, " +
				"so whether the indicator still occurs is unknown: " + msg
		}
		writeReproduceAudit(opts, saved, result, outcome)
		return result, nil
	}

	var baseline *detect.Baseline
	if session != nil && session.Baselines != nil {
		baseline = session.Baselines[baselineKey(generated.Request.Method, generated.Request.URL)]
	}
	result.ReplayedIndicators = detector.Evaluate(obs, baseline)
	result.Replayed = summarise(obs, redactor)

	reappeared := sharesIndicatorType(saved.Indicators, result.ReplayedIndicators)
	result.IndicatorReappeared = &reappeared
	result.ComparisonNote = comparisonNote(reappeared, saved.Indicators, result.ReplayedIndicators, result.Fidelity)

	writeReproduceAudit(opts, saved, result, fmt.Sprintf("indicator_reappeared=%t", reappeared))
	return result, nil
}

func writeReproduceAudit(opts ReproduceOptions, saved *store.Case, result *ReproduceResult, outcome string) {
	if opts.Audit == nil {
		return
	}
	result.auditIncomplete(opts.Audit.Write(audit.Event{
		Type:          audit.ReproduceFinished,
		SessionID:     saved.SessionID,
		CaseID:        result.CaseID,
		Operator:      opts.Config.Authorization.Operator,
		ScopeDigest:   result.ScopeDigest,
		EngineVersion: opts.EngineVersion,
		Outcome:       outcome,
		Detail:        result.ComparisonNote,
		Stats:         map[string]any{"fidelity": string(result.Fidelity)},
	}))
}

// compareInputs decides whether the regenerated request is the original or a
// close relative, and says exactly what moved.
func compareInputs(saved *store.Case, plan *mutate.Plan, engineVersion string) (Fidelity, []Drift) {
	var drift []Drift

	if saved.Reproduction.EngineVersion != engineVersion {
		drift = append(drift, Drift{
			Input:    "engine_version",
			Recorded: saved.Reproduction.EngineVersion,
			Current:  engineVersion,
			Effect: "the mutation algorithm is versioned, so a different engine can generate " +
				"a different request from the same seed and index",
		})
	}
	if saved.Reproduction.CorpusDigest != plan.CorpusDigest() {
		drift = append(drift, Drift{
			Input:    "corpus_digest",
			Recorded: saved.Reproduction.CorpusDigest,
			Current:  plan.CorpusDigest(),
			Effect:   "the samples have changed, so this case index no longer points at the same field",
		})
	}
	if saved.Reproduction.ConfigDigest != plan.ConfigDigest() {
		drift = append(drift, Drift{
			Input:    "config_digest",
			Recorded: saved.Reproduction.ConfigDigest,
			Current:  plan.ConfigDigest(),
			Effect:   "the mutation settings have changed, which changes what is generated",
		})
	}

	if len(drift) == 0 {
		return Exact, nil
	}
	return Drifted, drift
}

func summarise(obs detect.Observation, redactor *safety.Redactor) store.ResponseSummary {
	if obs.Err != nil {
		msg := redactor.String(obs.Err.Error())
		return store.ResponseSummary{Error: &msg}
	}
	status := obs.StatusCode
	latency := float64(obs.Latency) / float64(time.Millisecond)
	size := obs.BodyBytes
	return store.ResponseSummary{
		StatusCode: &status,
		LatencyMS:  &latency,
		BodyBytes:  &size,
		Truncated:  obs.Truncated,
	}
}

func sharesIndicatorType(original, replayed []detect.Indicator) bool {
	seen := map[detect.IndicatorType]bool{}
	for _, i := range replayed {
		seen[i.Type] = true
	}
	for _, i := range original {
		if seen[i.Type] {
			return true
		}
	}
	return false
}

// comparisonNote states the outcome without overclaiming in either direction.
func comparisonNote(reappeared bool, original, replayed []detect.Indicator, fidelity Fidelity) string {
	var note string
	if reappeared {
		note = fmt.Sprintf("the same indicator type was observed again (%s). "+
			"That it recurs makes it easier to investigate; it is still an indicator, not a confirmed vulnerability",
			typeList(replayed))
	} else if len(replayed) == 0 {
		note = fmt.Sprintf("no indicator was observed this time; the original was %s. "+
			"This does not show the first observation was wrong: responses and timings vary between runs",
			typeList(original))
	} else {
		note = fmt.Sprintf("different indicators were observed (%s) from the original (%s)",
			typeList(replayed), typeList(original))
	}
	if fidelity == Drifted {
		note += ". The inputs have drifted since the case was recorded, so this is a close " +
			"approximation of the original request rather than the request itself"
	}
	return note
}

func typeList(indicators []detect.Indicator) string {
	if len(indicators) == 0 {
		return "none"
	}
	out := ""
	for i, ind := range indicators {
		if i > 0 {
			out += ", "
		}
		out += string(ind.Type)
	}
	return out
}

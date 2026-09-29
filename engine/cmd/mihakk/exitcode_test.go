package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"mihakk/internal/runner"
	"mihakk/internal/store"
)

// An exit code that depends on the output format is a trap for whatever runs
// this in a pipeline: the JSON branch used to return success before the audit
// check ran, so `-json` reported zero while the document it had just printed
// said the audit log was incomplete.

func reproduceResult(auditFailures int) *runner.ReproduceResult {
	reappeared := true
	r := &runner.ReproduceResult{
		CaseID:                   "s1-000042",
		Fidelity:                 runner.Exact,
		AuthorizationRevalidated: true,
		ScopeDigest:              "sha256:abc",
		IndicatorReappeared:      &reappeared,
		ComparisonNote:           "the same indicator type was observed again",
	}
	for i := 0; i < auditFailures; i++ {
		r.AuditFailures++
		r.Warnings = append(r.Warnings,
			"an audit event could not be recorded (no space left on device); "+
				"this reproduce is not fully accounted for in the audit log")
	}
	return r
}

func TestReproduceExitCodeIsTheSameInBothOutputModes(t *testing.T) {
	cases := []struct {
		name          string
		auditFailures int
		wantCode      int
	}{
		{"clean", 0, 0},
		{"one audit failure", 1, 1},
		{"several audit failures", 3, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var textOut, textErr bytes.Buffer
			textCode := emitReproduce(reproduceResult(tc.auditFailures), false, &textOut, &textErr)

			var jsonOut, jsonErr bytes.Buffer
			jsonCode := emitReproduce(reproduceResult(tc.auditFailures), true, &jsonOut, &jsonErr)

			if textCode != tc.wantCode {
				t.Errorf("text mode exited %d, want %d", textCode, tc.wantCode)
			}
			if jsonCode != tc.wantCode {
				t.Errorf("json mode exited %d, want %d", jsonCode, tc.wantCode)
			}
			if textCode != jsonCode {
				t.Fatalf("the exit code depends on the output format: text=%d json=%d",
					textCode, jsonCode)
			}
		})
	}
}

// The detail must survive into the JSON, not only onto stderr: a caller
// parsing stdout has to be able to see what is missing.
func TestReproduceJSONCarriesTheAuditDetail(t *testing.T) {
	var out, errOut bytes.Buffer
	code := emitReproduce(reproduceResult(2), true, &out, &errOut)

	if code == 0 {
		t.Fatal("an incomplete audit exited zero in json mode")
	}

	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out.String())
	}

	failures, ok := decoded["audit_failures"].(float64)
	if !ok || int(failures) != 2 {
		t.Errorf("audit_failures = %v, want 2", decoded["audit_failures"])
	}
	warnings, ok := decoded["warnings"].([]any)
	if !ok || len(warnings) != 2 {
		t.Fatalf("warnings = %v, want two entries", decoded["warnings"])
	}
	if !strings.Contains(warnings[0].(string), "audit log") {
		t.Errorf("the warning does not say what is missing: %v", warnings[0])
	}

	// The warning also reaches stderr, where it cannot corrupt the document
	// a caller is parsing on stdout.
	if !strings.Contains(errOut.String(), "AUDIT INCOMPLETE") {
		t.Errorf("stderr does not flag the incomplete audit: %q", errOut.String())
	}
	if strings.Contains(out.String(), "AUDIT INCOMPLETE") {
		t.Error("the human-readable warning was written into the JSON stream")
	}
}

// A clean reproduce must not emit warnings in either mode, or the checks
// above would pass on a command that always complains.
func TestACleanReproduceIsSilentAndExitsZero(t *testing.T) {
	for _, asJSON := range []bool{false, true} {
		var out, errOut bytes.Buffer
		code := emitReproduce(reproduceResult(0), asJSON, &out, &errOut)
		if code != 0 {
			t.Errorf("json=%t: exited %d, want 0", asJSON, code)
		}
		if strings.Contains(errOut.String(), "AUDIT INCOMPLETE") {
			t.Errorf("json=%t: a clean reproduce warned about the audit log", asJSON)
		}
	}

	// And the JSON of a clean reproduce carries no warnings.
	var out, errOut bytes.Buffer
	emitReproduce(reproduceResult(0), true, &out, &errOut)
	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if w, present := decoded["warnings"]; present {
		t.Errorf("a clean reproduce emitted warnings: %v", w)
	}
}

// --- run ------------------------------------------------------------------

func runResult(incomplete bool) *runner.Result {
	result := &runner.Result{
		Session: &store.Session{
			SessionID: "s1",
			Status:    store.SessionCompleted,
		},
		Executed: 100,
		Detected: 16,
		Saved:    16,
	}
	if incomplete {
		result.Saved = 2
		result.UnsavedCases = 14
		result.Incomplete = true
		result.IncompleteReason = "14 observed indicator(s) could not be written to the case " +
			"store (first error: no space left on device); the saved results are a subset of " +
			"what was found"
		result.Session.Status = store.SessionIncomplete
	}
	return result
}

func TestRunExitsNonZeroWhenResultsAreIncomplete(t *testing.T) {
	var out, errOut bytes.Buffer
	code := emitRunSummary(runResult(true), reproduceHint{}, &out, &errOut)

	if code == 0 {
		t.Fatal("a run that lost results exited zero")
	}

	stderr := errOut.String()
	if !strings.Contains(stderr, "RESULTS INCOMPLETE") {
		t.Errorf("stderr does not flag the incomplete results: %q", stderr)
	}
	if !strings.Contains(stderr, "14 of 16") {
		t.Errorf("stderr does not say how much was lost: %q", stderr)
	}
	if !strings.Contains(stderr, "Do not read the saved cases as everything this run found") {
		t.Errorf("stderr does not warn against reading the cases as complete: %q", stderr)
	}
	if !strings.Contains(stderr, store.SessionIncomplete) {
		t.Errorf("stderr does not name the recorded session status: %q", stderr)
	}

	// The summary on stdout must not claim completion either.
	if strings.Contains(out.String(), "finished: "+store.SessionCompleted) {
		t.Errorf("the summary reported a completed session: %q", out.String())
	}
}

func TestRunExitsZeroWhenResultsAreComplete(t *testing.T) {
	var out, errOut bytes.Buffer
	result := runResult(false)
	result.Cases = []*store.Case{{CaseID: "s1-000001"}}

	code := emitRunSummary(result, reproduceHint{
		config: "cfg.json", corpus: "corpus.json", data: "./data",
	}, &out, &errOut)

	if code != 0 {
		t.Fatalf("a complete run exited %d", code)
	}
	if strings.Contains(errOut.String(), "INCOMPLETE") {
		t.Errorf("a complete run warned about incompleteness: %q", errOut.String())
	}
	stdout := out.String()
	if !strings.Contains(stdout, "indicators that need verification") {
		t.Errorf("the summary does not label the results as needing verification: %q", stdout)
	}
	if !strings.Contains(stdout, "mihakk reproduce s1-000001 -config cfg.json") {
		t.Errorf("the summary does not offer a usable reproduce command: %q", stdout)
	}
}

// Detected and saved are reported separately, so a reader can see the gap
// without having to compare two files.
func TestRunSummaryDistinguishesDetectedFromSaved(t *testing.T) {
	var out, errOut bytes.Buffer
	emitRunSummary(runResult(true), reproduceHint{}, &out, &errOut)

	stdout := out.String()
	if !strings.Contains(stdout, "detected : 16") {
		t.Errorf("the summary does not report what was detected: %q", stdout)
	}
	if !strings.Contains(stdout, "saved    : 2") {
		t.Errorf("the summary does not report what was saved: %q", stdout)
	}
}

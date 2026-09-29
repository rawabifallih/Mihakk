package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"mihakk/internal/audit"
	"mihakk/internal/corpus"
	"mihakk/internal/detect"
	"mihakk/internal/mutate"
	"mihakk/internal/runner"
	"mihakk/internal/safety"
	"mihakk/internal/store"
)

// session wires together everything a run or a reproduce needs. Building it
// is the only way to obtain a client, and it cannot be built without a config
// that has passed authorisation and scope validation -- which is what keeps
// "send a request" and "be authorised to send it" from drifting apart.
type session struct {
	cfg      *safety.SessionConfig
	corpus   *corpus.Corpus
	client   *safety.Client
	governor *safety.Governor
	store    *store.Store
	audit    *audit.Log
	redactor *safety.Redactor
}

func (s *session) close() {
	if s.governor != nil {
		s.governor.Stop()
	}
}

type sessionArgs struct {
	configPath  string
	corpusPath  string
	openAPIPath string
	baseURL     string
	dataDir     string
}

func openSession(ctx context.Context, a sessionArgs) (*session, error) {
	cfg, err := safety.LoadSessionConfig(a.configPath, time.Now())
	if err != nil {
		return nil, err
	}

	c, err := loadCorpus(a)
	if err != nil {
		return nil, err
	}

	redactor := cfg.NewRedactor()

	st, err := store.Open(a.dataDir)
	if err != nil {
		return nil, err
	}
	auditLog, err := audit.Open(filepath.Join(a.dataDir, "audit.jsonl"), redactor)
	if err != nil {
		return nil, err
	}

	gov, err := safety.NewGovernor(ctx, cfg.Limits, nil)
	if err != nil {
		return nil, err
	}

	client, err := safety.NewClient(safety.ClientConfig{
		Scope:         &cfg.Scope,
		Governor:      gov,
		Authorization: cfg.Authorization,
		Redactor:      redactor,
	})
	if err != nil {
		gov.Stop()
		return nil, err
	}

	return &session{
		cfg: cfg, corpus: c, client: client, governor: gov,
		store: st, audit: auditLog, redactor: redactor,
	}, nil
}

func loadCorpus(a sessionArgs) (*corpus.Corpus, error) {
	switch {
	case a.corpusPath != "" && a.openAPIPath != "":
		return nil, fmt.Errorf("mihakk: pass either -corpus or -openapi, not both")
	case a.openAPIPath != "":
		raw, err := os.ReadFile(a.openAPIPath)
		if err != nil {
			return nil, fmt.Errorf("mihakk: reading the OpenAPI document: %w", err)
		}
		result, err := corpus.LoadOpenAPI(raw, a.baseURL)
		if result != nil && len(result.Skipped) > 0 {
			fmt.Fprintf(os.Stderr, "mihakk: %d operation(s) are outside the supported OpenAPI subset:\n",
				len(result.Skipped))
			for _, s := range result.Skipped {
				fmt.Fprintf(os.Stderr, "  %s %s: %s\n", s.Method, s.Path, s.Reason)
			}
		}
		if err != nil {
			return nil, err
		}
		return result.Corpus, nil
	case a.corpusPath != "":
		return corpus.Load(a.corpusPath)
	default:
		return nil, fmt.Errorf("mihakk: one of -corpus or -openapi is required")
	}
}

func runCmd(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := fs.String("config", "", "session config JSON (required)")
	corpusPath := fs.String("corpus", "", "corpus JSON")
	openAPIPath := fs.String("openapi", "", "OpenAPI 3 document (JSON; a documented subset)")
	baseURL := fs.String("base-url", "", "base URL for the OpenAPI document")
	dataDir := fs.String("data", "./data", "directory for sessions, cases and the audit log")
	seedFlag := fs.String("seed", "", "master seed as hex; a random one is generated and printed if omitted")
	sessionID := fs.String("session-id", "", "session id; derived from the time if omitted")
	maxCases := fs.Int("max-cases", 0, "stop after this many cases (0 = the whole plan)")
	perTarget := fs.Int("mutations-per-target", 0, "override mutations_per_target")
	quiet := fs.Bool("quiet", false, "suppress progress output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "mihakk: -config is required")
		return 2
	}

	// Ctrl-C is the kill switch: it cancels the session context, which cuts
	// in-flight requests rather than waiting for them.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sess, err := openSession(ctx, sessionArgs{
		configPath: *configPath, corpusPath: *corpusPath,
		openAPIPath: *openAPIPath, baseURL: *baseURL, dataDir: *dataDir,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "mihakk: %v\n", err)
		return 1
	}
	defer sess.close()

	seed, err := resolveSeed(*seedFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mihakk: %v\n", err)
		return 1
	}

	mutCfg := mutate.DefaultConfig()
	if *perTarget > 0 {
		mutCfg.MutationsPerTarget = *perTarget
	}
	plan, err := mutate.NewPlan(sess.corpus, mutCfg, Version, seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mihakk: %v\n", err)
		return 1
	}

	id := *sessionID
	if id == "" {
		id = "s" + time.Now().UTC().Format("20060102T150405Z")
	}
	// The id becomes a directory name. Refused here so the run stops before it
	// starts rather than failing on its first write.
	if err := store.ValidSessionID(id); err != nil {
		fmt.Fprintf(os.Stderr, "mihakk: -session-id: %v\n", err)
		return 2
	}

	// Stopping the governor when the context is cancelled is what makes
	// Ctrl-C immediate: in-flight requests are cut, not drained.
	go func() {
		<-ctx.Done()
		sess.governor.Stop()
	}()

	r, err := runner.New(runner.Options{
		SessionID: id, EngineVersion: Version, Seed: seed,
		Client: sess.client, Governor: sess.governor, Plan: plan,
		Corpus: sess.corpus, Config: sess.cfg,
		Detector: detect.New(detect.DefaultConfig()),
		Store:    sess.store, Audit: sess.audit, Redactor: sess.redactor,
		MaxCases:   *maxCases,
		OnProgress: progressPrinter(*quiet),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "mihakk: %v\n", err)
		return 1
	}

	fmt.Printf("session %s\n", id)
	fmt.Printf("  seed          : %s\n", hex.EncodeToString(seed))
	fmt.Printf("  planned cases : %d\n", plan.Total())
	fmt.Printf("  targets       : %v\n", targetsOf(sess.cfg))
	fmt.Printf("  audit log     : %s\n\n", sess.audit.Path())

	result, err := r.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mihakk: %v\n", err)
		return 1
	}

	return emitRunSummary(result, reproduceHint{
		config: *configPath, corpus: *corpusPath, data: *dataDir,
	}, os.Stdout, os.Stderr)
}

// reproduceHint carries the paths used to print a ready-to-run reproduce
// command.
type reproduceHint struct{ config, corpus, data string }

// emitRunSummary writes the run summary and decides the exit code.
//
// `run` has no JSON mode, and this is not the place to add one: the exit code
// and the warning on stderr are what an automated caller needs, and a second
// output format would be a second place for the two to disagree.
func emitRunSummary(result *runner.Result, hint reproduceHint, stdout, stderr io.Writer) int {
	fmt.Fprintf(stdout, "\nfinished: %s\n", result.Session.Status)
	fmt.Fprintf(stdout, "  completed: %d case(s) without a local refusal\n", result.Executed)
	fmt.Fprintf(stdout, "  attempted: %d case(s) made at least one HTTP attempt\n", result.Accounting.CasesAttempted)
	fmt.Fprintf(stdout, "  refused  : %d case(s) ended in local refusal\n", result.Refused)
	a := result.Accounting
	fmt.Fprintf(stdout, "  answered : %d case(s) got a response\n", a.CasesAnswered)
	fmt.Fprintf(stdout, "  baseline : %d attempted (%d answered), %d ended in local refusal\n",
		a.BaselineAttempted, a.BaselineAnswered, a.BaselineRefused)
	fmt.Fprintf(stdout, "  http     : %d answered, %d no response, %d refused at connect "+
		"(one per redirect hop)\n", a.HTTPAnswered, a.HTTPUnanswered, a.HTTPRefused)
	fmt.Fprintf(stdout, "  detected : %d indicator case(s)\n", result.Detected)
	fmt.Fprintf(stdout, "  saved    : %d indicator case(s)\n", result.Saved)
	if result.Stopped {
		fmt.Fprintf(stdout, "  stopped  : %v\n", result.StopCause)
	}

	if result.Incomplete {
		// Nothing about this run may read as a complete result set.
		fmt.Fprintf(stderr, "\nRESULTS INCOMPLETE\n")
		fmt.Fprintf(stderr, "  %s\n", result.IncompleteReason)
		if result.UnsavedCases > 0 {
			fmt.Fprintf(stderr, "  %d of %d detected indicator(s) are NOT in the case store.\n",
				result.UnsavedCases, result.Detected)
		}
		fmt.Fprintf(stderr, "  Session %s is recorded as %q, not completed.\n",
			result.Session.SessionID, result.Session.Status)
		fmt.Fprintf(stderr, "  Do not read the saved cases as everything this run found.\n")
		return 1
	}

	if result.Saved > 0 {
		fmt.Fprintf(stdout, "\nThese are indicators that need verification, not confirmed vulnerabilities.\n")
		fmt.Fprintf(stdout, "Re-test one with:  mihakk reproduce %s -config %s -corpus %s -data %s\n",
			result.Cases[0].CaseID, hint.config, hint.corpus, hint.data)
	}
	return 0
}

func progressPrinter(quiet bool) func(runner.Progress) {
	if quiet {
		return nil
	}
	var last time.Time
	return func(p runner.Progress) {
		if time.Since(last) < 200*time.Millisecond {
			return
		}
		last = time.Now()
		fmt.Printf("\r  %d/%d attempted, %d completed without local refusal, %d saved, %d refused   ",
			p.Attempted, p.Planned, p.Executed, p.Saved, p.Refused)
	}
}

func resolveSeed(flagValue string) ([]byte, error) {
	if flagValue != "" {
		seed, err := hex.DecodeString(flagValue)
		if err != nil {
			return nil, fmt.Errorf("-seed must be hex: %w", err)
		}
		if len(seed) == 0 {
			return nil, fmt.Errorf("-seed must not be empty")
		}
		return seed, nil
	}
	seed := make([]byte, 16)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generating a seed: %w", err)
	}
	return seed, nil
}

func targetsOf(cfg *safety.SessionConfig) []string {
	var out []string
	for _, t := range cfg.Scope.Targets {
		out = append(out, fmt.Sprintf("%s://%s", t.Scheme, t.Authority()))
	}
	return out
}

func reproduceCmd(args []string) int {
	// The case id is positional, and Go's flag package stops parsing at the
	// first non-flag argument. Without pulling it out first, every flag typed
	// after the id is silently ignored -- which looked exactly like "-config
	// is required" while -config was right there on the command line.
	var caseID string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		caseID = args[0]
		args = args[1:]
	}

	fs := flag.NewFlagSet("reproduce", flag.ContinueOnError)
	configPath := fs.String("config", "", "session config JSON (required)")
	corpusPath := fs.String("corpus", "", "corpus JSON")
	openAPIPath := fs.String("openapi", "", "OpenAPI 3 document (JSON)")
	baseURL := fs.String("base-url", "", "base URL for the OpenAPI document")
	dataDir := fs.String("data", "./data", "directory holding the sessions")
	asJSON := fs.Bool("json", false, "emit the result as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if caseID == "" && fs.NArg() > 0 {
		caseID = fs.Arg(0) // the id was given after the flags
	}
	if caseID == "" {
		fmt.Fprintln(os.Stderr, "mihakk: a case id is required: mihakk reproduce <case-id> -config ...")
		return 2
	}
	// A case id carries a session id, which becomes a directory name.
	if _, _, err := store.ParseCaseID(caseID); err != nil {
		fmt.Fprintf(os.Stderr, "mihakk: %v\n", err)
		return 2
	}
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "mihakk: -config is required")
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// openSession re-runs the whole safety configuration: the authorisation
	// acknowledgement must still be current and still bound to this scope,
	// and the limits are rebuilt from the config as they are today.
	sess, err := openSession(ctx, sessionArgs{
		configPath: *configPath, corpusPath: *corpusPath,
		openAPIPath: *openAPIPath, baseURL: *baseURL, dataDir: *dataDir,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "mihakk: %v\n", err)
		return 1
	}
	defer sess.close()

	result, err := runner.Reproduce(ctx, runner.ReproduceOptions{
		CaseID: caseID, EngineVersion: Version,
		Client: sess.client, Governor: sess.governor,
		Config: sess.cfg, Corpus: sess.corpus,
		Detector: detect.New(detect.DefaultConfig()),
		Store:    sess.store, Audit: sess.audit, Redactor: sess.redactor,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "mihakk: %v\n", err)
		return 1
	}

	return emitReproduce(result, *asJSON, os.Stdout, os.Stderr)
}

// emitReproduce writes the result and decides the process exit code.
//
// Rendering and the exit code are decided in one place on purpose. They were
// split before, and the JSON branch returned success before the audit check
// ran: an automated caller passing -json read a zero exit as "fine" while the
// JSON it had just parsed said the audit log was incomplete. The exit code
// must not depend on the output format.
func emitReproduce(result *runner.ReproduceResult, asJSON bool, stdout, stderr io.Writer) int {
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fmt.Fprintf(stderr, "mihakk: %v\n", err)
			return 1
		}
	} else {
		fmt.Fprintf(stdout, "reproduce %s\n", result.CaseID)
		fmt.Fprintf(stdout, "  authorisation re-validated : %t\n", result.AuthorizationRevalidated)
		fmt.Fprintf(stdout, "  scope digest               : %s\n", result.ScopeDigest)
		fmt.Fprintf(stdout, "  fidelity                   : %s\n", result.Fidelity)
		for _, d := range result.Drift {
			fmt.Fprintf(stdout, "    drift: %s\n      recorded %s\n      current  %s\n      %s\n",
				d.Input, d.Recorded, d.Current, d.Effect)
		}

		switch {
		case result.IndicatorReappeared == nil:
			fmt.Fprintf(stdout, "  indicator reappeared       : unknown (nothing was sent)\n")
		case *result.IndicatorReappeared:
			fmt.Fprintf(stdout, "  indicator reappeared       : yes\n")
		default:
			fmt.Fprintf(stdout, "  indicator reappeared       : no\n")
		}
		fmt.Fprintf(stdout, "\n%s\n", result.ComparisonNote)
	}

	// Reached in both modes. In JSON mode the same facts are already in the
	// document on stdout (audit_failures, warnings); this goes to stderr so a
	// caller parsing stdout is unaffected.
	if result.AuditFailures > 0 {
		fmt.Fprintf(stderr, "\nAUDIT INCOMPLETE\n")
		for _, w := range result.Warnings {
			fmt.Fprintf(stderr, "  %s\n", w)
		}
		return 1
	}
	return 0
}

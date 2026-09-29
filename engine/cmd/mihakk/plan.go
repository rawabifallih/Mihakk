package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"mihakk/internal/mutate"
)

// planCmd inspects a mutation plan without sending anything. It exists so the
// determinism guarantee can be checked by hand: running it twice with the same
// corpus, seed and settings must print the same digests and the same cases.
func planCmd(args []string) int {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	corpusPath := fs.String("corpus", "", "path to the corpus JSON")
	openAPIPath := fs.String("openapi", "", "OpenAPI 3 document (JSON or YAML; a documented subset)")
	baseURL := fs.String("base-url", "", "base URL for the OpenAPI document")
	seed := fs.String("seed", "", "master seed (required; the same seed regenerates the same mutations)")
	perTarget := fs.Int("mutations-per-target", 0, "override mutations_per_target")
	maxValue := fs.Int("max-value-bytes", 0, "override max_value_bytes")
	show := fs.Int("show", -1, "print the full generated request for this case index")
	dumpAll := fs.Bool("dump", false, "print every case as one JSON object per line")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *seed == "" {
		fmt.Fprintln(os.Stderr, "mihakk: -seed is required")
		return 2
	}

	c, err := loadCorpus(sessionArgs{
		corpusPath: *corpusPath, openAPIPath: *openAPIPath, baseURL: *baseURL,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "mihakk: %v\n", err)
		return 1
	}

	cfg := mutate.DefaultConfig()
	if *perTarget > 0 {
		cfg.MutationsPerTarget = *perTarget
	}
	if *maxValue > 0 {
		cfg.MaxValueBytes = *maxValue
	}

	plan, err := mutate.NewPlan(c, cfg, Version, []byte(*seed))
	if err != nil {
		fmt.Fprintf(os.Stderr, "mihakk: %v\n", err)
		return 1
	}

	if *dumpAll {
		enc := json.NewEncoder(os.Stdout)
		for i := 0; i < plan.Total(); i++ {
			cse, err := plan.Case(i)
			if err != nil {
				fmt.Fprintf(os.Stderr, "mihakk: case %d: %v\n", i, err)
				return 1
			}
			if err := enc.Encode(json.RawMessage(cse.Canonical())); err != nil {
				fmt.Fprintf(os.Stderr, "mihakk: %v\n", err)
				return 1
			}
		}
		return 0
	}

	fmt.Printf("mutation plan\n")
	fmt.Printf("  engine version    : %s\n", plan.EngineVersion())
	fmt.Printf("  samples           : %d\n", len(c.Samples))
	fmt.Printf("  total cases       : %d\n", plan.Total())
	fmt.Printf("  corpus digest     : %s\n", plan.CorpusDigest())
	fmt.Printf("  config digest     : %s\n", plan.ConfigDigest())
	fmt.Printf("  derivation digest : %s\n", plan.DerivationDigest())
	fmt.Printf("\n  The derivation digest fixes the whole sequence. Same digest,\n")
	fmt.Printf("  same cases -- at any concurrency, in any process.\n")

	if *show >= 0 {
		cse, err := plan.Case(*show)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mihakk: %v\n", err)
			return 1
		}
		out, err := json.MarshalIndent(cse, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "mihakk: %v\n", err)
			return 1
		}
		fmt.Printf("\ncase %d:\n%s\n", *show, out)
	}
	return 0
}

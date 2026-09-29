package runner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The safety criterion for this phase is that requests can only leave through
// the guarded client. That is a property of the source, not of any one run: a
// single http.Get added later would bypass the scope check, the address
// pinning, the budget and the kill switch all at once, and no behavioural
// test would notice until something escaped.
//
// So it is asserted structurally. Every non-test file outside the safety
// package is parsed, and anything that can transmit is rejected.

// forbidden are the ways to originate an outbound request without going
// through safety.Client.
//
// The property being protected is that the engine only *sends* through the
// guarded client. Accepting connections is a different thing: the control API
// has to listen, and a listener cannot reach a target. So net.Listen,
// http.Server and the Serve functions are deliberately absent -- including
// them would have forced the control API to be written outside this check,
// which is the opposite of what the check is for.
var forbidden = map[string][]string{
	"http": {
		"Get", "Post", "PostForm", "Head",
		"DefaultClient", "DefaultTransport", "Client", "Transport",
	},
	"net":  {"Dial", "DialTimeout", "DialIP", "DialTCP", "DialUDP"},
	"tls":  {"Dial", "DialWithDialer", "Client"},
	"url":  {}, // parsing is fine
	"exec": {"Command", "CommandContext"},
}

// safetyPackage is the one place allowed to transmit.
const safetyPackage = "safety"

func TestOnlyTheSafetyPackageCanSendRequests(t *testing.T) {
	root := repoEngineRoot(t)

	var offences []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// testdata holds fixtures, not compiled code.
			if info.Name() == "testdata" || info.Name() == ".gocache" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// The guarded client itself must be able to do these things.
		if filepath.Base(filepath.Dir(path)) == safetyPackage {
			return nil
		}

		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}

		// Map import paths to the local name they are bound to, so an aliased
		// import cannot slip past a check that matches on the name.
		imports := map[string]string{}
		for _, spec := range file.Imports {
			importPath := strings.Trim(spec.Path.Value, `"`)
			name := importPath[strings.LastIndex(importPath, "/")+1:]
			if spec.Name != nil {
				name = spec.Name.Name
			}
			imports[name] = importPath
		}

		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			importPath, imported := imports[ident.Name]
			if !imported {
				return true
			}

			base := importPath[strings.LastIndex(importPath, "/")+1:]
			names, watched := forbidden[base]
			if !watched {
				return true
			}
			for _, forbiddenName := range names {
				if sel.Sel.Name == forbiddenName {
					rel, _ := filepath.Rel(root, path)
					offences = append(offences, rel+": "+ident.Name+"."+sel.Sel.Name+
						" — only the safety package may transmit")
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the source: %v", err)
	}

	if len(offences) > 0 {
		t.Fatalf("code outside the safety package can send requests directly:\n  %s",
			strings.Join(offences, "\n  "))
	}
}

// The test above is only meaningful if it would actually catch something, so
// this checks the detector against a file that does transmit.
func TestEnforcementTestWouldCatchADirectSend(t *testing.T) {
	dir := t.TempDir()
	offending := filepath.Join(dir, "sneaky.go")
	source := `package sneaky

import "net/http"

func Leak() { http.Get("http://example.invalid") }
`
	if err := os.WriteFile(offending, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, offending, nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "http" {
			for _, name := range forbidden["http"] {
				if sel.Sel.Name == name {
					found = true
				}
			}
		}
		return true
	})
	if !found {
		t.Fatal("the forbidden-call detector did not flag a plain http.Get; " +
			"the enforcement test above proves nothing")
	}
}

// repoEngineRoot finds the engine directory from the test's working directory.
func repoEngineRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the engine root (no go.mod above the test)")
	return ""
}

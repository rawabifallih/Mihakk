package store

// A session id becomes a directory name. Before these guards existed it was
// joined straight into a path, and filepath.Join cleans as it joins, so an id of
// "../../x" resolved outside the store: it was demonstrated to read a file there
// and to overwrite one.
//
// Three independent defences now stand between an id and the filesystem, and each
// is tested ON ITS OWN, with the other two out of the picture -- otherwise a test
// passes because a different guard caught the input, and says nothing about the
// one it claims to cover:
//
//	1. ValidSessionID -- an allowlist, tested by calling it directly.
//	2. containedIn    -- a lexical containment check, tested by calling it
//	                     directly with paths the allowlist would never pass.
//	3. os.Root        -- the rooted handle, tested by asking it for those same
//	                     paths, and by planting a symlink that is lexically
//	                     innocent so defences 1 and 2 both accept it.
//
// TestUnguardedJoinEscapes records why any of this is needed: it demonstrates the
// primitive the store used to call, and fails if that primitive ever stops being
// dangerous -- which would mean this file is testing the wrong thing.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// hostileIDs are ids that must never reach the filesystem.
var hostileIDs = []struct {
	name string
	id   string
}{
	{"parent traversal", "../../escaped"},
	{"single parent", "../escaped"},
	{"interior dot dot", "a/../../escaped"},
	{"bare dot dot", ".."},
	{"bare dot", "."},
	{"nested separator", "nested/child"},
	{"absolute path", "/etc/passwd"},
	{"backslash separator", `..\..\escaped`},
	{"leading dot", ".hidden"},
	{"leading dash", "-rf"},
	{"empty", ""},
	{"nul byte", "sess\x00ion"},
	{"newline", "sess\nion"},
	{"space", "sess ion"},
	{"colon", "sess:ion"},
	{"tilde", "~root"},
	{"too long", strings.Repeat("a", maxSessionIDLength+1)},
}

// validIDs must keep working. A guard that breaks ordinary use gets removed.
var validIDs = []string{
	"integration",
	"live-1790430000",
	"s20260926T140000Z",
	"a",
	"under_score",
	"dot.separated",
	"MixedCase123",
	strings.Repeat("a", maxSessionIDLength),
}

// --- defence 1, on its own --------------------------------------------------

func TestAllowlistRejectsHostileIDs(t *testing.T) {
	for _, tc := range hostileIDs {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidSessionID(tc.id)
			if err == nil {
				t.Fatalf("ValidSessionID(%q) accepted a hostile id", tc.id)
			}
			if !errors.Is(err, ErrInvalidSessionID) {
				t.Errorf("error should wrap ErrInvalidSessionID, got %v", err)
			}
		})
	}
}

func TestAllowlistAcceptsOrdinaryIDs(t *testing.T) {
	for _, id := range validIDs {
		if err := ValidSessionID(id); err != nil {
			t.Errorf("ValidSessionID(%q) rejected an ordinary id: %v", id, err)
		}
	}
}

// --- defence 2, on its own -------------------------------------------------
// Called directly, so the allowlist is not in the way. These are the paths that
// would exist if defence 1 were ever loosened.

func TestContainmentRejectsEscapingPathsWithoutTheAllowlist(t *testing.T) {
	sessions := filepath.Join(t.TempDir(), "store", "sessions")

	for _, tc := range []struct {
		name string
		path string
	}{
		{"one level up", filepath.Join(sessions, "..", "escaped")},
		{"two levels up", filepath.Join(sessions, "..", "..", "escaped")},
		{"the sessions directory itself", sessions},
		{"a sibling with a shared prefix", sessions + "-evil"},
		{"an unrelated absolute path", "/etc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := containedIn(sessions, tc.path); err == nil {
				t.Fatalf("containedIn(%q, %q) accepted a path outside the directory",
					sessions, tc.path)
			}
		})
	}
}

func TestContainmentAcceptsPathsInside(t *testing.T) {
	sessions := filepath.Join(t.TempDir(), "store", "sessions")
	for _, id := range validIDs {
		p := filepath.Join(sessions, id)
		if err := containedIn(sessions, p); err != nil {
			t.Errorf("containedIn rejected %q, which is inside: %v", p, err)
		}
	}
}

// --- defence 3, on its own -------------------------------------------------

func TestRootedHandleRefusesEscapingPaths(t *testing.T) {
	base := t.TempDir()
	st := openStore(t, filepath.Join(base, "store"))

	if err := os.WriteFile(filepath.Join(base, "outside.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	for _, rel := range []string{
		"../outside.json",
		"../../outside.json",
		"a/../../outside.json",
	} {
		if _, err := st.readFile(rel); err == nil {
			t.Errorf("the rooted handle read %q from outside its root", rel)
		}
		if err := st.writeFile(rel, []byte("x")); err == nil {
			t.Errorf("the rooted handle wrote %q outside its root", rel)
		}
	}
}

// The case defences 1 and 2 cannot catch: a lexically innocent id pointing at a
// symlink that leaves the root. Both of them accept "linked"; only the rooted
// handle refuses to follow it.
func TestSymlinkCannotCarryReadsOrWritesOutsideTheRoot(t *testing.T) {
	base := t.TempDir()
	storeDir := filepath.Join(base, "store")
	st := openStore(t, storeDir)

	outside := filepath.Join(base, "elsewhere")
	if err := os.MkdirAll(outside, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	victim := filepath.Join(outside, "session.json")
	const original = `{"session_id":"victim","status":"OUTSIDE THE ROOT"}`
	if err := os.WriteFile(victim, []byte(original), 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "cases.jsonl"),
		[]byte(`{"case_id":"victim-000001","session_id":"victim","status":"OUTSIDE"}`+"\n"),
		0o600); err != nil {
		t.Fatalf("write victim cases: %v", err)
	}

	// The id itself is clean, and both earlier defences say so.
	const id = "linked"
	if err := ValidSessionID(id); err != nil {
		t.Fatalf("precondition: %q should pass the allowlist: %v", id, err)
	}
	if err := st.checkSessionID(id); err != nil {
		t.Fatalf("precondition: %q should pass containment: %v", id, err)
	}
	dir := filepath.Join(storeDir, "sessions", id)
	if err := os.Symlink(outside, dir); err != nil {
		t.Skipf("this filesystem does not support symlinks: %v", err)
	}

	if sess, err := st.LoadSession(id); err == nil {
		t.Errorf("LoadSession followed a symlink out of the root and read status %q", sess.Status)
	}
	if cases, err := st.Cases(id); err == nil && len(cases) > 0 {
		t.Errorf("Cases followed a symlink out of the root and read %d case(s)", len(cases))
	}

	if err := st.SaveSession(&Session{
		SessionID: id, EngineVersion: "test",
		StartedAt: time.Now(), Status: "WRITTEN THROUGH THE SYMLINK",
	}); err == nil {
		t.Errorf("SaveSession wrote through a symlink out of the root")
	}

	after, readErr := os.ReadFile(victim)
	if readErr != nil {
		t.Fatalf("reading victim back: %v", readErr)
	}
	if string(after) != original {
		t.Errorf("a file outside the root was modified:\nbefore %s\nafter  %s", original, after)
	}
}

// --- the store's own surface ------------------------------------------------

func TestStoreRefusesHostileSessionIDs(t *testing.T) {
	st := openStore(t, filepath.Join(t.TempDir(), "store"))

	for _, tc := range hostileIDs {
		t.Run(tc.name, func(t *testing.T) {
			if err := st.SaveSession(&Session{SessionID: tc.id, StartedAt: time.Now()}); err == nil {
				t.Errorf("SaveSession accepted %q", tc.id)
			}
			if _, err := st.LoadSession(tc.id); err == nil {
				t.Errorf("LoadSession accepted %q", tc.id)
			}
			if _, err := st.Cases(tc.id); err == nil {
				t.Errorf("Cases accepted %q", tc.id)
			}
			if err := st.AppendCase(&Case{SessionID: tc.id, CaseID: tc.id + "-000001"}); err == nil {
				t.Errorf("AppendCase accepted %q", tc.id)
			}
		})
	}
}

func TestNothingOutsideTheRootIsTouched(t *testing.T) {
	base := t.TempDir()
	st := openStore(t, filepath.Join(base, "store"))

	// Files a hostile id would aim at, planted before the attempt.
	targets := map[string]string{
		filepath.Join(base, "escaped"):               `{"status":"PRE-EXISTING A"}`,
		filepath.Join(base, "victim"):                `{"status":"PRE-EXISTING B"}`,
		filepath.Join(base, "store", "session.json"): `{"status":"PRE-EXISTING C"}`,
	}
	for path, body := range targets {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	for _, tc := range hostileIDs {
		_ = st.SaveSession(&Session{SessionID: tc.id, StartedAt: time.Now(), Status: "ATTEMPT"})
		_ = st.AppendCase(&Case{SessionID: tc.id, CaseID: tc.id + "-000001"})
		_, _ = st.LoadSession(tc.id)
		_, _ = st.Cases(tc.id)
		_, _, _ = st.FindCase(tc.id + "-000001")
	}

	for path, body := range targets {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("a pre-existing file disappeared: %s: %v", path, err)
			continue
		}
		if string(got) != body {
			t.Errorf("a pre-existing file outside the sessions root changed:\n%s\nbefore %s\nafter  %s",
				path, body, got)
		}
	}
}

func TestOrdinarySessionsStillRoundTrip(t *testing.T) {
	st := openStore(t, filepath.Join(t.TempDir(), "store"))

	for _, id := range validIDs {
		sess := &Session{SessionID: id, EngineVersion: "test",
			StartedAt: time.Now(), Status: "completed", SavedCases: 1}
		if err := st.SaveSession(sess); err != nil {
			t.Fatalf("SaveSession(%q): %v", id, err)
		}
		if err := st.AppendCase(&Case{
			CaseID: CaseID(id, 1), SessionID: id,
			Indicators: nil, Status: StatusNeedsVerification,
		}); err != nil {
			t.Fatalf("AppendCase(%q): %v", id, err)
		}

		back, err := st.LoadSession(id)
		if err != nil {
			t.Fatalf("LoadSession(%q): %v", id, err)
		}
		if back.SessionID != id || back.Status != "completed" {
			t.Errorf("round trip changed the record: %+v", back)
		}
		cases, err := st.Cases(id)
		if err != nil || len(cases) != 1 {
			t.Fatalf("Cases(%q) = %d, %v", id, len(cases), err)
		}
		if _, _, err := st.FindCase(CaseID(id, 1)); err != nil {
			t.Errorf("FindCase(%q): %v", CaseID(id, 1), err)
		}
	}

	ids, err := st.Sessions()
	if err != nil {
		t.Fatalf("Sessions: %v", err)
	}
	if len(ids) != len(validIDs) {
		t.Errorf("Sessions listed %d of %d", len(ids), len(validIDs))
	}
}

// --- case ids ---------------------------------------------------------------

func TestParseCaseIDRejectsHostileSessionHalves(t *testing.T) {
	for _, tc := range hostileIDs {
		if tc.id == "" {
			continue // "-000001" has no session half to speak of
		}
		caseID := tc.id + "-000001"
		if _, _, err := ParseCaseID(caseID); err == nil {
			t.Errorf("ParseCaseID(%q) accepted a hostile session half", caseID)
		}
	}
}

func TestParseCaseIDStillAcceptsRealOnes(t *testing.T) {
	for _, id := range validIDs {
		caseID := CaseID(id, 42)
		gotID, gotIndex, err := ParseCaseID(caseID)
		if err != nil {
			t.Errorf("ParseCaseID(%q): %v", caseID, err)
			continue
		}
		if gotID != id || gotIndex != 42 {
			t.Errorf("ParseCaseID(%q) = %q, %d", caseID, gotID, gotIndex)
		}
	}
}

// --- a symlink is not a session --------------------------------------------

func TestSessionsSkipsSymlinksAndInvalidNames(t *testing.T) {
	base := t.TempDir()
	storeDir := filepath.Join(base, "store")
	st := openStore(t, storeDir)

	if err := st.SaveSession(&Session{SessionID: "real", StartedAt: time.Now()}); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	outside := filepath.Join(base, "elsewhere")
	if err := os.MkdirAll(outside, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	sessions := filepath.Join(storeDir, "sessions")
	if err := os.Symlink(outside, filepath.Join(sessions, "linked")); err != nil {
		t.Skipf("no symlink support: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(sessions, ".hidden"), 0o750); err != nil {
		t.Fatalf("mkdir hidden: %v", err)
	}

	ids, err := st.Sessions()
	if err != nil {
		t.Fatalf("Sessions: %v", err)
	}
	for _, id := range ids {
		if id == "linked" {
			t.Error("Sessions listed a symlink as a session")
		}
		if id == ".hidden" {
			t.Error("Sessions listed a name the allowlist refuses")
		}
	}
	if len(ids) != 1 || ids[0] != "real" {
		t.Errorf("Sessions = %v, want [real]", ids)
	}
}

// --- why the guards exist ---------------------------------------------------

// The primitive the store used to call, kept as a live demonstration. If this
// ever stops escaping, the guards above are testing something that no longer
// matters and this file should be revisited.
func TestUnguardedJoinEscapes(t *testing.T) {
	sessions := filepath.Join(t.TempDir(), "store", "sessions")

	escaping := 0
	for _, tc := range hostileIDs {
		joined := filepath.Join(sessions, tc.id) // what the code did before
		if containedIn(sessions, joined) != nil {
			escaping++
			t.Logf("unguarded: id %-20q -> %s", tc.id, joined)
		}
	}
	if escaping == 0 {
		t.Fatal("no hostile id escapes an unguarded join; these tests no longer guard anything")
	}
	t.Logf("%d of %d hostile ids escape an unguarded join", escaping, len(hostileIDs))
}

func openStore(t *testing.T, dir string) *Store {
	t.Helper()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("Open(%q): %v", dir, err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// --- the limit of the protection -------------------------------------------

// What is protected is everything BENEATH the sessions directory. The directory
// itself is trusted: it is the path the operator configured with -data, and
// os.OpenRoot resolves it once, when the store opens. If that path is itself a
// symlink, the store works inside its target.
//
// This is recorded as a test rather than left as a claim in prose, so the
// boundary is explicit and a future change that narrows it will show up here.
//
// It is not a traversal: no caller-supplied id is involved, and a person who can
// replace the data directory can read and write its contents anyway. The engine
// runs with /data as a volume owned by its own unprivileged user.
func TestTheSessionsRootItselfIsTrusted(t *testing.T) {
	base := t.TempDir()
	realData := filepath.Join(base, "real-data")
	if err := os.MkdirAll(realData, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// -data points at a symlink to somewhere else.
	linkedData := filepath.Join(base, "linked-data")
	if err := os.Symlink(realData, linkedData); err != nil {
		t.Skipf("no symlink support: %v", err)
	}

	st := openStore(t, linkedData)
	if err := st.SaveSession(&Session{SessionID: "ordinary",
		StartedAt: time.Now(), Status: "completed"}); err != nil {
		t.Fatalf("SaveSession through a symlinked data dir: %v", err)
	}

	// The write landed in the symlink's target, as configured.
	if _, err := os.Stat(filepath.Join(realData, "sessions", "ordinary", "session.json")); err != nil {
		t.Errorf("the session was not written into the configured directory: %v", err)
	}

	// And a hostile id still cannot leave it.
	if err := st.SaveSession(&Session{SessionID: "../../escaped",
		StartedAt: time.Now()}); err == nil {
		t.Error("a traversing id was accepted inside a symlinked data directory")
	}
	if _, err := os.Stat(filepath.Join(base, "escaped")); err == nil {
		t.Error("a traversing id escaped a symlinked data directory")
	}
}

// Swapping <data>/sessions for a symlink AFTER the store has opened must not
// change what the store works on.
//
// This is the slip that made the rule worth stating: the session listing read the
// directory by path while every other operation used the handle. A path is
// resolved afresh on each use, so a directory swapped underneath it is followed;
// a descriptor is not. Either outcome is acceptable here -- the listing keeps
// reading the directory the handle pinned, or it fails outright -- but it must
// never report names from the directory the path now points at.
func TestSessionsIsNotFooledByASwappedDirectory(t *testing.T) {
	base := t.TempDir()
	storeDir := filepath.Join(base, "store")
	st := openStore(t, storeDir)

	if err := st.SaveSession(&Session{SessionID: "real",
		StartedAt: time.Now(), Status: "completed"}); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	// Somewhere else, holding a plausible-looking session directory.
	elsewhere := filepath.Join(base, "elsewhere")
	if err := os.MkdirAll(filepath.Join(elsewhere, "intruder"), 0o750); err != nil {
		t.Fatalf("mkdir elsewhere: %v", err)
	}
	if err := os.WriteFile(filepath.Join(elsewhere, "intruder", "session.json"),
		[]byte(`{"session_id":"intruder","status":"FROM OUTSIDE"}`), 0o600); err != nil {
		t.Fatalf("write intruder: %v", err)
	}

	// The swap: move the real directory aside and put a symlink in its place.
	sessions := filepath.Join(storeDir, "sessions")
	if err := os.Rename(sessions, sessions+".moved"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := os.Symlink(elsewhere, sessions); err != nil {
		t.Skipf("no symlink support: %v", err)
	}

	ids, err := st.Sessions()
	if err != nil {
		t.Logf("Sessions failed outright after the swap, which is acceptable: %v", err)
		return
	}
	for _, id := range ids {
		if id == "intruder" {
			t.Errorf("Sessions listed %q from the swapped-in directory; it read by path, not by handle", id)
		}
	}
	// Reading the pinned directory is the other acceptable outcome.
	if len(ids) != 1 || ids[0] != "real" {
		t.Errorf("Sessions = %v; want [real] from the pinned directory, or an error", ids)
	}

	// And the rest of the store is unaffected, which is the asymmetry that made
	// the listing's use of a path a real inconsistency rather than a style point.
	if sess, err := st.LoadSession("real"); err != nil {
		t.Errorf("LoadSession after the swap: %v", err)
	} else if sess.Status != "completed" {
		t.Errorf("LoadSession read the wrong record: %+v", sess)
	}
	if _, err := st.LoadSession("intruder"); err == nil {
		t.Error("LoadSession read a record from the swapped-in directory")
	}
}

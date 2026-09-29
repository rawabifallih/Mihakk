package aggregate

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"mihakk/internal/store"
)

// A session written before the accounting existed must come out as "not
// counted": accounting: null in the document. A zero there would read as a
// count -- nothing refused, nothing unanswered -- for a run nobody counted.

func accountingOf(t *testing.T, sess *store.Session) json.RawMessage {
	t.Helper()
	doc, err := Build(sess, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var shape struct {
		Session map[string]json.RawMessage `json:"session"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil {
		t.Fatal(err)
	}
	value, present := shape.Session["accounting"]
	if !present {
		t.Fatal("the document has no accounting key at all; a reader cannot tell absent from forgotten")
	}
	return value
}

func TestASessionFromBeforeTheCountIsNullNotZero(t *testing.T) {
	// The record exactly as an older engine wrote it: saved, then read back,
	// through the store, with no accounting key in the file.
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sess := sessionFixture(0)
	sess.Accounting = nil
	if err := st.SaveSession(sess); err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(filepath.Join(dir, "sessions", sess.SessionID, "session.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(onDisk, []byte("accounting")) {
		t.Fatal("the legacy fixture carries an accounting key; it would not be legacy")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	// A new Store is the engine after a restart, not merely another read through
	// the handle that wrote the fixture.
	restarted, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	loaded, err := restarted.LoadSession(sess.SessionID)
	if err != nil {
		t.Fatal(err)
	}

	if got := string(accountingOf(t, loaded)); got != "null" {
		t.Fatalf("accounting for an uncounted session is %s; want null", got)
	}
}

func TestACountedSessionCarriesItsCountsIncludingZeros(t *testing.T) {
	sess := sessionFixture(0)
	sess.Accounting = &store.Accounting{BaselineAttempted: 3, BaselineAnswered: 3, HTTPAnswered: 3}
	var got store.Accounting
	if err := json.Unmarshal(accountingOf(t, sess), &got); err != nil {
		t.Fatalf("accounting is not an object: %v", err)
	}
	if got != *sess.Accounting {
		t.Fatalf("accounting %+v; want %+v", got, *sess.Accounting)
	}
}

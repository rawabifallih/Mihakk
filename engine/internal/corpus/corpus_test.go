package corpus

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const goodCorpus = `{
  "corpus_version": "1",
  "samples": [
    {
      "id": "b-second",
      "method": "post",
      "url": "http://testbed:8000/api/orders",
      "headers": {"content-type": ["application/json"]},
      "body": "{\"qty\":1}"
    },
    {
      "id": "a-first",
      "method": "GET",
      "url": "http://testbed:8000/api/items?page=1",
      "headers": {"ACCEPT": ["application/json"]}
    }
  ]
}`

func TestParseCanonicalisesSamples(t *testing.T) {
	c, err := Parse([]byte(goodCorpus))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Samples[0].ID != "a-first" || c.Samples[1].ID != "b-second" {
		t.Fatalf("samples were not sorted by id: %s, %s", c.Samples[0].ID, c.Samples[1].ID)
	}
	if c.Samples[1].Method != "POST" {
		t.Errorf("method = %q, want POST", c.Samples[1].Method)
	}
	if _, ok := c.Samples[0].Headers["Accept"]; !ok {
		t.Errorf("header name was not canonicalised: %v", c.Samples[0].Headers)
	}
}

// Ordering and spelling must not move the digest; content must.
func TestDigestIsCanonicalButContentSensitive(t *testing.T) {
	a, err := Parse([]byte(goodCorpus))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	reordered := `{
  "corpus_version": "1",
  "samples": [
    {
      "id": "a-first",
      "method": "get",
      "url": "http://testbed:8000/api/items?page=1",
      "headers": {"Accept": ["application/json"]}
    },
    {
      "id": "b-second",
      "method": "POST",
      "url": "http://testbed:8000/api/orders",
      "headers": {"Content-Type": ["application/json"]},
      "body": "{\"qty\":1}"
    }
  ]
}`
	b, err := Parse([]byte(reordered))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if a.Digest() != b.Digest() {
		t.Fatalf("equivalent corpora produced different digests:\n a=%s\n b=%s", a.Digest(), b.Digest())
	}

	changed, _ := Parse([]byte(goodCorpus))
	changed.Samples[0].URL = "http://testbed:8000/api/items?page=2"
	if changed.Digest() == a.Digest() {
		t.Fatal("changing a sample url did not change the digest")
	}
}

func TestValidateRejectsUnusableSamples(t *testing.T) {
	cases := map[string]string{
		"no samples":        `{"corpus_version":"1","samples":[]}`,
		"empty id":          `{"corpus_version":"1","samples":[{"id":"","method":"GET","url":"http://t:1/a"}]}`,
		"duplicate id":      `{"corpus_version":"1","samples":[{"id":"x","method":"GET","url":"http://t:1/a"},{"id":"x","method":"GET","url":"http://t:1/b"}]}`,
		"no method":         `{"corpus_version":"1","samples":[{"id":"x","method":"","url":"http://t:1/a"}]}`,
		"relative url":      `{"corpus_version":"1","samples":[{"id":"x","method":"GET","url":"/api/items"}]}`,
		"non-http scheme":   `{"corpus_version":"1","samples":[{"id":"x","method":"GET","url":"ftp://t:1/a"}]}`,
		"url credentials":   `{"corpus_version":"1","samples":[{"id":"x","method":"GET","url":"http://u:p@t:1/a"}]}`,
		"bad body encoding": `{"corpus_version":"1","samples":[{"id":"x","method":"GET","url":"http://t:1/a","body":"zz","body_encoding":"rot13"}]}`,
		"bad base64":        `{"corpus_version":"1","samples":[{"id":"x","method":"GET","url":"http://t:1/a","body":"not base64!!","body_encoding":"base64"}]}`,
		"wrong version":     `{"corpus_version":"9","samples":[{"id":"x","method":"GET","url":"http://t:1/a"}]}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(raw)); !errors.Is(err, ErrInvalidCorpus) {
				t.Fatalf("Parse = %v, want ErrInvalidCorpus", err)
			}
		})
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	raw := `{"corpus_version":"1","samples":[{"id":"x","method":"GET","url":"http://t:1/a","surprise":true}]}`
	if _, err := Parse([]byte(raw)); !errors.Is(err, ErrInvalidCorpus) {
		t.Fatalf("Parse = %v, want ErrInvalidCorpus", err)
	}
}

func TestBodyKindClassification(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
		body        string
		want        BodyKind
	}{
		{"no body", "application/json", "", BodyNone},
		{"json by content type", "application/json", `{"a":1}`, BodyJSON},
		{"form by content type", "application/x-www-form-urlencoded", "a=1&b=2", BodyForm},
		{"raw by content type", "application/octet-stream", "binary-ish", BodyRaw},
		{"json by sniffing", "", `{"a":1}`, BodyJSON},
		{"raw when unsniffable", "", "not json at all", BodyRaw},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := Sample{ID: "x", Method: "POST", URL: "http://t:1/a", Body: tc.body}
			if tc.contentType != "" {
				s.Headers = map[string][]string{"Content-Type": {tc.contentType}}
			}
			if got := s.BodyKind(); got != tc.want {
				t.Fatalf("BodyKind() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestContentTypeIgnoresParameters(t *testing.T) {
	s := Sample{Headers: map[string][]string{"Content-Type": {"application/json; charset=utf-8"}}}
	if got := s.ContentType(); got != "application/json" {
		t.Fatalf("ContentType() = %q, want application/json", got)
	}
}

func TestDecodedBodyHandlesBase64(t *testing.T) {
	s := Sample{Body: "cmF3LWJpbmFyeS1wYXlsb2Fk", BodyEncoding: "base64"}
	got, err := s.DecodedBody()
	if err != nil {
		t.Fatalf("DecodedBody: %v", err)
	}
	if string(got) != "raw-binary-payload" {
		t.Fatalf("DecodedBody() = %q", got)
	}

	plain := Sample{Body: "hello"}
	got, err = plain.DecodedBody()
	if err != nil || string(got) != "hello" {
		t.Fatalf("DecodedBody() = (%q, %v)", got, err)
	}
}

func TestHeaderNamesAreSorted(t *testing.T) {
	s := Sample{Headers: map[string][]string{
		"Z-Last": {"1"}, "Accept": {"2"}, "M-Middle": {"3"},
	}}
	got := s.HeaderNames()
	want := []string{"Accept", "M-Middle", "Z-Last"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("HeaderNames() = %v, want %v", got, want)
		}
	}
}

func TestLoadReadsFromDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corpus.json")
	if err := os.WriteFile(path, []byte(goodCorpus), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.Samples) != 2 {
		t.Fatalf("loaded %d samples, want 2", len(c.Samples))
	}

	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("Load of a missing file returned no error")
	}
}

func TestFind(t *testing.T) {
	c, err := Parse([]byte(goodCorpus))
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.Find("a-first")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if s.ID != "a-first" {
		t.Fatalf("Find returned %q", s.ID)
	}
	if _, err := c.Find("nope"); !errors.Is(err, ErrNoSuchSample) {
		t.Fatalf("Find(missing) = %v, want ErrNoSuchSample", err)
	}
}

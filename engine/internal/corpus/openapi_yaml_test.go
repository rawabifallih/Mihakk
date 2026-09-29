package corpus

import (
	"errors"
	"strings"
	"testing"
)

// The same document, written both ways. Every construct the subset supports
// appears in both: parameters in all three locations, a path-level parameter,
// a request body, and a local $ref.
const equivalentYAMLDoc = `
openapi: "3.0.3"
servers:
  - url: http://testbed:8000
paths:
  /api/items:
    get:
      operationId: listItems
      parameters:
        - name: page
          in: query
          schema:
            type: integer
        - name: q
          in: query
          schema:
            type: string
            example: shoes
        - name: X-Trace
          in: header
          schema:
            type: string
  /api/orders/{orderId}:
    parameters:
      - name: orderId
        in: path
        required: true
        schema:
          type: integer
    get: {}
    post:
      operationId: createOrder
      requestBody:
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/Order"
components:
  schemas:
    Order:
      type: object
      properties:
        sku:
          type: string
          example: A-001
        qty:
          type: integer
          default: 2
        express:
          type: boolean
`

// The two formats must reach the parser as the same document, so the corpus
// they produce is identical down to the digest. Anything less would mean a
// case index recorded from a JSON run pointed somewhere else after the same
// spec was re-saved as YAML.
func TestJSONAndYAMLProduceTheSameCorpus(t *testing.T) {
	fromJSON, err := LoadOpenAPI([]byte(minimalDoc), "")
	if err != nil {
		t.Fatalf("LoadOpenAPI(json): %v", err)
	}
	fromYAML, err := LoadOpenAPI([]byte(equivalentYAMLDoc), "")
	if err != nil {
		t.Fatalf("LoadOpenAPI(yaml): %v", err)
	}

	if len(fromYAML.Skipped) != 0 {
		t.Fatalf("the YAML document skipped operations: %+v", fromYAML.Skipped)
	}
	if got, want := len(fromYAML.Corpus.Samples), len(fromJSON.Corpus.Samples); got != want {
		t.Fatalf("YAML produced %d samples, JSON produced %d", got, want)
	}

	for i := range fromJSON.Corpus.Samples {
		j, y := fromJSON.Corpus.Samples[i], fromYAML.Corpus.Samples[i]
		if j.ID != y.ID {
			t.Errorf("sample %d: id %q (json) vs %q (yaml)", i, j.ID, y.ID)
		}
		if j.Method != y.Method {
			t.Errorf("sample %s: method %q vs %q", j.ID, j.Method, y.Method)
		}
		if j.URL != y.URL {
			t.Errorf("sample %s: url\n  json: %s\n  yaml: %s", j.ID, j.URL, y.URL)
		}
		if j.Body != y.Body {
			t.Errorf("sample %s: body\n  json: %s\n  yaml: %s", j.ID, j.Body, y.Body)
		}
		for _, name := range j.HeaderNames() {
			if strings.Join(j.Headers[name], ",") != strings.Join(y.Headers[name], ",") {
				t.Errorf("sample %s: header %s differs: %v vs %v",
					j.ID, name, j.Headers[name], y.Headers[name])
			}
		}
	}

	if fromJSON.Corpus.Digest() != fromYAML.Corpus.Digest() {
		t.Fatalf("the two formats produced different corpus digests:\n json: %s\n yaml: %s",
			fromJSON.Corpus.Digest(), fromYAML.Corpus.Digest())
	}
	t.Logf("both formats produced %s", fromJSON.Corpus.Digest())
}

// The YAML conversion itself must be stable: Go map iteration is randomised,
// so a converter that walked maps without imposing an order would produce a
// different corpus on every parse.
func TestYAMLConversionIsDeterministic(t *testing.T) {
	first, err := LoadOpenAPI([]byte(equivalentYAMLDoc), "")
	if err != nil {
		t.Fatal(err)
	}
	want := first.Corpus.Digest()

	for i := 0; i < 100; i++ {
		again, err := LoadOpenAPI([]byte(equivalentYAMLDoc), "")
		if err != nil {
			t.Fatal(err)
		}
		if got := again.Corpus.Digest(); got != want {
			t.Fatalf("parse %d produced a different digest: %s != %s", i, got, want)
		}
		for j := range again.Corpus.Samples {
			if again.Corpus.Samples[j].URL != first.Corpus.Samples[j].URL {
				t.Fatalf("parse %d produced a different url for sample %s",
					i, again.Corpus.Samples[j].ID)
			}
		}
	}
}

// Converting YAML to the internal representation must not change values.
func TestYAMLScalarsSurviveTheConversion(t *testing.T) {
	doc := `
openapi: "3.0.0"
servers:
  - url: http://testbed:8000
paths:
  /api/x:
    post:
      operationId: scalars
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                count:
                  type: integer
                  default: 42
                ratio:
                  type: number
                  default: 1.5
                enabled:
                  type: boolean
                  default: true
                label:
                  type: string
                  default: "on"
`
	result, err := LoadOpenAPI([]byte(doc), "")
	if err != nil {
		t.Fatalf("LoadOpenAPI: %v", err)
	}
	body := result.Corpus.Samples[0].Body
	for _, want := range []string{`"count":42`, `"ratio":1.5`, `"enabled":true`, `"label":"on"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the body lost %s: %s", want, body)
		}
	}
	// "on" is a YAML 1.1 boolean; quoted, it must stay a string.
	if strings.Contains(body, `"label":true`) {
		t.Errorf("a quoted string was coerced to a boolean: %s", body)
	}
}

// The subset must not widen just because the document is YAML.
func TestYAMLIsHeldToTheSameSubset(t *testing.T) {
	doc := `
openapi: "3.0.0"
servers:
  - url: http://testbed:8000
paths:
  /api/ok:
    get:
      operationId: ok
  /api/odd:
    post:
      operationId: odd
      requestBody:
        content:
          application/json:
            schema:
              oneOf:
                - type: string
`
	result, err := LoadOpenAPI([]byte(doc), "")
	if err != nil {
		t.Fatalf("LoadOpenAPI: %v", err)
	}
	if len(result.Skipped) != 1 || !strings.Contains(result.Skipped[0].Reason, "oneOf") {
		t.Fatalf("oneOf was not refused in YAML: %+v", result.Skipped)
	}
}

func TestMalformedYAMLIsRejectedClearly(t *testing.T) {
	for name, doc := range map[string]string{
		"not a mapping":  "- just\n- a\n- list\n",
		"broken syntax":  "openapi: \"3.0.0\"\npaths:\n  - : :\n   bad\n",
		"empty document": "   \n\n",
		"plain scalar":   "just a string\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadOpenAPI([]byte(doc), "http://testbed:8000")
			if !errors.Is(err, ErrInvalidCorpus) {
				t.Fatalf("LoadOpenAPI = %v, want ErrInvalidCorpus", err)
			}
		})
	}
}

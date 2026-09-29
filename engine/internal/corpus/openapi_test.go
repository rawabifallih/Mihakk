package corpus

import (
	"errors"
	"strings"
	"testing"
)

const minimalDoc = `{
  "openapi": "3.0.3",
  "servers": [{"url": "http://testbed:8000"}],
  "paths": {
    "/api/items": {
      "get": {
        "operationId": "listItems",
        "parameters": [
          {"name": "page", "in": "query", "schema": {"type": "integer"}},
          {"name": "q", "in": "query", "schema": {"type": "string", "example": "shoes"}},
          {"name": "X-Trace", "in": "header", "schema": {"type": "string"}}
        ]
      }
    },
    "/api/orders/{orderId}": {
      "parameters": [
        {"name": "orderId", "in": "path", "required": true, "schema": {"type": "integer"}}
      ],
      "get": {},
      "post": {
        "operationId": "createOrder",
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {"$ref": "#/components/schemas/Order"}
            }
          }
        }
      }
    }
  },
  "components": {
    "schemas": {
      "Order": {
        "type": "object",
        "properties": {
          "sku": {"type": "string", "example": "A-001"},
          "qty": {"type": "integer", "default": 2},
          "express": {"type": "boolean"}
        }
      }
    }
  }
}`

func TestLoadOpenAPIBuildsASampleForEachOperation(t *testing.T) {
	result, err := LoadOpenAPI([]byte(minimalDoc), "")
	if err != nil {
		t.Fatalf("LoadOpenAPI: %v", err)
	}
	if len(result.Skipped) != 0 {
		t.Fatalf("operations were skipped unexpectedly: %+v", result.Skipped)
	}
	if got := len(result.Corpus.Samples); got != 3 {
		t.Fatalf("got %d samples, want 3", got)
	}

	byID := map[string]*Sample{}
	for i := range result.Corpus.Samples {
		byID[result.Corpus.Samples[i].ID] = &result.Corpus.Samples[i]
	}

	items := byID["listItems"]
	if items == nil {
		t.Fatal("the operationId was not used as the sample id")
	}
	if !strings.Contains(items.URL, "q=shoes") {
		t.Errorf("the example value was not used: %s", items.URL)
	}
	if !strings.Contains(items.URL, "page=1") {
		t.Errorf("no placeholder for the integer parameter: %s", items.URL)
	}
	if _, ok := items.Headers["X-Trace"]; !ok {
		t.Errorf("the header parameter was not carried over: %v", items.Headers)
	}

	order := byID["createOrder"]
	if order == nil {
		t.Fatal("the request-body operation produced no sample")
	}
	if !strings.Contains(order.Body, `"sku":"A-001"`) {
		t.Errorf("the local $ref was not resolved into a body: %s", order.Body)
	}
	if !strings.Contains(order.Body, `"qty":2`) {
		t.Errorf("the schema default was not used: %s", order.Body)
	}
	if order.ContentType() != "application/json" {
		t.Errorf("content type = %q", order.ContentType())
	}

	// The shared path-level parameter must reach both operations on that path.
	for _, id := range []string{"createOrder", "get-api-orders-orderId"} {
		s := byID[id]
		if s == nil {
			t.Fatalf("no sample %q; path-level parameters were not shared", id)
		}
		if !strings.Contains(s.URL, "/api/orders/1") {
			t.Errorf("sample %s did not use the shared path parameter: %s", id, s.URL)
		}
	}

	// The path template must be filled in, never sent literally.
	for _, s := range result.Corpus.Samples {
		if strings.Contains(s.URL, "{") {
			t.Errorf("sample %s still has an unfilled path template: %s", s.ID, s.URL)
		}
	}
}

func TestLoadOpenAPIIsDeterministic(t *testing.T) {
	first, err := LoadOpenAPI([]byte(minimalDoc), "")
	if err != nil {
		t.Fatal(err)
	}
	want := first.Corpus.Digest()
	for i := 0; i < 50; i++ {
		again, err := LoadOpenAPI([]byte(minimalDoc), "")
		if err != nil {
			t.Fatal(err)
		}
		if got := again.Corpus.Digest(); got != want {
			t.Fatalf("parse %d produced a different corpus digest: %s != %s", i, got, want)
		}
	}
}

// Everything outside the documented subset must be named, not silently
// dropped and not quietly widened.
func TestLoadOpenAPISkipsWhatIsOutsideTheSubset(t *testing.T) {
	cases := map[string]string{
		"oneOf":         `{"oneOf": [{"type": "string"}]}`,
		"anyOf":         `{"anyOf": [{"type": "string"}]}`,
		"allOf":         `{"allOf": [{"type": "string"}]}`,
		"external $ref": `{"$ref": "https://example.invalid/schemas/Thing.json"}`,
		"relative $ref": `{"$ref": "./other.json#/Thing"}`,
	}
	for name, schema := range cases {
		t.Run(name, func(t *testing.T) {
			doc := `{
  "openapi": "3.0.0",
  "servers": [{"url": "http://testbed:8000"}],
  "paths": {
    "/api/ok": {"get": {"operationId": "ok"}},
    "/api/odd": {"post": {"operationId": "odd", "requestBody": {"content":
      {"application/json": {"schema": ` + schema + `}}}}}
  }
}`
			result, err := LoadOpenAPI([]byte(doc), "")
			if err != nil {
				t.Fatalf("LoadOpenAPI: %v", err)
			}
			if len(result.Skipped) != 1 {
				t.Fatalf("expected exactly one skipped operation, got %+v", result.Skipped)
			}
			if result.Skipped[0].Path != "/api/odd" {
				t.Errorf("the wrong operation was skipped: %+v", result.Skipped[0])
			}
			if result.Skipped[0].Reason == "" {
				t.Error("the skipped operation has no reason")
			}
			// The usable operation is still there.
			if len(result.Corpus.Samples) != 1 {
				t.Errorf("got %d samples, want the one usable operation", len(result.Corpus.Samples))
			}
		})
	}
}

func TestLoadOpenAPISkipsNonJSONBodies(t *testing.T) {
	doc := `{
  "openapi": "3.0.0",
  "servers": [{"url": "http://testbed:8000"}],
  "paths": {
    "/api/ok": {"get": {"operationId": "ok"}},
    "/api/upload": {"post": {"requestBody": {"content":
      {"multipart/form-data": {"schema": {"type": "object"}}}}}}
  }
}`
	result, err := LoadOpenAPI([]byte(doc), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Skipped) != 1 || !strings.Contains(result.Skipped[0].Reason, "application/json") {
		t.Fatalf("the multipart body was not reported as unsupported: %+v", result.Skipped)
	}
}

func TestLoadOpenAPIAcceptsYAML(t *testing.T) {
	doc := "openapi: \"3.0.0\"\npaths:\n  /api/items:\n    get:\n      operationId: listItems\n"
	result, err := LoadOpenAPI([]byte(doc), "http://testbed:8000")
	if err != nil {
		t.Fatalf("LoadOpenAPI(yaml) = %v, want it accepted", err)
	}
	if len(result.Corpus.Samples) != 1 || result.Corpus.Samples[0].ID != "listItems" {
		t.Fatalf("the YAML document produced %+v", result.Corpus.Samples)
	}
}

func TestLoadOpenAPIRejectsUnsupportedVersionsAndMissingBase(t *testing.T) {
	swagger := `{"swagger": "2.0", "paths": {}}`
	if _, err := LoadOpenAPI([]byte(swagger), "http://t:1"); !errors.Is(err, ErrInvalidCorpus) {
		t.Errorf("a Swagger 2.0 document was accepted: %v", err)
	}

	noServer := `{"openapi": "3.0.0", "paths": {"/api/x": {"get": {}}}}`
	if _, err := LoadOpenAPI([]byte(noServer), ""); !errors.Is(err, ErrInvalidCorpus) {
		t.Errorf("a document with no base URL was accepted: %v", err)
	}
	if _, err := LoadOpenAPI([]byte(noServer), "http://testbed:8000"); err != nil {
		t.Errorf("an explicit base URL was not accepted: %v", err)
	}
}

func TestLoadOpenAPIRejectsARefCycle(t *testing.T) {
	doc := `{
  "openapi": "3.0.0",
  "servers": [{"url": "http://testbed:8000"}],
  "paths": {"/api/x": {"post": {"requestBody": {"content":
    {"application/json": {"schema": {"$ref": "#/components/schemas/Loop"}}}}}}},
  "components": {"schemas": {"Loop": {"$ref": "#/components/schemas/Loop"}}}
}`
	result, err := LoadOpenAPI([]byte(doc), "")
	if err == nil {
		t.Fatalf("a self-referential schema was accepted: %+v", result)
	}
	if len(result.Skipped) != 1 || !strings.Contains(result.Skipped[0].Reason, "deep") {
		t.Errorf("the cycle was not reported as a depth limit: %+v", result.Skipped)
	}
}

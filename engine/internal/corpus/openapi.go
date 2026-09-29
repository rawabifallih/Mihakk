package corpus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// OpenAPI support is a deliberately small subset, fixed in phase 1 and not
// widened since. What is handled:
//
//   - OpenAPI 3.x documents in JSON or YAML
//   - parameters in query, path and header
//   - application/json request bodies whose schema is an object of simple
//     types (string, number, integer, boolean, and arrays of those)
//   - local $ref into #/components/…
//
// What is not, and is reported rather than silently ignored:
//
//   - external or remote $ref
//   - oneOf / anyOf / allOf / not
//   - multipart and non-JSON bodies
//   - security schemes and authentication flows
//
// An operation the subset cannot express is skipped and named in Skipped, so
// a corpus is never quietly smaller than the document that produced it.

// maxRefDepth bounds local $ref resolution; a document can reference itself.
const maxRefDepth = 8

// OpenAPIResult is a corpus plus what could not be expressed.
type OpenAPIResult struct {
	Corpus  *Corpus
	Skipped []SkippedOperation
}

// SkippedOperation records one operation the subset could not express.
type SkippedOperation struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type oaDocument struct {
	OpenAPI    string                `json:"openapi"`
	Servers    []oaServer            `json:"servers"`
	Paths      map[string]oaPathItem `json:"paths"`
	Components struct {
		Schemas    map[string]json.RawMessage `json:"schemas"`
		Parameters map[string]json.RawMessage `json:"parameters"`
	} `json:"components"`
}

type oaServer struct {
	URL string `json:"url"`
}

type oaPathItem map[string]json.RawMessage

type oaOperation struct {
	OperationID string            `json:"operationId"`
	Parameters  []json.RawMessage `json:"parameters"`
	RequestBody *struct {
		Content map[string]struct {
			Schema json.RawMessage `json:"schema"`
		} `json:"content"`
	} `json:"requestBody"`
}

type oaParameter struct {
	Ref      string          `json:"$ref"`
	Name     string          `json:"name"`
	In       string          `json:"in"`
	Required bool            `json:"required"`
	Example  any             `json:"example"`
	Schema   json.RawMessage `json:"schema"`
}

type oaSchema struct {
	Ref        string                     `json:"$ref"`
	Type       string                     `json:"type"`
	Format     string                     `json:"format"`
	Example    any                        `json:"example"`
	Default    any                        `json:"default"`
	Enum       []any                      `json:"enum"`
	Properties map[string]json.RawMessage `json:"properties"`
	Items      json.RawMessage            `json:"items"`

	// Unsupported combinators, decoded only so they can be detected.
	OneOf []json.RawMessage `json:"oneOf"`
	AnyOf []json.RawMessage `json:"anyOf"`
	AllOf []json.RawMessage `json:"allOf"`
	Not   json.RawMessage   `json:"not"`
}

var httpMethods = []string{"get", "post", "put", "patch", "delete"}

// LoadOpenAPI builds a corpus from an OpenAPI 3 document.
//
// baseURL overrides the document's servers entry; it is required when the
// document has none, or when its server URL is relative.
func LoadOpenAPI(raw []byte, baseURL string) (*OpenAPIResult, error) {
	// A YAML document is converted to JSON and then parsed by exactly the same
	// code as a JSON one. Converging early is what makes the two formats
	// produce identical samples: there is one parser, not two that have to be
	// kept in agreement.
	jsonRaw, err := toJSONDocument(raw)
	if err != nil {
		return nil, err
	}

	var doc oaDocument
	if err := json.Unmarshal(jsonRaw, &doc); err != nil {
		return nil, fmt.Errorf("%w: parsing the OpenAPI document: %v", ErrInvalidCorpus, err)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.") {
		return nil, fmt.Errorf("%w: openapi version %q is not supported (only 3.x)",
			ErrInvalidCorpus, doc.OpenAPI)
	}

	base := strings.TrimSpace(baseURL)
	if base == "" && len(doc.Servers) > 0 {
		base = doc.Servers[0].URL
	}
	base = strings.TrimSuffix(base, "/")
	parsedBase, err := url.Parse(base)
	if err != nil || parsedBase.Scheme == "" || parsedBase.Host == "" {
		return nil, fmt.Errorf("%w: an absolute base URL is required; pass one explicitly "+
			"when the document has no absolute servers entry (got %q)", ErrInvalidCorpus, base)
	}

	result := &OpenAPIResult{Corpus: &Corpus{CorpusVersion: CorpusVersion}}

	paths := make([]string, 0, len(doc.Paths))
	for p := range doc.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths) // map order is random; the corpus must be reproducible

	for _, path := range paths {
		item := doc.Paths[path]
		for _, method := range httpMethods {
			rawOp, ok := item[method]
			if !ok {
				continue
			}
			sample, reason := buildSample(&doc, base, method, path, rawOp, item["parameters"])
			if reason != "" {
				result.Skipped = append(result.Skipped, SkippedOperation{
					Method: strings.ToUpper(method), Path: path, Reason: reason,
				})
				continue
			}
			result.Corpus.Samples = append(result.Corpus.Samples, *sample)
		}
	}

	if len(result.Corpus.Samples) == 0 {
		return result, fmt.Errorf("%w: the document produced no usable samples (%d operations skipped)",
			ErrInvalidCorpus, len(result.Skipped))
	}

	result.Corpus.Normalize()
	if err := result.Corpus.Validate(); err != nil {
		return result, err
	}
	return result, nil
}

// toJSONDocument returns the document as JSON, converting from YAML if needed.
//
// The conversion is deterministic: YAML is decoded into plain Go values, then
// re-encoded with encoding/json, which sorts object keys. The same document
// written in either format therefore reaches the parser as the same bytes.
func toJSONDocument(raw []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})))
	if trimmed == "" {
		return nil, fmt.Errorf("%w: the OpenAPI document is empty", ErrInvalidCorpus)
	}
	if strings.HasPrefix(trimmed, "{") {
		return []byte(trimmed), nil
	}

	var decoded any
	if err := yaml.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("%w: the document is neither JSON nor valid YAML: %v",
			ErrInvalidCorpus, err)
	}

	normalised, err := normaliseYAML(decoded)
	if err != nil {
		return nil, err
	}
	if _, ok := normalised.(map[string]any); !ok {
		return nil, fmt.Errorf("%w: the OpenAPI document must be a mapping at the top level",
			ErrInvalidCorpus)
	}

	encoded, err := json.Marshal(normalised)
	if err != nil {
		return nil, fmt.Errorf("%w: converting the YAML document: %v", ErrInvalidCorpus, err)
	}
	return encoded, nil
}

// normaliseYAML turns a decoded YAML value into something encoding/json can
// represent. yaml.v3 gives map[string]any for string-keyed mappings, but a
// document may use other scalar key types, which JSON has no way to express.
func normaliseYAML(v any) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for key, value := range t {
			converted, err := normaliseYAML(value)
			if err != nil {
				return nil, err
			}
			out[key] = converted
		}
		return out, nil

	case map[any]any:
		out := make(map[string]any, len(t))
		for key, value := range t {
			name, ok := key.(string)
			if !ok {
				// Stringifying silently could merge two distinct keys, so it
				// is refused rather than guessed at.
				return nil, fmt.Errorf("%w: the document has a non-string mapping key (%v); "+
					"OpenAPI keys must be strings", ErrInvalidCorpus, key)
			}
			converted, err := normaliseYAML(value)
			if err != nil {
				return nil, err
			}
			out[name] = converted
		}
		return out, nil

	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			converted, err := normaliseYAML(item)
			if err != nil {
				return nil, err
			}
			out[i] = converted
		}
		return out, nil

	default:
		return v, nil
	}
}

// buildSample turns one operation into a sample, or explains why it cannot.
func buildSample(doc *oaDocument, base, method, path string, rawOp, rawPathParams json.RawMessage) (*Sample, string) {
	var op oaOperation
	if err := json.Unmarshal(rawOp, &op); err != nil {
		return nil, fmt.Sprintf("the operation could not be parsed: %v", err)
	}

	// Parameters may be declared once on the path item and shared by every
	// operation under it, which is how most documents express a path
	// variable. Operation-level entries override a path-level one with the
	// same name and location.
	merged, reason := mergeParameters(doc, rawPathParams, op.Parameters)
	if reason != "" {
		return nil, reason
	}

	concretePath := path
	query := url.Values{}
	headers := map[string][]string{}

	for _, rawParam := range merged {
		param, reason := resolveParameter(doc, rawParam, 0)
		if reason != "" {
			return nil, reason
		}
		value, reason := placeholderFor(doc, param, 0)
		if reason != "" {
			return nil, reason
		}
		switch param.In {
		case "path":
			concretePath = strings.ReplaceAll(concretePath, "{"+param.Name+"}", url.PathEscape(value))
		case "query":
			query.Set(param.Name, value)
		case "header":
			headers[param.Name] = []string{value}
		case "cookie":
			return nil, "cookie parameters are outside the supported subset"
		default:
			return nil, fmt.Sprintf("parameter location %q is outside the supported subset", param.In)
		}
	}

	if strings.Contains(concretePath, "{") {
		return nil, "the path has template variables with no matching parameter definition"
	}

	full := base + concretePath
	if encoded := query.Encode(); encoded != "" {
		full += "?" + encoded
	}

	sample := &Sample{
		ID:      sampleID(op.OperationID, method, path),
		Method:  strings.ToUpper(method),
		URL:     full,
		Headers: headers,
	}
	if sample.Headers == nil || len(sample.Headers) == 0 {
		sample.Headers = map[string][]string{}
	}
	sample.Headers["Accept"] = []string{"application/json"}

	if op.RequestBody != nil {
		jsonContent, ok := op.RequestBody.Content["application/json"]
		if !ok {
			available := make([]string, 0, len(op.RequestBody.Content))
			for k := range op.RequestBody.Content {
				available = append(available, k)
			}
			sort.Strings(available)
			return nil, fmt.Sprintf("the request body uses %v; only application/json is supported",
				available)
		}
		value, reason := exampleForSchema(doc, jsonContent.Schema, 0)
		if reason != "" {
			return nil, reason
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Sprintf("the example body could not be encoded: %v", err)
		}
		sample.Body = string(encoded)
		sample.Headers["Content-Type"] = []string{"application/json"}
	}

	return sample, ""
}

// mergeParameters combines path-level and operation-level parameter lists.
func mergeParameters(doc *oaDocument, rawPathParams json.RawMessage, opParams []json.RawMessage) ([]json.RawMessage, string) {
	var pathParams []json.RawMessage
	if len(rawPathParams) > 0 {
		if err := json.Unmarshal(rawPathParams, &pathParams); err != nil {
			return nil, fmt.Sprintf("the path-level parameters could not be parsed: %v", err)
		}
	}
	if len(pathParams) == 0 {
		return opParams, ""
	}

	// Identify an operation-level parameter by name+location so it can shadow
	// the shared one.
	overridden := map[string]bool{}
	for _, raw := range opParams {
		param, reason := resolveParameter(doc, raw, 0)
		if reason != "" {
			return nil, reason
		}
		overridden[param.In+":"+param.Name] = true
	}

	merged := make([]json.RawMessage, 0, len(pathParams)+len(opParams))
	for _, raw := range pathParams {
		param, reason := resolveParameter(doc, raw, 0)
		if reason != "" {
			return nil, reason
		}
		if overridden[param.In+":"+param.Name] {
			continue
		}
		merged = append(merged, raw)
	}
	return append(merged, opParams...), ""
}

func sampleID(operationID, method, path string) string {
	if operationID != "" {
		return operationID
	}
	cleaned := strings.NewReplacer("/", "-", "{", "", "}", "").Replace(strings.Trim(path, "/"))
	if cleaned == "" {
		cleaned = "root"
	}
	return strings.ToLower(method) + "-" + cleaned
}

// resolveParameter follows a local $ref into #/components/parameters.
func resolveParameter(doc *oaDocument, raw json.RawMessage, depth int) (*oaParameter, string) {
	if depth > maxRefDepth {
		return nil, "the parameter's $ref chain is too deep"
	}
	var param oaParameter
	if err := json.Unmarshal(raw, &param); err != nil {
		return nil, fmt.Sprintf("a parameter could not be parsed: %v", err)
	}
	if param.Ref == "" {
		return &param, ""
	}
	name, reason := localRefName(param.Ref, "parameters")
	if reason != "" {
		return nil, reason
	}
	target, ok := doc.Components.Parameters[name]
	if !ok {
		return nil, fmt.Sprintf("the parameter $ref %q does not resolve", param.Ref)
	}
	return resolveParameter(doc, target, depth+1)
}

// localRefName accepts only #/components/<section>/<name>.
func localRefName(ref, section string) (string, string) {
	prefix := "#/components/" + section + "/"
	if !strings.HasPrefix(ref, prefix) {
		return "", fmt.Sprintf("$ref %q is outside the supported subset; only local "+
			"#/components/%s/... references are resolved", ref, section)
	}
	return strings.TrimPrefix(ref, prefix), ""
}

// placeholderFor produces a starting value for a parameter. The value only has
// to be plausible: mutation replaces it immediately.
func placeholderFor(doc *oaDocument, param *oaParameter, depth int) (string, string) {
	if param.Example != nil {
		return fmt.Sprint(param.Example), ""
	}
	if len(param.Schema) == 0 {
		return "1", ""
	}
	value, reason := exampleForSchema(doc, param.Schema, depth)
	if reason != "" {
		return "", reason
	}
	switch v := value.(type) {
	case string:
		return v, ""
	case nil:
		return "", ""
	default:
		encoded, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Sprintf("a parameter value could not be encoded: %v", err)
		}
		return strings.Trim(string(encoded), `"`), ""
	}
}

// exampleForSchema builds a starting value from a schema in the subset.
func exampleForSchema(doc *oaDocument, raw json.RawMessage, depth int) (any, string) {
	if depth > maxRefDepth {
		return nil, "the schema's $ref chain is too deep"
	}
	if len(raw) == 0 {
		return nil, ""
	}

	var schema oaSchema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, fmt.Sprintf("a schema could not be parsed: %v", err)
	}

	switch {
	case len(schema.OneOf) > 0:
		return nil, "oneOf is outside the supported subset"
	case len(schema.AnyOf) > 0:
		return nil, "anyOf is outside the supported subset"
	case len(schema.AllOf) > 0:
		return nil, "allOf is outside the supported subset"
	case len(schema.Not) > 0:
		return nil, "not is outside the supported subset"
	}

	if schema.Ref != "" {
		name, reason := localRefName(schema.Ref, "schemas")
		if reason != "" {
			return nil, reason
		}
		target, ok := doc.Components.Schemas[name]
		if !ok {
			return nil, fmt.Sprintf("the schema $ref %q does not resolve", schema.Ref)
		}
		return exampleForSchema(doc, target, depth+1)
	}

	if schema.Example != nil {
		return schema.Example, ""
	}
	if schema.Default != nil {
		return schema.Default, ""
	}
	if len(schema.Enum) > 0 {
		return schema.Enum[0], ""
	}

	switch schema.Type {
	case "string":
		return "sample", ""
	case "integer":
		return 1, ""
	case "number":
		return 1.5, ""
	case "boolean":
		return true, ""
	case "array":
		item, reason := exampleForSchema(doc, schema.Items, depth+1)
		if reason != "" {
			return nil, reason
		}
		if item == nil {
			return []any{}, ""
		}
		return []any{item}, ""
	case "object", "":
		if len(schema.Properties) == 0 {
			return map[string]any{}, ""
		}
		names := make([]string, 0, len(schema.Properties))
		for n := range schema.Properties {
			names = append(names, n)
		}
		sort.Strings(names) // keep the generated body reproducible
		out := make(map[string]any, len(names))
		for _, n := range names {
			value, reason := exampleForSchema(doc, schema.Properties[n], depth+1)
			if reason != "" {
				return nil, reason
			}
			out[n] = value
		}
		return out, ""
	default:
		return nil, fmt.Sprintf("schema type %q is outside the supported subset", schema.Type)
	}
}

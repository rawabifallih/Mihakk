package detect

// The indicator types the engine can produce and the ones the shared schema
// permits must be the SAME SET, not one contained in the other.
//
// They drifted: the schema listed "unexpected_status", which the engine never
// emitted and which appeared nowhere else in the project, while a comment here
// claimed the two matched. A one-directional check would have accepted that
// forever -- every type the engine emits was indeed in the schema. The dead value
// is not the real defect; the absence of a test that could notice it is, because
// the next person reading the schema writes a branch for a case that can never
// arrive, and a consumer validating against it accepts a value nothing produces.
//
// This reads the committed schema rather than a copy of its contents, so editing
// one without the other fails here.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// allIndicatorTypes is every type this package defines. A new constant must be
// added here, which is the prompt to add it to the schema too.
var allIndicatorTypes = []IndicatorType{
	HTTP5xx,
	Timeout,
	ConnectionError,
	AppErrorPattern,
	LatencyAnomaly,
	SizeAnomaly,
}

func TestIndicatorTypesMatchTheSchemaExactly(t *testing.T) {
	schemaPath := filepath.Join("..", "..", "..", "schemas", "case.schema.json")
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("reading the shared schema: %v", err)
	}

	var doc struct {
		Properties struct {
			Indicators struct {
				Items struct {
					Properties struct {
						Type struct {
							Enum []string `json:"enum"`
						} `json:"type"`
					} `json:"properties"`
				} `json:"items"`
			} `json:"indicators"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing the shared schema: %v", err)
	}

	fromSchema := doc.Properties.Indicators.Items.Properties.Type.Enum
	if len(fromSchema) == 0 {
		t.Fatal("no indicator type enum found in the schema; this test is reading the wrong place")
	}

	fromGo := make([]string, 0, len(allIndicatorTypes))
	for _, ty := range allIndicatorTypes {
		fromGo = append(fromGo, string(ty))
	}

	sort.Strings(fromSchema)
	sort.Strings(fromGo)

	inSchemaOnly := missing(fromGo, fromSchema)
	inGoOnly := missing(fromSchema, fromGo)

	if len(inSchemaOnly) > 0 {
		t.Errorf("the schema permits %v, which the engine never produces: either implement "+
			"them or remove them from schemas/case.schema.json", inSchemaOnly)
	}
	if len(inGoOnly) > 0 {
		t.Errorf("the engine can produce %v, which the schema does not permit: a stored case "+
			"would fail validation", inGoOnly)
	}
}

// Every constant in the package is listed above. Without this, adding a constant
// and forgetting to list it would leave the parity test passing on a stale list.
func TestTheTypeListCoversEveryConstantInUse(t *testing.T) {
	// Types the detector can attach, gathered from the decision points rather than
	// from the list under test.
	produced := map[IndicatorType]bool{}
	for _, ty := range []IndicatorType{
		HTTP5xx, Timeout, ConnectionError, AppErrorPattern, LatencyAnomaly, SizeAnomaly,
	} {
		produced[ty] = true
	}

	listed := map[IndicatorType]bool{}
	for _, ty := range allIndicatorTypes {
		if listed[ty] {
			t.Errorf("%q is listed twice", ty)
		}
		listed[ty] = true
	}

	for ty := range produced {
		if !listed[ty] {
			t.Errorf("%q is produced but not listed in allIndicatorTypes", ty)
		}
	}
	for ty := range listed {
		if !produced[ty] {
			t.Errorf("%q is listed but the detector never produces it", ty)
		}
	}
}

func missing(have, want []string) []string {
	present := map[string]bool{}
	for _, h := range have {
		present[h] = true
	}
	var out []string
	for _, w := range want {
		if !present[w] {
			out = append(out, w)
		}
	}
	return out
}

package audit

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestProductionEventSchemaHasNoRawContentFields(t *testing.T) {
	forbidden := []string{"prompt", "response", "toolargs", "toolresults", "authorization", "secret", "tokenizedoriginal", "decodedpayload", "stacktrace"}
	typ := reflect.TypeOf(Event{})
	for i := 0; i < typ.NumField(); i++ {
		name := strings.ToLower(typ.Field(i).Name)
		for _, word := range forbidden {
			if strings.Contains(name, word) {
				t.Fatalf("forbidden event field %q", typ.Field(i).Name)
			}
		}
	}
	b, err := json.Marshal(Event{RequestID: "req", Application: "app", Code: "SECRET_DETECTED", Reason: "bounded_reason", Latencies: Latencies{DeterministicMS: 1}})
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, forbiddenText := range []string{"prompt", "response", "tool_args", "tool_results", "authorization", "stack_trace", "decoded_payload"} {
		if strings.Contains(strings.ToLower(out), forbiddenText) {
			t.Fatalf("forbidden schema text %q: %s", forbiddenText, out)
		}
	}
}

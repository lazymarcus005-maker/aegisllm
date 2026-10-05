package core

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestSafeStringExcludesContent(t *testing.T) {
	e := InspectionEnvelope{
		RequestID:   "req-1",
		Direction:   DirectionRequest,
		Application: "agent-x",
		Target:      Target{Provider: "cloud", Model: "gpt-x"},
		Messages: []Message{
			{Role: RoleUser, Parts: []ContentPart{{Type: PartText, Text: "supersecret-token-value glpat-abc"}}},
		},
	}
	safe := e.SafeString()
	if strings.Contains(safe, "supersecret") || strings.Contains(safe, "glpat") {
		t.Fatalf("SafeString leaked content: %s", safe)
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("envelope JSON (intentionally includes content for pipeline use): %s", b)
}

func TestEnvelopeJSONRoundTrip(t *testing.T) {
	e := InspectionEnvelope{
		RequestID:   "req-1",
		Direction:   DirectionRequest,
		Application: "agent-x",
		Target:      Target{Provider: "cloud", Model: "gpt-x"},
		Messages: []Message{
			{Role: RoleUser, Parts: []ContentPart{{Type: PartText, Text: "hello"}}},
		},
		Tools: []ToolDefinition{{Name: "shell", Schema: json.RawMessage(`{"type":"object"}`)}},
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var back InspectionEnvelope
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, e) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", back, e)
	}
}

func TestTextPartsOrderAndFiltering(t *testing.T) {
	e := InspectionEnvelope{
		Messages: []Message{
			{Role: RoleSystem, Parts: []ContentPart{{Type: PartText, Text: "sys"}}},
			{Role: RoleUser, Parts: []ContentPart{
				{Type: PartImageRef},
				{Type: PartText, Text: "first"},
				{Type: PartText},
				{Type: PartText, Text: "second"},
			}},
		},
	}
	got := e.TextParts()
	if len(got) != 3 {
		t.Fatalf("expected 3 text parts, got %d", len(got))
	}
	wantTexts := []string{"sys", "first", "second"}
	for i, lt := range got {
		if lt.Text != wantTexts[i] {
			t.Fatalf("part %d: got %q want %q", i, lt.Text, wantTexts[i])
		}
	}
	if got[1].MessageIndex != 1 || got[1].PartIndex != 1 {
		t.Fatalf("located text index wrong: %+v", got[1])
	}
	if got[0].Role != RoleSystem {
		t.Fatalf("role not carried: %+v", got[0])
	}
}

package gateway

import (
	"strings"
	"testing"

	"github.com/aegisllm/gateway/internal/pii"
)

func TestApplyTransformationsStringContent(t *testing.T) {
	raw := []byte(`{"model":"m","temperature":0.7,"messages":[{"role":"user","content":"call 0812345678 now"}],"top_level_extra":true}`)
	plan := []pii.Transformation{{MessageIndex: 0, PartIndex: 0, Start: 5, End: 15, Replacement: "[REDACTED:PHONE_NUMBER]"}}

	out, err := applyTransformationsToBody(raw, plan)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "0812345678") {
		t.Fatalf("raw value survived: %s", s)
	}
	if !strings.Contains(s, "[REDACTED:PHONE_NUMBER]") {
		t.Fatalf("replacement missing: %s", s)
	}
	// Unrelated fields must survive the round trip with fidelity.
	for _, want := range []string{`"model":"m"`, `"temperature":0.7`, `"top_level_extra":true`} {
		if !strings.Contains(s, want) {
			t.Fatalf("lost field %s in: %s", want, s)
		}
	}
}

func TestApplyTransformationsPartArrayContent(t *testing.T) {
	raw := []byte(`{"model":"m","messages":[{"role":"user","content":[
		{"type":"text","text":"keep me"},
		{"type":"text","text":"card 4111111111111111 here"}
	]}]}`)
	plan := []pii.Transformation{{MessageIndex: 0, PartIndex: 1, Start: 5, End: 20, Replacement: "[REDACTED:CREDIT_CARD]"}}

	out, err := applyTransformationsToBody(raw, plan)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "4111111111111111") {
		t.Fatalf("card survived: %s", s)
	}
	if !strings.Contains(s, "keep me") {
		t.Fatalf("sibling part damaged: %s", s)
	}
	if !strings.Contains(s, "[REDACTED:CREDIT_CARD]") {
		t.Fatalf("replacement missing: %s", s)
	}
}

func TestApplyTransformationsNoPlanReturnsRaw(t *testing.T) {
	raw := []byte(`{"model":"m","messages":[{"role":"user","content":"x"}]}`)
	out, err := applyTransformationsToBody(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(raw) {
		t.Fatalf("raw must pass through untouched:\n got %s\nwant %s", out, raw)
	}
}

func TestApplyTransformationsOutOfRangeIsError(t *testing.T) {
	raw := []byte(`{"model":"m","messages":[{"role":"user","content":"x"}]}`)
	plan := []pii.Transformation{{MessageIndex: 5, PartIndex: 0, Start: 0, End: 1, Replacement: "r"}}
	if _, err := applyTransformationsToBody(raw, plan); err == nil {
		t.Fatal("expected error for out-of-range message index")
	}
}

package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/pii"
)

func TestNormalizerForEndpointMatrix(t *testing.T) {
	cases := []struct {
		path   string
		family string
		body   string
		msgs   int
	}{
		{"/v1/chat/completions", "openai", `{"model":"m","messages":[{"role":"user","content":"hello"}]}`, 1},
		{"/v1/responses", "openai", `{"model":"m","input":"hello"}`, 1},
		{"/v1/completions", "openai", `{"model":"m","prompt":["hello","world"]}`, 2},
		{"/v1/embeddings", "openai", `{"model":"m","input":"hello"}`, 1},
		{"/v1/messages", "anthropic", `{"model":"m","max_tokens":32,"messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`, 1},
		{"/v1/complete", "anthropic", `{"model":"m","prompt":"hello"}`, 1},
		{"/anthropic/v1/messages", "anthropic", `{"model":"m","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}`, 1},
		{"/message", "openai", `{"model":"m","messages":[{"role":"user","content":"hello"}]}`, 1},
		{"/messages", "anthropic", `{"model":"m","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}`, 1},
		{"/chatcompletion", "generic", `{"prompt":"hello"}`, 1},
		{"/chat/completions", "generic", `{"input":"hello"}`, 1},
		{"/response", "generic", `{"text":"hello"}`, 1},
		{"/responses", "generic", `{"content":"hello"}`, 1},
		{"/v1/message", "generic", `{"prompt":"hello"}`, 1},
		{"/v1/response", "generic", `{"input":"hello"}`, 1},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			n := NormalizerFor(tc.path)
			if n == nil {
				t.Fatal("normalizer missing")
			}
			env, err := n.ParseRequest([]byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if env.Metadata["endpoint_family"] != tc.family {
				t.Fatalf("family: got %q want %q", env.Metadata["endpoint_family"], tc.family)
			}
			if len(env.Messages) != tc.msgs {
				t.Fatalf("messages: got %d want %d", len(env.Messages), tc.msgs)
			}
			if env.RequestID == "" || env.Direction != core.DirectionRequest {
				t.Fatalf("request envelope not normalized: %+v", env)
			}
		})
	}
}

func TestNormalizerValidationErrors(t *testing.T) {
	cases := []struct {
		path string
		body string
	}{
		{"/v1/chat/completions", `{"messages":[{"role":"user","content":"x"}]}`},
		{"/v1/chat/completions", `{"model":"m","messages":[]}`},
		{"/v1/responses", `{"input":"x"}`},
		{"/v1/responses", `{"model":"m","input":[]}`},
		{"/v1/completions", `{"prompt":"x"}`},
		{"/v1/completions", `{"model":"m","prompt":""}`},
		{"/v1/embeddings", `{"input":"x"}`},
		{"/v1/messages", `{"max_tokens":32,"messages":[{"role":"user","content":"x"}]}`},
		{"/v1/messages", `{"model":"m","max_tokens":32,"messages":[]}`},
		{"/v1/complete", `{"model":"m"}`},
	}
	for _, tc := range cases {
		t.Run(tc.path+"/"+tc.body, func(t *testing.T) {
			if _, err := NormalizerFor(tc.path).ParseRequest([]byte(tc.body)); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestGenericSupersetShapes(t *testing.T) {
	cases := []struct {
		body   string
		family string
	}{
		{`{"model":"m","messages":[{"role":"user","content":"hello"}]}`, "openai"},
		{`{"model":"m","max_tokens":8,"messages":[{"role":"user","content":"hello"}]}`, "anthropic"},
		{`{"prompt":"hello"}`, "generic"},
	}
	n := genericSupersetNormalizer{}
	for _, tc := range cases {
		env, err := n.ParseRequest([]byte(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		if got := env.Metadata["endpoint_family"]; got != tc.family {
			t.Fatalf("family for %s: got %s want %s", tc.body, got, tc.family)
		}
	}
}

func TestResponseRewriteEveryNormalizer(t *testing.T) {
	cases := []struct {
		name string
		n    Normalizer
		body string
		want string
		noop bool
	}{
		{"chat", openAIChatNormalizer{}, `{"choices":[{"message":{"role":"assistant","content":"phone 0812345678"}}]}`, "phone [REDACTED:PHONE_NUMBER]", false},
		{"responses", openAIResponsesNormalizer{}, `{"output":[{"type":"message","content":[{"type":"output_text","text":"phone 0812345678"}]}]}`, "phone [REDACTED:PHONE_NUMBER]", false},
		{"completions", openAICompletionsNormalizer{}, `{"choices":[{"text":"phone 0812345678"}]}`, "phone [REDACTED:PHONE_NUMBER]", false},
		{"embeddings", openAIEmbeddingsNormalizer{}, `{"data":[{"embedding":[1,2]}]}`, "", true},
		{"anthropic", anthropicMessagesNormalizer{}, `{"content":[{"type":"text","text":"phone 0812345678"}]}`, "phone [REDACTED:PHONE_NUMBER]", false},
		{"complete", anthropicMessagesNormalizer{legacyComplete: true}, `{"completion":"phone 0812345678"}`, "phone [REDACTED:PHONE_NUMBER]", false},
		{"generic", genericSupersetNormalizer{}, `{"choices":[{"message":{"content":"phone 0812345678"}}]}`, "phone [REDACTED:PHONE_NUMBER]", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value := "phone 0812345678"
			plan := []pii.Transformation{{MessageIndex: 0, PartIndex: 0, Start: strings.Index(value, "0812345678"), End: len(value), Replacement: "[REDACTED:PHONE_NUMBER]"}}
			out, err := tc.n.RewriteResponse([]byte(tc.body), plan)
			if err != nil {
				t.Fatal(err)
			}
			if tc.noop {
				if string(out) != tc.body {
					t.Fatalf("noop changed response: %s", out)
				}
				return
			}
			if !strings.Contains(string(out), tc.want) || strings.Contains(string(out), "0812345678") {
				t.Fatalf("rewrite failed: %s", out)
			}
			if _, err := tc.n.ParseResponse(out); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestResponsesInputTextObjectRewrite(t *testing.T) {
	n := openAIResponsesNormalizer{}
	raw := []byte(`{"model":"m","input":{"input_text":"phone 0812345678"}}`)
	env, err := n.ParseRequest(raw)
	if err != nil || len(env.TextParts()) != 1 {
		t.Fatalf("parse input_text object: env=%+v err=%v", env, err)
	}
	value := env.TextParts()[0].Text
	out, err := n.RewriteRequest(raw, []pii.Transformation{{MessageIndex: 0, PartIndex: 0, Start: strings.Index(value, "0812345678"), End: len(value), Replacement: "[REDACTED:PHONE_NUMBER]"}})
	if err != nil || strings.Contains(string(out), "0812345678") {
		t.Fatalf("rewrite input_text object: %s (%v)", out, err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
}

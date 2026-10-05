package gateway

import (
	"testing"

	"github.com/aegisllm/gateway/internal/core"
)

func TestParseTypicalRequest(t *testing.T) {
	body := []byte(`{
		"model": "gpt-x",
		"messages": [
			{"role": "system", "content": "You are helpful."},
			{"role": "user", "content": "hello"}
		],
		"tools": [{
			"type": "function",
			"function": {
				"name": "shell",
				"description": "run a command",
				"parameters": {"type": "object"}
			}
		}]
	}`)
	env, err := ParseChatCompletions(body)
	if err != nil {
		t.Fatal(err)
	}
	if env.Target.Model != "gpt-x" {
		t.Fatalf("model: %s", env.Target.Model)
	}
	if env.Direction != core.DirectionRequest {
		t.Fatalf("direction: %s", env.Direction)
	}
	if len(env.Messages) != 2 {
		t.Fatalf("messages: %d", len(env.Messages))
	}
	if env.Messages[0].Role != core.RoleSystem || env.Messages[0].Parts[0].Text != "You are helpful." {
		t.Fatalf("system message wrong: %+v", env.Messages[0])
	}
	if env.Messages[1].Parts[0].Type != core.PartText || env.Messages[1].Parts[0].Text != "hello" {
		t.Fatalf("user message wrong: %+v", env.Messages[1])
	}
	if len(env.Tools) != 1 || env.Tools[0].Name != "shell" {
		t.Fatalf("tools wrong: %+v", env.Tools)
	}
	if env.RequestID == "" {
		t.Fatal("request id not generated")
	}
}

func TestParseContentPartArray(t *testing.T) {
	body := []byte(`{"model":"m","messages":[{"role":"user","content":[
		{"type":"text","text":"look"},
		{"type":"image_url","image_url":{"url":"https://x/y.png"}}
	]}]}`)
	env, err := ParseChatCompletions(body)
	if err != nil {
		t.Fatal(err)
	}
	parts := env.Messages[0].Parts
	if len(parts) != 2 {
		t.Fatalf("parts: %d", len(parts))
	}
	if parts[0].Type != core.PartText || parts[0].Text != "look" {
		t.Fatalf("text part wrong: %+v", parts[0])
	}
	if parts[1].Type != core.PartImageRef {
		t.Fatalf("image part wrong: %+v", parts[1])
	}
}

func TestParseToolCallsAndResults(t *testing.T) {
	body := []byte(`{"model":"m","messages":[
		{"role":"assistant","content":null,"tool_calls":[{"id":"call1","type":"function","function":{"name":"shell","arguments":"{\"command\":\"ls\"}"}}]},
		{"role":"tool","tool_call_id":"call1","content":"file.txt"}
	]}`)
	env, err := ParseChatCompletions(body)
	if err != nil {
		t.Fatal(err)
	}
	assistant := env.Messages[0]
	if assistant.Role != core.RoleAssistant {
		t.Fatalf("role: %s", assistant.Role)
	}
	if len(assistant.Parts) != 1 || assistant.Parts[0].Type != core.PartToolCall {
		t.Fatalf("tool call part wrong: %+v", assistant.Parts)
	}
	if assistant.Parts[0].ToolName != "shell" || assistant.Parts[0].ToolCallID != "call1" {
		t.Fatalf("tool call fields wrong: %+v", assistant.Parts[0])
	}
	toolMsg := env.Messages[1]
	if len(toolMsg.Parts) != 1 || toolMsg.Parts[0].Type != core.PartToolResult {
		t.Fatalf("tool result part wrong: %+v", toolMsg.Parts)
	}
	if toolMsg.Parts[0].Text != "file.txt" || toolMsg.Parts[0].ToolCallID != "call1" {
		t.Fatalf("tool result fields wrong: %+v", toolMsg.Parts[0])
	}
}

func TestParseNullAndEmptyContent(t *testing.T) {
	env, err := ParseChatCompletions([]byte(`{"model":"m","messages":[{"role":"assistant","content":null}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(env.Messages[0].Parts) != 0 {
		t.Fatalf("expected no parts, got %+v", env.Messages[0].Parts)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"malformed json", `{"model": `},
		{"missing model", `{"messages":[{"role":"user","content":"x"}]}`},
		{"missing messages", `{"model":"m"}`},
		{"empty messages", `{"model":"m","messages":[]}`},
		{"missing role", `{"model":"m","messages":[{"content":"x"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseChatCompletions([]byte(tc.body)); err == nil {
				t.Fatalf("expected error for %s", tc.body)
			}
		})
	}
}

func TestParseStreamFlagRecorded(t *testing.T) {
	env, err := ParseChatCompletions([]byte(`{"model":"m","stream":true,"messages":[{"role":"user","content":"x"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if env.Metadata["stream"] != "true" {
		t.Fatalf("stream flag not recorded: %+v", env.Metadata)
	}
}

package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/aegisllm/gateway/internal/core"
)

type openAIRequest struct {
	Model    string          `json:"model"`
	Messages []openAIMessage `json:"messages"`
	Tools    []openAITool    `json:"tools"`
	Stream   bool            `json:"stream"`
}

type openAIMessage struct {
	Role       string           `json:"role"`
	Content    json.RawMessage  `json:"content"`
	Name       string           `json:"name"`
	ToolCallID string           `json:"tool_call_id"`
	ToolCalls  []openAIToolCall `json:"tool_calls"`
}

type openAIToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type openAITool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

// ParseChatCompletions parses an OpenAI-compatible chat completions request
// body into an InspectionEnvelope. Parsing never mutates the payload: the
// caller forwards the original raw bytes (T-003).
func ParseChatCompletions(raw []byte) (*core.InspectionEnvelope, error) {
	var req openAIRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("invalid JSON body: %w", err)
	}
	if req.Model == "" {
		return nil, fmt.Errorf("missing required field: model")
	}
	if len(req.Messages) == 0 {
		return nil, fmt.Errorf("missing required field: messages")
	}

	env := &core.InspectionEnvelope{
		RequestID: newRequestID(),
		Direction: core.DirectionRequest,
		Target:    core.Target{Model: req.Model},
	}
	if req.Stream {
		env.Metadata = map[string]string{"stream": "true"}
	}

	for i, m := range req.Messages {
		if m.Role == "" {
			return nil, fmt.Errorf("messages[%d]: missing role", i)
		}
		msg := core.Message{Role: core.Role(m.Role)}
		parts, err := parseContent(m.Content)
		if err != nil {
			return nil, fmt.Errorf("messages[%d]: %w", i, err)
		}
		msg.Parts = append(msg.Parts, parts...)
		for _, tc := range m.ToolCalls {
			msg.Parts = append(msg.Parts, core.ContentPart{
				Type:       core.PartToolCall,
				ToolCallID: tc.ID,
				ToolName:   tc.Function.Name,
				Arguments:  json.RawMessage(tc.Function.Arguments),
				// Arguments are also exposed as text so deterministic
				// scanners see smuggled content inside nested structures.
				Text: tc.Function.Arguments,
			})
		}
		if m.ToolCallID != "" {
			// OpenAI tool results arrive as role=tool messages with a
			// tool_call_id; their content parts are tool results.
			for j := range msg.Parts {
				if msg.Parts[j].Type == core.PartText {
					msg.Parts[j].Type = core.PartToolResult
				}
				msg.Parts[j].ToolCallID = m.ToolCallID
			}
		}
		env.Messages = append(env.Messages, msg)
	}

	for _, t := range req.Tools {
		env.Tools = append(env.Tools, core.ToolDefinition{
			Name:        t.Function.Name,
			Description: t.Function.Description,
			Schema:      t.Function.Parameters,
		})
	}
	return env, nil
}

// parseContent handles the three OpenAI content shapes: null, string, and an
// array of typed parts.
func parseContent(raw json.RawMessage) ([]core.ContentPart, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s == "" {
			return nil, nil
		}
		return []core.ContentPart{{Type: core.PartText, Text: s}}, nil
	}
	var arr []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("unsupported content shape")
	}
	parts := make([]core.ContentPart, 0, len(arr))
	for _, p := range arr {
		switch p.Type {
		case "text":
			parts = append(parts, core.ContentPart{Type: core.PartText, Text: p.Text})
		case "image_url":
			parts = append(parts, core.ContentPart{Type: core.PartImageRef})
		default:
			parts = append(parts, core.ContentPart{Type: core.PartJSON})
		}
	}
	return parts, nil
}

func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req-unavailable"
	}
	return "req-" + hex.EncodeToString(b[:])
}

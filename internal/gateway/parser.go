package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aegisllm/gateway/internal/core"
)

type openAIRequest struct {
	Model    string          `json:"model"`
	Messages []openAIMessage `json:"messages"`
	Tools    []openAITool    `json:"tools"`
	Stream   bool            `json:"stream"`
}

func parseAttachmentRef(typ string, part map[string]json.RawMessage) (*core.AttachmentRef, error) {
	ref := &core.AttachmentRef{Kind: typ}
	_ = json.Unmarshal(part["mime_type"], &ref.MIMEType)
	if v, ok := part["filename"]; ok {
		_ = json.Unmarshal(v, &ref.Name)
	}
	if v, ok := part["name"]; ok && ref.Name == "" {
		_ = json.Unmarshal(v, &ref.Name)
	}
	var imageURL string
	if raw, ok := part["image_url"]; ok {
		if json.Unmarshal(raw, &imageURL) != nil {
			var object map[string]json.RawMessage
			if json.Unmarshal(raw, &object) == nil {
				_ = json.Unmarshal(object["url"], &imageURL)
				if ref.MIMEType == "" {
					_ = json.Unmarshal(object["mime_type"], &ref.MIMEType)
				}
			}
		}
	}
	for _, key := range []string{"url", "file_url", "image", "document_url"} {
		if imageURL == "" {
			_ = json.Unmarshal(part[key], &imageURL)
		}
	}
	for _, key := range []string{"file_data", "data", "base64", "file_base64"} {
		if ref.InlineData == "" {
			_ = json.Unmarshal(part[key], &ref.InlineData)
		}
	}
	if source, ok := part["source"]; ok {
		var object map[string]json.RawMessage
		if json.Unmarshal(source, &object) == nil {
			_ = json.Unmarshal(object["media_type"], &ref.MIMEType)
			var sourceType string
			_ = json.Unmarshal(object["type"], &sourceType)
			if sourceType == "url" {
				_ = json.Unmarshal(object["url"], &imageURL)
			} else {
				_ = json.Unmarshal(object["data"], &ref.InlineData)
			}
		}
	}
	if file, ok := part["file"]; ok {
		var object map[string]json.RawMessage
		if json.Unmarshal(file, &object) == nil {
			if ref.MIMEType == "" {
				_ = json.Unmarshal(object["mime_type"], &ref.MIMEType)
			}
			if imageURL == "" {
				_ = json.Unmarshal(object["url"], &imageURL)
			}
			if ref.InlineData == "" {
				_ = json.Unmarshal(object["data"], &ref.InlineData)
				if ref.InlineData == "" {
					_ = json.Unmarshal(object["file_data"], &ref.InlineData)
				}
			}
		}
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(imageURL)), "data:") {
		if ref.InlineData == "" {
			ref.InlineData = strings.TrimSpace(imageURL)
		}
		imageURL = ""
	}
	ref.URL = strings.TrimSpace(imageURL)
	if ref.URL == "" && ref.InlineData == "" {
		return nil, fmt.Errorf("attachment source is required")
	}
	if ref.MIMEType == "" && ref.URL == "" && !strings.HasPrefix(strings.ToLower(ref.InlineData), "data:") {
		return nil, fmt.Errorf("attachment MIME type is required")
	}
	return ref, nil
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
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("unsupported content shape")
	}
	parts := make([]core.ContentPart, 0, len(arr))
	for _, item := range arr {
		var p map[string]json.RawMessage
		if err := json.Unmarshal(item, &p); err != nil {
			return nil, fmt.Errorf("content part must be an object")
		}
		var typ string
		_ = json.Unmarshal(p["type"], &typ)
		if typ == "" {
			for _, key := range []string{"attachment", "file_data", "file_base64", "base64", "data", "url", "file_url", "document_url", "image_url", "source"} {
				if _, ok := p[key]; ok {
					typ = "attachment"
					break
				}
			}
		}
		var text, inputText, outputText, name string
		_ = json.Unmarshal(p["text"], &text)
		_ = json.Unmarshal(p["input_text"], &inputText)
		_ = json.Unmarshal(p["output_text"], &outputText)
		_ = json.Unmarshal(p["name"], &name)
		switch typ {
		case "text", "input_text", "output_text":
			text := text
			if text == "" {
				text = inputText
			}
			if text == "" {
				text = outputText
			}
			parts = append(parts, core.ContentPart{Type: core.PartText, Text: text})
		case "tool_use":
			parts = append(parts, core.ContentPart{Type: core.PartToolCall, ToolName: name, Arguments: p["input"], Text: string(p["input"])})
		case "tool_result":
			resultParts, err := parseContent(p["content"])
			if err == nil && len(resultParts) > 0 {
				for _, part := range resultParts {
					part.Type = core.PartToolResult
					parts = append(parts, part)
				}
			} else {
				parts = append(parts, core.ContentPart{Type: core.PartToolResult})
			}
		case "image_url", "input_image", "image", "file", "input_file", "document", "attachment":
			ref, err := parseAttachmentRef(typ, p)
			if err != nil {
				return nil, err
			}
			partType := core.PartAttachment
			if typ == "image_url" || typ == "input_image" || typ == "image" {
				partType = core.PartImageRef
			}
			parts = append(parts, core.ContentPart{Type: partType, Attachment: ref})
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

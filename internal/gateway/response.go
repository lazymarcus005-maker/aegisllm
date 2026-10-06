package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/pii"
)

// ParseChatCompletionsResponse normalizes an OpenAI chat completions response
// into an InspectionEnvelope(direction=RESPONSE) (T-021). The raw body stays
// the source of truth for forwarding; this envelope is for inspection only.
func ParseChatCompletionsResponse(raw []byte) (*core.InspectionEnvelope, error) {
	var resp struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Role       string           `json:"role"`
				Content    json.RawMessage  `json:"content"`
				ToolCalls  []openAIToolCall `json:"tool_calls"`
				ToolCallID string           `json:"tool_call_id"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("invalid response JSON: %w", err)
	}
	env := &core.InspectionEnvelope{
		RequestID: newRequestID(),
		Direction: core.DirectionResponse,
		Target:    core.Target{Model: resp.Model},
	}
	for i, c := range resp.Choices {
		msg := core.Message{Role: core.Role(c.Message.Role)}
		parts, err := parseContent(c.Message.Content)
		if err != nil {
			return nil, fmt.Errorf("choices[%d]: %w", i, err)
		}
		msg.Parts = append(msg.Parts, parts...)
		for _, tc := range c.Message.ToolCalls {
			msg.Parts = append(msg.Parts, core.ContentPart{
				Type:       core.PartToolCall,
				ToolCallID: tc.ID,
				ToolName:   tc.Function.Name,
				Arguments:  json.RawMessage(tc.Function.Arguments),
				Text:       tc.Function.Arguments, // scanable text form
			})
		}
		env.Messages = append(env.Messages, msg)
	}
	return env, nil
}

// applyPlanToResponseBody rewrites choice message content in an OpenAI
// response body according to the plan (outbound redaction). The response
// envelope maps one message per choice, so plan MessageIndex is the choice
// index; span replacement itself is pii.ApplyToText, the same seam the
// request path uses.
func applyPlanToResponseBody(raw []byte, plan []pii.Transformation) ([]byte, error) {
	if len(plan) == 0 {
		return raw, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("response transform: reparse body: %w", err)
	}
	root, ok := doc.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("response transform: body is not a JSON object")
	}
	choices, ok := root["choices"].([]any)
	if !ok {
		return nil, fmt.Errorf("response transform: body has no choices array")
	}

	byChoice := map[int][]pii.Transformation{}
	for _, t := range plan {
		byChoice[t.MessageIndex] = append(byChoice[t.MessageIndex], t)
	}
	for idx, ts := range byChoice {
		if idx < 0 || idx >= len(choices) {
			return nil, fmt.Errorf("response transform: choice index %d out of range", idx)
		}
		choice, ok := choices[idx].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("response transform: choice %d is not an object", idx)
		}
		msg, ok := choice["message"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("response transform: choice %d has no message object", idx)
		}
		switch content := msg["content"].(type) {
		case string:
			msg["content"] = pii.ApplyToText(content, filterParts(ts, 0))
		case []any:
			for pi, partAny := range content {
				part, ok := partAny.(map[string]any)
				if !ok {
					continue
				}
				if text, ok := part["text"].(string); ok {
					part["text"] = pii.ApplyToText(text, filterParts(ts, pi))
				}
			}
		default:
			// null/non-text: nothing to transform
		}
	}
	return json.Marshal(doc)
}

func filterParts(ts []pii.Transformation, part int) []pii.Transformation {
	out := make([]pii.Transformation, 0, len(ts))
	for _, t := range ts {
		if t.PartIndex == part {
			out = append(out, t)
		}
	}
	return out
}

// placeholderRe matches <TYPE_NNN> token placeholders the model may echo.
var placeholderRe = regexp.MustCompile(`<([A-Z][A-Z0-9_]*_[0-9]{3})>`)

// replacePlaceholdersInBody rewrites every token placeholder in response
// content for which the resolver returns a value. Placeholders that do not
// resolve (never issued, foreign namespace) are left untouched — model-
// invented markers are inert text, never blindly replaced (T-023).
func replacePlaceholdersInBody(raw []byte, resolve func(label string) (string, bool)) ([]byte, bool, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return raw, false, fmt.Errorf("placeholder replace: reparse body: %w", err)
	}
	root, ok := doc.(map[string]any)
	if !ok {
		return raw, false, nil
	}
	choices, ok := root["choices"].([]any)
	if !ok {
		return raw, false, nil
	}
	replaced := false
	for _, choiceAny := range choices {
		choice, ok := choiceAny.(map[string]any)
		if !ok {
			continue
		}
		msg, ok := choice["message"].(map[string]any)
		if !ok {
			continue
		}
		switch content := msg["content"].(type) {
		case string:
			if out, changed := replaceInText(content, resolve); changed {
				msg["content"] = out
				replaced = true
			}
		case []any:
			for _, partAny := range content {
				part, ok := partAny.(map[string]any)
				if !ok {
					continue
				}
				if text, ok := part["text"].(string); ok {
					if out, changed := replaceInText(text, resolve); changed {
						part["text"] = out
						replaced = true
					}
				}
			}
		}
	}
	if !replaced {
		return raw, false, nil
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return raw, false, err
	}
	return out, true, nil
}

func replaceInText(text string, resolve func(string) (string, bool)) (string, bool) {
	matches := placeholderRe.FindAllStringSubmatchIndex(text, -1)
	if len(matches) == 0 {
		return text, false
	}
	changed := false
	for i := len(matches) - 1; i >= 0; i-- {
		m := matches[i]
		label := text[m[2]:m[3]]
		value, ok := resolve(label)
		if !ok {
			continue
		}
		text = text[:m[0]] + value + text[m[1]:]
		changed = true
	}
	return text, changed
}

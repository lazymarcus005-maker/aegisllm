package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/aegisllm/gateway/internal/pii"
)

// applyTransformationsToBody rewrites message content in the original OpenAI
// request body according to the plan. It parses with UseNumber to preserve
// numeric fidelity, mutates only the affected content strings, and re-marshals.
func applyTransformationsToBody(raw []byte, transforms []pii.Transformation) ([]byte, error) {
	if len(transforms) == 0 {
		return raw, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("transform: reparse body: %w", err)
	}
	root, ok := doc.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("transform: body is not a JSON object")
	}
	messages, ok := root["messages"].([]any)
	if !ok {
		return nil, fmt.Errorf("transform: body has no messages array")
	}

	// Group transformations per message part, then rewrite each part once.
	byPart := map[string][]pii.Transformation{}
	order := []string{}
	for _, t := range transforms {
		key := fmt.Sprintf("%d/%d", t.MessageIndex, t.PartIndex)
		if _, seen := byPart[key]; !seen {
			order = append(order, key)
		}
		byPart[key] = append(byPart[key], t)
	}
	for _, key := range order {
		ts := byPart[key]
		mi, pi := ts[0].MessageIndex, ts[0].PartIndex
		if mi < 0 || mi >= len(messages) {
			return nil, fmt.Errorf("transform: message index %d out of range", mi)
		}
		msg, ok := messages[mi].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("transform: message %d is not an object", mi)
		}
		switch content := msg["content"].(type) {
		case string:
			if pi != 0 {
				return nil, fmt.Errorf("transform: part index %d on string content", pi)
			}
			msg["content"] = pii.ApplyToText(content, ts)
		case []any:
			if pi < 0 || pi >= len(content) {
				return nil, fmt.Errorf("transform: part index %d out of range", pi)
			}
			part, ok := content[pi].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("transform: content part %d is not an object", pi)
			}
			text, _ := part["text"].(string)
			part["text"] = pii.ApplyToText(text, ts)
		default:
			// null / non-text content: nothing to transform; skip silently —
			// findings cannot exist on content that has no text.
		}
	}
	return json.Marshal(doc)
}

// stripRestrictedTools removes policy-restricted tool definitions and
// assistant tool calls for those tools from the request body (T-025).
func stripRestrictedTools(raw []byte, restricted []string) ([]byte, error) {
	if len(restricted) == 0 {
		return raw, nil
	}
	blocked := map[string]bool{}
	for _, name := range restricted {
		blocked[name] = true
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("restrict tools: reparse body: %w", err)
	}
	root, ok := doc.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("restrict tools: body is not a JSON object")
	}

	// Strip tool definitions.
	if tools, ok := root["tools"].([]any); ok {
		var kept []any
		for _, t := range tools {
			tool, ok := t.(map[string]any)
			if !ok {
				kept = append(kept, t)
				continue
			}
			fn, _ := tool["function"].(map[string]any)
			name, _ := fn["name"].(string)
			if blocked[name] {
				continue
			}
			kept = append(kept, t)
		}
		if len(kept) == 0 {
			delete(root, "tools")
		} else {
			root["tools"] = kept
		}
	}

	// Strip pending tool calls for restricted tools.
	if messages, ok := root["messages"].([]any); ok {
		for _, m := range messages {
			msg, ok := m.(map[string]any)
			if !ok {
				continue
			}
			calls, ok := msg["tool_calls"].([]any)
			if !ok {
				continue
			}
			var kept []any
			for _, c := range calls {
				call, ok := c.(map[string]any)
				if !ok {
					kept = append(kept, c)
					continue
				}
				fn, _ := call["function"].(map[string]any)
				name, _ := fn["name"].(string)
				if blocked[name] {
					continue
				}
				kept = append(kept, c)
			}
			if len(kept) == 0 {
				delete(msg, "tool_calls")
			} else {
				msg["tool_calls"] = kept
			}
		}
	}
	return json.Marshal(doc)
}

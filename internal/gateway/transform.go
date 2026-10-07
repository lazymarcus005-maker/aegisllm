package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/aegisllm/gateway/internal/pii"
)

// applyTransformationsToBody is the compatibility seam for the original chat
// endpoint; format-specific rewriting now lives on the chat normalizer.
func applyTransformationsToBody(raw []byte, transforms []pii.Transformation) ([]byte, error) {
	return (openAIChatNormalizer{}).RewriteRequest(raw, transforms)
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

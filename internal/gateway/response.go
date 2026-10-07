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
	return (openAIChatNormalizer{}).ParseResponse(raw)
}

// applyPlanToResponseBody is the compatibility seam for the original chat
// endpoint; format-specific rewriting now lives on the chat normalizer.
func applyPlanToResponseBody(raw []byte, plan []pii.Transformation) ([]byte, error) {
	return (openAIChatNormalizer{}).RewriteResponse(raw, plan)
}

// placeholderRe matches both the legacy development label and the P1.9
// opaque label. The resolver still performs the cryptographic validation.
var placeholderRe = regexp.MustCompile(`<((?:[A-Z][A-Z0-9_]*_[0-9]{3})|(?:v1(?:\.[A-Za-z0-9:_-]+){3,4}))>`)

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

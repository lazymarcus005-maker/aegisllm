package gateway

import (
	"regexp"
	"strings"

	"github.com/aegisllm/gateway/internal/core"
)

var placeholderRe = regexp.MustCompile(`<((?:[A-Z][A-Z0-9_]*_[0-9]{3})|(?:v1(?:\.[A-Za-z0-9:_-]+){3,4}))>`)

// ParseChatCompletionsResponse normalizes an OpenAI chat completions response
// into an InspectionEnvelope(direction=RESPONSE). The raw body remains the
// source of truth for forwarding; this envelope is for inspection only.
func ParseChatCompletionsResponse(raw []byte) (*core.InspectionEnvelope, error) {
	return (openAIChatNormalizer{}).ParseResponse(raw)
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
		text = strings.Join([]string{text[:m[0]], value, text[m[1]:]}, "")
		changed = true
	}
	return text, changed
}

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/pii"
)

// Normalizer converts one wire format into the shared inspection envelope and
// owns the format-specific transformation seam. Raw content is never logged.
type Normalizer interface {
	Family() string
	ParseRequest(raw []byte) (*core.InspectionEnvelope, error)
	RewriteRequest(raw []byte, plan []pii.Transformation) ([]byte, error)
	ParseResponse(raw []byte) (*core.InspectionEnvelope, error)
	RewriteResponse(raw []byte, plan []pii.Transformation) ([]byte, error)
}

type openAIChatNormalizer struct{}
type openAIResponsesNormalizer struct{}
type openAICompletionsNormalizer struct{}
type openAIEmbeddingsNormalizer struct{}
type anthropicMessagesNormalizer struct{ legacyComplete bool }
type genericSupersetNormalizer struct{}

func (openAIChatNormalizer) Family() string          { return "openai" }
func (openAIResponsesNormalizer) Family() string     { return "openai" }
func (openAICompletionsNormalizer) Family() string   { return "openai" }
func (openAIEmbeddingsNormalizer) Family() string    { return "openai" }
func (a anthropicMessagesNormalizer) Family() string { return "anthropic" }
func (genericSupersetNormalizer) Family() string     { return "generic" }

// NormalizerFor maps canonical endpoints and supports generic aliases nested
// under an optional deployment prefix.
func NormalizerFor(path string) Normalizer {
	path = strings.TrimSuffix(path, "/")
	switch path {
	case "/v1/chat/completions":
		return openAIChatNormalizer{}
	case "/v1/responses":
		return openAIResponsesNormalizer{}
	case "/v1/completions":
		return openAICompletionsNormalizer{}
	case "/v1/embeddings":
		return openAIEmbeddingsNormalizer{}
	case "/v1/messages", "/anthropic/v1/messages":
		return anthropicMessagesNormalizer{}
	case "/v1/complete":
		return anthropicMessagesNormalizer{legacyComplete: true}
	case "/message", "/messages", "/chatcompletion", "/chat/completions", "/response", "/responses", "/v1/message", "/v1/response":
		return genericSupersetNormalizer{}
	}
	for _, suffix := range []string{"/chat/completions", "/chatcompletion", "/messages", "/message", "/responses", "/response"} {
		if strings.HasSuffix(path, suffix) {
			return genericSupersetNormalizer{}
		}
	}
	return nil
}

func requestEnvelope(model, family string, stream bool) *core.InspectionEnvelope {
	env := &core.InspectionEnvelope{
		RequestID: newRequestID(), Direction: core.DirectionRequest,
		Target: core.Target{Model: model}, Metadata: map[string]string{"endpoint_family": family},
	}
	if stream {
		env.Metadata["stream"] = "true"
	}
	return env
}

func responseEnvelope(model string) *core.InspectionEnvelope {
	return &core.InspectionEnvelope{RequestID: newRequestID(), Direction: core.DirectionResponse, Target: core.Target{Model: model}}
}

func decodeObject(raw []byte) (map[string]json.RawMessage, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("invalid JSON body: %w", err)
	}
	if doc == nil {
		return nil, fmt.Errorf("request body must be a JSON object")
	}
	return doc, nil
}

func rawString(doc map[string]json.RawMessage, key string) (string, bool, error) {
	raw, ok := doc[key]
	if !ok {
		return "", false, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", true, fmt.Errorf("%s must be a string", key)
	}
	return value, true, nil
}

func parseOpenAITools(raw json.RawMessage) []core.ToolDefinition {
	var tools []openAITool
	if json.Unmarshal(raw, &tools) != nil {
		return nil
	}
	out := make([]core.ToolDefinition, 0, len(tools))
	for _, t := range tools {
		out = append(out, core.ToolDefinition{Name: t.Function.Name, Description: t.Function.Description, Schema: t.Function.Parameters})
	}
	return out
}

func openAIChatRequest(raw []byte, family string) (*core.InspectionEnvelope, error) {
	env, err := ParseChatCompletions(raw)
	if err != nil {
		return nil, err
	}
	if env.Metadata == nil {
		env.Metadata = map[string]string{}
	}
	env.Metadata["endpoint_family"] = family
	return env, nil
}

func (openAIChatNormalizer) ParseRequest(raw []byte) (*core.InspectionEnvelope, error) {
	return openAIChatRequest(raw, "openai")
}

func (openAIChatNormalizer) RewriteRequest(raw []byte, plan []pii.Transformation) ([]byte, error) {
	return rewriteJSONTargets(raw, plan, buildOpenAIRequestTargets)
}

func (openAIChatNormalizer) ParseResponse(raw []byte) (*core.InspectionEnvelope, error) {
	return parseOpenAIResponse(raw, "chat")
}

func (openAIChatNormalizer) RewriteResponse(raw []byte, plan []pii.Transformation) ([]byte, error) {
	return rewriteJSONTargets(raw, plan, buildOpenAIResponseTargets)
}

func (openAIResponsesNormalizer) ParseRequest(raw []byte) (*core.InspectionEnvelope, error) {
	doc, err := decodeObject(raw)
	if err != nil {
		return nil, err
	}
	model, ok, err := rawString(doc, "model")
	if err != nil {
		return nil, err
	}
	if !ok || model == "" {
		return nil, fmt.Errorf("missing required field: model")
	}
	var stream bool
	_ = json.Unmarshal(doc["stream"], &stream)
	env := requestEnvelope(model, "openai", stream)
	if instructions, _, _ := rawString(doc, "instructions"); instructions != "" {
		env.Messages = append(env.Messages, core.Message{Role: core.RoleSystem, Parts: []core.ContentPart{{Type: core.PartText, Text: instructions}}})
	}
	input, exists := doc["input"]
	if !exists {
		input = doc["input_text"]
	}
	if len(input) == 0 || string(input) == "null" {
		return nil, fmt.Errorf("missing required field: input")
	}
	if err := appendResponsesInput(env, input); err != nil {
		return nil, err
	}
	if len(env.Messages) == 0 {
		return nil, fmt.Errorf("missing required field: input")
	}
	env.Tools = parseOpenAITools(doc["tools"])
	return env, nil
}

func appendResponsesInput(env *core.InspectionEnvelope, raw json.RawMessage) error {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		if text == "" {
			return fmt.Errorf("input must not be empty")
		}
		env.Messages = append(env.Messages, core.Message{Role: core.RoleUser, Parts: []core.ContentPart{{Type: core.PartText, Text: text}}})
		return nil
	}
	var messages []struct {
		Role      string          `json:"role"`
		Content   json.RawMessage `json:"content"`
		InputText string          `json:"input_text"`
	}
	if json.Unmarshal(raw, &messages) == nil && messages != nil {
		if len(messages) == 0 {
			return fmt.Errorf("missing required field: input")
		}
		for i, m := range messages {
			role := m.Role
			if role == "" {
				role = "user"
			}
			content := m.Content
			if len(content) == 0 && m.InputText != "" {
				content, _ = json.Marshal(m.InputText)
			}
			parts, err := parseContent(content)
			if err != nil {
				return fmt.Errorf("input[%d]: %w", i, err)
			}
			if len(parts) == 0 {
				return fmt.Errorf("input[%d]: content must not be empty", i)
			}
			env.Messages = append(env.Messages, core.Message{Role: core.Role(role), Parts: parts})
		}
		return nil
	}
	var object struct {
		InputText string          `json:"input_text"`
		Content   json.RawMessage `json:"content"`
	}
	if json.Unmarshal(raw, &object) == nil && object.InputText != "" {
		env.Messages = append(env.Messages, core.Message{Role: core.RoleUser, Parts: []core.ContentPart{{Type: core.PartText, Text: object.InputText}}})
		return nil
	}
	return fmt.Errorf("input must be a string or array of messages")
}

func (openAIResponsesNormalizer) RewriteRequest(raw []byte, plan []pii.Transformation) ([]byte, error) {
	return rewriteJSONTargets(raw, plan, buildResponsesRequestTargets)
}
func (openAIResponsesNormalizer) ParseResponse(raw []byte) (*core.InspectionEnvelope, error) {
	return parseStructuredResponse(raw, "responses")
}
func (openAIResponsesNormalizer) RewriteResponse(raw []byte, plan []pii.Transformation) ([]byte, error) {
	return rewriteJSONTargets(raw, plan, buildResponsesResponseTargets)
}

func (openAICompletionsNormalizer) ParseRequest(raw []byte) (*core.InspectionEnvelope, error) {
	doc, err := decodeObject(raw)
	if err != nil {
		return nil, err
	}
	model, ok, err := rawString(doc, "model")
	if err != nil {
		return nil, err
	}
	if !ok || model == "" {
		return nil, fmt.Errorf("missing required field: model")
	}
	var prompts []string
	if err := json.Unmarshal(doc["prompt"], &prompts); err != nil {
		var prompt string
		if err := json.Unmarshal(doc["prompt"], &prompt); err != nil {
			return nil, fmt.Errorf("missing required field: prompt")
		}
		prompts = []string{prompt}
	}
	if len(prompts) == 0 {
		return nil, fmt.Errorf("missing required field: prompt")
	}
	env := requestEnvelope(model, "openai", false)
	var stream bool
	_ = json.Unmarshal(doc["stream"], &stream)
	if stream {
		env.Metadata["stream"] = "true"
	}
	for i, prompt := range prompts {
		if prompt == "" {
			return nil, fmt.Errorf("prompt[%d] must not be empty", i)
		}
		env.Messages = append(env.Messages, core.Message{Role: core.RoleUser, Parts: []core.ContentPart{{Type: core.PartText, Text: prompt}}})
	}
	return env, nil
}
func (openAICompletionsNormalizer) RewriteRequest(raw []byte, plan []pii.Transformation) ([]byte, error) {
	return rewriteJSONTargets(raw, plan, buildPromptTargets)
}
func (openAICompletionsNormalizer) ParseResponse(raw []byte) (*core.InspectionEnvelope, error) {
	return parseStructuredResponse(raw, "completions")
}
func (openAICompletionsNormalizer) RewriteResponse(raw []byte, plan []pii.Transformation) ([]byte, error) {
	return rewriteJSONTargets(raw, plan, buildCompletionResponseTargets)
}

func (openAIEmbeddingsNormalizer) ParseRequest(raw []byte) (*core.InspectionEnvelope, error) {
	doc, err := decodeObject(raw)
	if err != nil {
		return nil, err
	}
	model, ok, err := rawString(doc, "model")
	if err != nil {
		return nil, err
	}
	if !ok || model == "" {
		return nil, fmt.Errorf("missing required field: model")
	}
	var inputs []string
	if err := json.Unmarshal(doc["input"], &inputs); err != nil {
		var input string
		if err := json.Unmarshal(doc["input"], &input); err != nil {
			return nil, fmt.Errorf("missing required field: input")
		}
		inputs = []string{input}
	}
	if len(inputs) == 0 {
		return nil, fmt.Errorf("missing required field: input")
	}
	env := requestEnvelope(model, "openai", false)
	for i, input := range inputs {
		if input == "" {
			return nil, fmt.Errorf("input[%d] must not be empty", i)
		}
		env.Messages = append(env.Messages, core.Message{Role: core.RoleUser, Parts: []core.ContentPart{{Type: core.PartText, Text: input}}})
	}
	return env, nil
}
func (openAIEmbeddingsNormalizer) RewriteRequest(raw []byte, plan []pii.Transformation) ([]byte, error) {
	return rewriteJSONTargets(raw, plan, buildInputTargets)
}
func (openAIEmbeddingsNormalizer) ParseResponse(raw []byte) (*core.InspectionEnvelope, error) {
	return responseEnvelope(""), nil
}
func (openAIEmbeddingsNormalizer) RewriteResponse(raw []byte, _ []pii.Transformation) ([]byte, error) {
	return raw, nil
}

func (a anthropicMessagesNormalizer) ParseRequest(raw []byte) (*core.InspectionEnvelope, error) {
	doc, err := decodeObject(raw)
	if err != nil {
		return nil, err
	}
	model, ok, err := rawString(doc, "model")
	if err != nil {
		return nil, err
	}
	if !ok || model == "" {
		return nil, fmt.Errorf("missing required field: model")
	}
	if a.legacyComplete {
		prompt, ok, err := rawString(doc, "prompt")
		if err != nil {
			return nil, err
		}
		if !ok || prompt == "" {
			return nil, fmt.Errorf("missing required field: prompt")
		}
		env := requestEnvelope(model, "anthropic", false)
		env.Messages = append(env.Messages, core.Message{Role: core.RoleUser, Parts: []core.ContentPart{{Type: core.PartText, Text: prompt}}})
		return env, nil
	}
	var stream bool
	_ = json.Unmarshal(doc["stream"], &stream)
	env := requestEnvelope(model, "anthropic", stream)
	if system, exists := doc["system"]; exists && string(system) != "null" {
		parts, err := parseContent(system)
		if err != nil {
			return nil, fmt.Errorf("system: %w", err)
		}
		if len(parts) > 0 {
			env.Messages = append(env.Messages, core.Message{Role: core.RoleSystem, Parts: parts})
		}
	}
	var messages []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(doc["messages"], &messages); err != nil || len(messages) == 0 {
		return nil, fmt.Errorf("missing required field: messages")
	}
	for i, m := range messages {
		if m.Role == "" {
			return nil, fmt.Errorf("messages[%d]: missing role", i)
		}
		parts, err := parseContent(m.Content)
		if err != nil {
			return nil, fmt.Errorf("messages[%d]: %w", i, err)
		}
		if len(parts) == 0 {
			return nil, fmt.Errorf("messages[%d]: content must not be empty", i)
		}
		env.Messages = append(env.Messages, core.Message{Role: core.Role(m.Role), Parts: parts})
	}
	var tools []struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		InputSchema json.RawMessage `json:"input_schema"`
	}
	if json.Unmarshal(doc["tools"], &tools) == nil {
		for _, t := range tools {
			env.Tools = append(env.Tools, core.ToolDefinition{Name: t.Name, Description: t.Description, Schema: t.InputSchema})
		}
	}
	return env, nil
}
func (a anthropicMessagesNormalizer) RewriteRequest(raw []byte, plan []pii.Transformation) ([]byte, error) {
	if a.legacyComplete {
		return rewriteJSONTargets(raw, plan, buildPromptTargets)
	}
	return rewriteJSONTargets(raw, plan, buildAnthropicRequestTargets)
}
func (a anthropicMessagesNormalizer) ParseResponse(raw []byte) (*core.InspectionEnvelope, error) {
	if a.legacyComplete {
		return parseStructuredResponse(raw, "complete")
	}
	return parseStructuredResponse(raw, "anthropic")
}
func (a anthropicMessagesNormalizer) RewriteResponse(raw []byte, plan []pii.Transformation) ([]byte, error) {
	if a.legacyComplete {
		return rewriteJSONTargets(raw, plan, buildAnthropicResponseTargets)
	}
	return rewriteJSONTargets(raw, plan, buildAnthropicResponseTargets)
}

func (genericSupersetNormalizer) ParseRequest(raw []byte) (*core.InspectionEnvelope, error) {
	if env, err := openAIChatRequest(raw, "openai"); err == nil {
		if doc, decodeErr := decodeObject(raw); decodeErr == nil {
			if _, hasSystem := doc["system"]; hasSystem {
				if anthropic, anthropicErr := (anthropicMessagesNormalizer{}).ParseRequest(raw); anthropicErr == nil {
					anthropic.Metadata["endpoint_family"] = "anthropic"
					return anthropic, nil
				}
			}
			if _, hasMaxTokens := doc["max_tokens"]; hasMaxTokens {
				if anthropic, anthropicErr := (anthropicMessagesNormalizer{}).ParseRequest(raw); anthropicErr == nil {
					anthropic.Metadata["endpoint_family"] = "anthropic"
					return anthropic, nil
				}
			}
		}
		return env, nil
	}
	if env, err := (anthropicMessagesNormalizer{}).ParseRequest(raw); err == nil {
		env.Metadata["endpoint_family"] = "anthropic"
		return env, nil
	}
	doc, err := decodeObject(raw)
	if err != nil {
		return nil, err
	}
	model, _, _ := rawString(doc, "model")
	for _, key := range []string{"prompt", "input", "text", "content"} {
		if value, ok := doc[key]; ok {
			text, ok := valueAsText(value)
			if ok && text != "" {
				env := requestEnvelope(model, "generic", false)
				env.Messages = []core.Message{{Role: core.RoleUser, Parts: []core.ContentPart{{Type: core.PartText, Text: text}}}}
				return env, nil
			}
		}
	}
	return nil, fmt.Errorf("request does not match a supported endpoint shape")
}
func (genericSupersetNormalizer) RewriteRequest(raw []byte, plan []pii.Transformation) ([]byte, error) {
	return rewriteJSONTargets(raw, plan, buildGenericRequestTargets)
}
func (genericSupersetNormalizer) ParseResponse(raw []byte) (*core.InspectionEnvelope, error) {
	var shape struct {
		Choices []struct {
			Message json.RawMessage `json:"message"`
			Text    string          `json:"text"`
		} `json:"choices"`
	}
	if json.Unmarshal(raw, &shape) == nil && len(shape.Choices) > 0 {
		if len(shape.Choices[0].Message) > 0 {
			return parseOpenAIResponse(raw, "chat")
		}
		return parseStructuredResponse(raw, "completions")
	}
	return parseStructuredResponse(raw, "generic")
}
func (genericSupersetNormalizer) RewriteResponse(raw []byte, plan []pii.Transformation) ([]byte, error) {
	return rewriteJSONTargets(raw, plan, buildGenericResponseTargets)
}

func valueAsText(raw json.RawMessage) (string, bool) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s, true
	}
	var obj struct {
		InputText string `json:"input_text"`
	}
	if json.Unmarshal(raw, &obj) == nil && obj.InputText != "" {
		return obj.InputText, true
	}
	return "", false
}

// textTarget preserves the normalized message/part coordinates while holding
// a setter into the decoded wire document.
type textTarget struct {
	message, part int
	text          string
	set           func(string)
}
type targetBuilder func(map[string]any) []textTarget

func rewriteJSONTargets(raw []byte, plan []pii.Transformation, build targetBuilder) ([]byte, error) {
	if len(plan) == 0 {
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
	targets := build(root)
	byKey := map[string][]pii.Transformation{}
	for _, t := range plan {
		key := fmt.Sprintf("%d/%d", t.MessageIndex, t.PartIndex)
		byKey[key] = append(byKey[key], t)
	}
	for _, target := range targets {
		key := fmt.Sprintf("%d/%d", target.message, target.part)
		if ts := byKey[key]; len(ts) > 0 {
			target.set(pii.ApplyToText(target.text, ts))
			delete(byKey, key)
		}
	}
	for key := range byKey {
		return nil, fmt.Errorf("transform: target %s not found", key)
	}
	return json.Marshal(doc)
}

func buildContentTargets(raw any, message int, nextPart int, out *[]textTarget) int {
	switch content := raw.(type) {
	case string:
		// String fields are added by the caller, which owns their map key.
		_ = content
	case []any:
		for i, item := range content {
			if part, ok := item.(map[string]any); ok {
				if text, ok := contentText(part); ok {
					p := i
					*out = append(*out, textTarget{message: message, part: p, text: text, set: func(v string) { partTextSet(part, v) }})
				}
			}
		}
	}
	return nextPart
}
func buildMessageContentTargets(msg map[string]any, message int, out *[]textTarget) {
	if text, ok := msg["content"].(string); ok {
		if text != "" {
			*out = append(*out, textTarget{message: message, part: 0, text: text, set: func(v string) { msg["content"] = v }})
		}
		return
	}
	buildContentTargets(msg["content"], message, 0, out)
}
func buildFieldContentTargets(root map[string]any, key string, message int, out *[]textTarget) {
	if text, ok := root[key].(string); ok {
		if text != "" {
			*out = append(*out, textTarget{message: message, part: 0, text: text, set: func(v string) { root[key] = v }})
		}
		return
	}
	buildContentTargets(root[key], message, 0, out)
}
func contentText(part map[string]any) (string, bool) {
	for _, key := range []string{"text", "input_text", "output_text"} {
		if text, ok := part[key].(string); ok {
			return text, true
		}
	}
	return "", false
}
func partTextSet(part map[string]any, value string) {
	if _, ok := part["text"]; ok {
		part["text"] = value
	} else if _, ok := part["input_text"]; ok {
		part["input_text"] = value
	} else {
		part["output_text"] = value
	}
}

func buildOpenAIRequestTargets(root map[string]any) []textTarget {
	var out []textTarget
	messages, _ := root["messages"].([]any)
	for mi, msgAny := range messages {
		msg, _ := msgAny.(map[string]any)
		buildMessageContentTargets(msg, mi, &out)
		if calls, ok := msg["tool_calls"].([]any); ok {
			part := contentPartCount(msg["content"])
			for _, callAny := range calls {
				call, _ := callAny.(map[string]any)
				fn, _ := call["function"].(map[string]any)
				if text, ok := fn["arguments"].(string); ok {
					f := fn
					out = append(out, textTarget{mi, part, text, func(v string) { f["arguments"] = v }})
					part++
				}
			}
		}
	}
	return out
}
func contentPartCount(raw any) int {
	if arr, ok := raw.([]any); ok {
		return len(arr)
	}
	if _, ok := raw.(string); ok {
		return 1
	}
	return 0
}
func buildResponsesRequestTargets(root map[string]any) []textTarget {
	var out []textTarget
	if text, ok := root["input"].(string); ok {
		return []textTarget{{0, 0, text, func(v string) { root["input"] = v }}}
	}
	if text, ok := root["input_text"].(string); ok {
		return []textTarget{{0, 0, text, func(v string) { root["input_text"] = v }}}
	}
	if input, ok := root["input"].(map[string]any); ok {
		if text, ok := input["input_text"].(string); ok {
			return []textTarget{{0, 0, text, func(v string) { input["input_text"] = v }}}
		}
	}
	if messages, ok := root["input"].([]any); ok {
		for mi, itemAny := range messages {
			item, _ := itemAny.(map[string]any)
			buildMessageContentTargets(item, mi, &out)
			if text, ok := item["input_text"].(string); ok {
				i := mi
				out = append(out, textTarget{i, 0, text, func(v string) { item["input_text"] = v }})
			}
		}
	}
	return out
}
func buildPromptTargets(root map[string]any) []textTarget {
	var out []textTarget
	switch prompt := root["prompt"].(type) {
	case string:
		out = append(out, textTarget{0, 0, prompt, func(v string) { root["prompt"] = v }})
	case []any:
		for i, value := range prompt {
			if text, ok := value.(string); ok {
				idx := i
				out = append(out, textTarget{idx, 0, text, func(v string) { prompt[idx] = v }})
			}
		}
	}
	return out
}
func buildInputTargets(root map[string]any) []textTarget {
	var out []textTarget
	switch input := root["input"].(type) {
	case string:
		out = append(out, textTarget{0, 0, input, func(v string) { root["input"] = v }})
	case []any:
		for i, value := range input {
			if text, ok := value.(string); ok {
				idx := i
				out = append(out, textTarget{idx, 0, text, func(v string) { input[idx] = v }})
			}
		}
	}
	return out
}
func buildAnthropicRequestTargets(root map[string]any) []textTarget {
	var out []textTarget
	mi := 0
	if _, ok := root["system"]; ok {
		buildFieldContentTargets(root, "system", mi, &out)
		mi++
	}
	messages, _ := root["messages"].([]any)
	for _, itemAny := range messages {
		item, _ := itemAny.(map[string]any)
		buildMessageContentTargets(item, mi, &out)
		mi++
	}
	return out
}

func buildOpenAIResponseTargets(root map[string]any) []textTarget {
	var out []textTarget
	choices, _ := root["choices"].([]any)
	for mi, itemAny := range choices {
		item, _ := itemAny.(map[string]any)
		msg, _ := item["message"].(map[string]any)
		buildMessageContentTargets(msg, mi, &out)
		part := contentPartCount(msg["content"])
		calls, _ := msg["tool_calls"].([]any)
		for _, callAny := range calls {
			call, _ := callAny.(map[string]any)
			fn, _ := call["function"].(map[string]any)
			if text, ok := fn["arguments"].(string); ok {
				f := fn
				out = append(out, textTarget{mi, part, text, func(v string) { f["arguments"] = v }})
				part++
			}
		}
	}
	return out
}
func buildResponsesResponseTargets(root map[string]any) []textTarget { return buildOutputTargets(root) }
func buildOutputTargets(root map[string]any) []textTarget {
	var out []textTarget
	values, _ := root["output"].([]any)
	if len(values) == 0 {
		values, _ = root["data"].([]any)
	}
	for mi, valueAny := range values {
		value, _ := valueAny.(map[string]any)
		if text, ok := value["text"].(string); ok {
			idx := mi
			out = append(out, textTarget{idx, 0, text, func(v string) { value["text"] = v }})
		}
		buildFieldContentTargets(value, "content", mi, &out)
	}
	return out
}
func buildCompletionResponseTargets(root map[string]any) []textTarget {
	var out []textTarget
	choices, _ := root["choices"].([]any)
	for i, itemAny := range choices {
		item, _ := itemAny.(map[string]any)
		if text, ok := item["text"].(string); ok {
			idx := i
			out = append(out, textTarget{idx, 0, text, func(v string) { item["text"] = v }})
		}
	}
	return out
}
func buildAnthropicResponseTargets(root map[string]any) []textTarget {
	var out []textTarget
	if text, ok := root["completion"].(string); ok {
		out = append(out, textTarget{0, 0, text, func(v string) { root["completion"] = v }})
		return out
	}
	buildFieldContentTargets(root, "content", 0, &out)
	return out
}
func buildGenericRequestTargets(root map[string]any) []textTarget {
	if _, ok := root["messages"]; ok {
		return buildOpenAIRequestTargets(root)
	}
	if _, ok := root["prompt"]; ok {
		return buildPromptTargets(root)
	}
	if _, ok := root["input"]; ok {
		return buildInputTargets(root)
	}
	var out []textTarget
	for _, key := range []string{"text", "content"} {
		if text, ok := root[key].(string); ok {
			k := key
			out = append(out, textTarget{0, 0, text, func(v string) { root[k] = v }})
			break
		}
	}
	return out
}
func buildGenericResponseTargets(root map[string]any) []textTarget {
	if _, ok := root["choices"]; ok {
		if choices, _ := root["choices"].([]any); len(choices) > 0 {
			if item, _ := choices[0].(map[string]any); item != nil {
				if _, ok := item["message"]; ok {
					return buildOpenAIResponseTargets(root)
				}
			}
		}
		return buildCompletionResponseTargets(root)
	}
	if _, ok := root["output"]; ok {
		return buildOutputTargets(root)
	}
	return buildAnthropicResponseTargets(root)
}

func parseOpenAIResponse(raw []byte, shape string) (*core.InspectionEnvelope, error) {
	if shape == "chat" {
		var response struct {
			Model   string `json:"model"`
			Choices []struct {
				Message struct {
					Role      string           `json:"role"`
					Content   json.RawMessage  `json:"content"`
					ToolCalls []openAIToolCall `json:"tool_calls"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(raw, &response); err != nil {
			return nil, fmt.Errorf("invalid response JSON: %w", err)
		}
		env := responseEnvelope(response.Model)
		for i, choice := range response.Choices {
			parts, err := parseContent(choice.Message.Content)
			if err != nil {
				return nil, fmt.Errorf("choices[%d]: %w", i, err)
			}
			msg := core.Message{Role: core.Role(choice.Message.Role), Parts: parts}
			for _, tc := range choice.Message.ToolCalls {
				msg.Parts = append(msg.Parts, core.ContentPart{Type: core.PartToolCall, ToolCallID: tc.ID, ToolName: tc.Function.Name, Arguments: json.RawMessage(tc.Function.Arguments), Text: tc.Function.Arguments})
			}
			env.Messages = append(env.Messages, msg)
		}
		return env, nil
	}
	return parseStructuredResponse(raw, shape)
}
func parseStructuredResponse(raw []byte, shape string) (*core.InspectionEnvelope, error) {
	doc, err := decodeObject(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid response JSON: %w", err)
	}
	model, _, _ := rawString(doc, "model")
	env := responseEnvelope(model)
	switch shape {
	case "completions", "complete":
		var choices []struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(doc["choices"], &choices)
		if len(choices) == 0 {
			if text, ok, _ := rawString(doc, "completion"); ok {
				env.Messages = append(env.Messages, core.Message{Role: core.RoleAssistant, Parts: []core.ContentPart{{Type: core.PartText, Text: text}}})
			}
		}
		for _, choice := range choices {
			env.Messages = append(env.Messages, core.Message{Role: core.RoleAssistant, Parts: []core.ContentPart{{Type: core.PartText, Text: choice.Text}}})
		}
	case "responses", "generic":
		values := doc["output"]
		if len(values) == 0 {
			values = doc["data"]
		}
		var output []struct {
			Type    string          `json:"type"`
			Text    string          `json:"text"`
			Content json.RawMessage `json:"content"`
		}
		if json.Unmarshal(values, &output) == nil {
			for _, item := range output {
				parts, _ := parseContent(item.Content)
				if item.Text != "" {
					parts = append(parts, core.ContentPart{Type: core.PartText, Text: item.Text})
				}
				if len(parts) > 0 {
					env.Messages = append(env.Messages, core.Message{Role: core.RoleAssistant, Parts: parts})
				}
			}
		}
		if len(env.Messages) == 0 {
			if text, ok, _ := rawString(doc, "content"); ok {
				env.Messages = append(env.Messages, core.Message{Role: core.RoleAssistant, Parts: []core.ContentPart{{Type: core.PartText, Text: text}}})
			}
		}
	case "anthropic":
		parts, _ := parseContent(doc["content"])
		if text, ok, _ := rawString(doc, "completion"); ok {
			parts = append(parts, core.ContentPart{Type: core.PartText, Text: text})
		}
		if len(parts) > 0 {
			env.Messages = append(env.Messages, core.Message{Role: core.RoleAssistant, Parts: parts})
		}
	}
	return env, nil
}

func replacePlaceholdersInNormalizerBody(raw []byte, n Normalizer, resolve func(string) (string, bool)) ([]byte, bool, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return raw, false, err
	}
	root, ok := doc.(map[string]any)
	if !ok {
		return raw, false, nil
	}
	var build targetBuilder
	switch n.(type) {
	case openAIChatNormalizer:
		build = buildOpenAIResponseTargets
	case openAIResponsesNormalizer:
		build = buildResponsesResponseTargets
	case openAICompletionsNormalizer:
		build = buildCompletionResponseTargets
	case anthropicMessagesNormalizer:
		build = buildAnthropicResponseTargets
	default:
		build = buildGenericResponseTargets
	}
	changed := false
	for _, target := range build(root) {
		if value, ok := replaceInText(target.text, resolve); ok {
			target.set(value)
			changed = true
		}
	}
	if !changed {
		return raw, false, nil
	}
	out, err := json.Marshal(doc)
	return out, true, err
}

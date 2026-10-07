// Package streaming contains the bounded wire-level machinery used by the
// gateway's streaming response adapter. It deliberately knows nothing about
// policy: policy decisions remain in internal/gateway's shared pipeline.
package streaming

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

var (
	ErrEventTooLarge = errors.New("sse event exceeds configured limit")
	ErrMalformed     = errors.New("malformed sse event")
)

// Config bounds parser memory. HoldbackBytes is the minimum amount of data
// retained by the gateway between inspection decisions; the gateway validates
// the production minimum before startup.
type Config struct {
	MaxEventBytes    int64
	HoldbackBytes    int
	MaxBufferedBytes int64
}

// Event is one dispatched SSE event. Raw is retained so comments and unknown
// fields can be forwarded byte-for-byte when no content rewrite is needed.
type Event struct {
	Raw     []byte
	Lines   []string
	Data    string
	HasData bool
	Comment bool
	Event   string
	IsDone  bool
}

// Parser implements the SSE line/event rules with a hard event byte bound.
type Parser struct {
	r   *bufio.Reader
	max int64
}

func NewParser(r io.Reader, cfg Config) *Parser {
	max := cfg.MaxEventBytes
	if max <= 0 {
		max = 64 * 1024
	}
	return &Parser{r: bufio.NewReaderSize(r, 32*1024), max: max}
}

// Next returns the next complete event. EOF after a non-empty final event is
// returned with that event; the following call returns io.EOF.
func (p *Parser) Next() (Event, error) {
	var lines []string
	var raw bytes.Buffer
	for {
		line, err := p.readLine()
		if err != nil && len(line) == 0 {
			if len(lines) == 0 {
				return Event{}, err
			}
			return p.build(lines, raw.Bytes()), nil
		}
		trimmed := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if trimmed == "" {
			if len(lines) == 0 {
				if err != nil {
					return Event{}, err
				}
				continue
			}
			return p.build(lines, raw.Bytes()), nil
		}
		if raw.Len()+len(line) > int(p.max) {
			return Event{}, ErrEventTooLarge
		}
		raw.WriteString(line)
		lines = append(lines, trimmed)
		if err != nil {
			return p.build(lines, raw.Bytes()), nil
		}
	}
}

func (p *Parser) readLine() (string, error) {
	line, err := p.r.ReadString('\n')
	if len(line) > int(p.max) {
		return "", ErrEventTooLarge
	}
	return line, err
}

func (p *Parser) build(lines []string, raw []byte) Event {
	e := Event{Raw: append([]byte(nil), raw...), Lines: append([]string(nil), lines...)}
	var data []string
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, ":") {
			if strings.HasPrefix(line, ":") {
				e.Comment = true
			}
			continue
		}
		field, value, ok := strings.Cut(line, ":")
		if !ok {
			field, value = line, ""
		}
		if strings.HasPrefix(value, " ") {
			value = value[1:]
		}
		switch field {
		case "data":
			data = append(data, value)
			e.HasData = true
		case "event":
			e.Event = value
		}
	}
	e.Data = strings.Join(data, "\n")
	e.IsDone = strings.TrimSpace(e.Data) == "[DONE]"
	return e
}

// Encode returns a valid SSE event with data replaced. It preserves comments,
// event names, and unknown fields; data may contain newlines.
func (e Event) Encode(data string) []byte {
	if !e.HasData {
		return append([]byte(nil), e.Raw...)
	}
	var out bytes.Buffer
	dataLines := strings.Split(data, "\n")
	dataIndex := 0
	for _, line := range e.Lines {
		if strings.HasPrefix(line, "data:") {
			if dataIndex < len(dataLines) {
				out.WriteString("data: ")
				out.WriteString(dataLines[dataIndex])
				out.WriteString("\n")
				dataIndex++
			}
			continue
		}
		out.WriteString(line)
		out.WriteString("\n")
	}
	for dataIndex < len(dataLines) {
		out.WriteString("data: ")
		out.WriteString(dataLines[dataIndex])
		out.WriteString("\n")
		dataIndex++
	}
	out.WriteString("\n")
	return out.Bytes()
}

// Fragment is a provider-specific text delta. Path identifies the JSON value
// and is intentionally bounded to the current event, avoiding unbounded labels
// or state keyed by attacker-controlled identifiers.
type Fragment struct {
	Path []string
	Text string
	Kind string
}

// FamilyFor maps supported endpoint paths to the conservative extractor.
func FamilyFor(path string) string {
	path = strings.TrimSuffix(path, "/")
	switch {
	case path == "/v1/responses" || strings.HasSuffix(path, "/responses"):
		return "openai-responses"
	case path == "/v1/messages" || path == "/anthropic/v1/messages" || strings.HasSuffix(path, "/messages"):
		return "anthropic"
	case path == "/v1/chat/completions" || strings.HasSuffix(path, "/chat/completions"):
		return "openai-chat"
	default:
		return "generic"
	}
}

// Extract returns only known content-bearing fields. Supported providers fail
// closed on malformed JSON; generic SSE may conservatively carry plain text.
func Extract(family, data string) ([]Fragment, error) {
	if strings.TrimSpace(data) == "" || strings.TrimSpace(data) == "[DONE]" {
		return nil, nil
	}
	var root any
	if err := json.Unmarshal([]byte(data), &root); err != nil {
		if family == "generic" {
			return []Fragment{{Text: data, Kind: "text"}}, nil
		}
		return nil, fmt.Errorf("%w: provider event JSON: %v", ErrMalformed, err)
	}
	var out []Fragment
	switch family {
	case "openai-chat":
		out = appendOpenAIChat(out, root, nil)
	case "openai-responses":
		out = appendResponses(out, root, nil)
	case "anthropic":
		out = appendAnthropic(out, root, nil)
	default:
		out = appendGeneric(out, root, nil)
	}
	return out, nil
}

func appendOpenAIChat(out []Fragment, root any, base []string) []Fragment {
	m, ok := root.(map[string]any)
	if !ok {
		return out
	}
	choices, _ := m["choices"].([]any)
	for i, item := range choices {
		cm, _ := item.(map[string]any)
		delta, _ := cm["delta"].(map[string]any)
		if text, ok := delta["content"].(string); ok {
			out = append(out, Fragment{Path: []string{"choices", strconv.Itoa(i), "delta", "content"}, Text: text, Kind: "text"})
		}
		calls, _ := delta["tool_calls"].([]any)
		for j, call := range calls {
			callMap, _ := call.(map[string]any)
			fn, _ := callMap["function"].(map[string]any)
			if args, ok := fn["arguments"].(string); ok {
				out = append(out, Fragment{Path: []string{"choices", strconv.Itoa(i), "delta", "tool_calls", strconv.Itoa(j), "function", "arguments"}, Text: args, Kind: "tool_arguments"})
			}
		}
	}
	return out
}

func appendResponses(out []Fragment, root any, _ []string) []Fragment {
	m, ok := root.(map[string]any)
	if !ok {
		return out
	}
	typ, _ := m["type"].(string)
	for _, key := range []string{"delta", "text", "output_text", "arguments"} {
		if text, ok := m[key].(string); ok && responseKeyAllowed(typ, key) {
			out = append(out, Fragment{Path: []string{key}, Text: text, Kind: responseKind(typ, key)})
		}
	}
	if item, ok := m["item"].(map[string]any); ok {
		if args, ok := item["arguments"].(string); ok {
			out = append(out, Fragment{Path: []string{"item", "arguments"}, Text: args, Kind: "tool_arguments"})
		}
	}
	return out
}

func responseKeyAllowed(typ, key string) bool {
	if strings.HasPrefix(typ, "response.output_text.") || strings.Contains(typ, "function_call_arguments") || strings.Contains(typ, "tool") {
		return true
	}
	return key != "delta"
}

func responseKind(typ, key string) string {
	if key == "arguments" || strings.Contains(typ, "function_call") || strings.Contains(typ, "tool") {
		return "tool_arguments"
	}
	return "text"
}

func appendAnthropic(out []Fragment, root any, _ []string) []Fragment {
	m, ok := root.(map[string]any)
	if !ok {
		return out
	}
	if m["type"] != "content_block_delta" {
		return out
	}
	delta, _ := m["delta"].(map[string]any)
	for _, key := range []string{"text", "partial_json"} {
		if text, ok := delta[key].(string); ok {
			kind := "text"
			if key == "partial_json" {
				kind = "tool_arguments"
			}
			out = append(out, Fragment{Path: []string{"delta", key}, Text: text, Kind: kind})
		}
	}
	if inputJSON, ok := delta["input_json_delta"].(map[string]any); ok {
		if partial, ok := inputJSON["partial_json"].(string); ok {
			out = append(out, Fragment{Path: []string{"delta", "input_json_delta", "partial_json"}, Text: partial, Kind: "tool_arguments"})
		}
	}
	return out
}

func appendGeneric(out []Fragment, root any, path []string) []Fragment {
	switch v := root.(type) {
	case string:
		if len(path) == 0 {
			return append(out, Fragment{Text: v, Kind: "text"})
		}
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value := v[key]
			if text, ok := value.(string); ok && genericKey(key) {
				kind := "text"
				if strings.Contains(strings.ToLower(key), "arg") || key == "partial_json" {
					kind = "tool_arguments"
				}
				out = append(out, Fragment{Path: append(append([]string{}, path...), key), Text: text, Kind: kind})
				continue
			}
			out = appendGeneric(out, value, append(append([]string{}, path...), key))
		}
	case []any:
		for i, value := range v {
			out = appendGeneric(out, value, append(append([]string{}, path...), strconv.Itoa(i)))
		}
	}
	return out
}

func genericKey(key string) bool {
	switch strings.ToLower(key) {
	case "text", "content", "delta", "output_text", "partial_json", "arguments":
		return true
	default:
		return false
	}
}

// Rewrite replaces extracted JSON string values. Plain generic text is
// rewritten directly. A nil replacement leaves the original value intact.
func Rewrite(family, data string, fragments []Fragment, replacements map[int]string) (string, error) {
	if len(replacements) == 0 || len(fragments) == 0 {
		return data, nil
	}
	var root any
	if err := json.Unmarshal([]byte(data), &root); err != nil {
		if family == "generic" {
			if replacement, ok := replacements[0]; ok {
				return replacement, nil
			}
		}
		return "", fmt.Errorf("%w: rewrite JSON: %v", ErrMalformed, err)
	}
	for index, replacement := range replacements {
		if index < 0 || index >= len(fragments) {
			return "", ErrMalformed
		}
		if family == "generic" && len(fragments[index].Path) == 0 {
			out, err := json.Marshal(replacement)
			if err != nil {
				return "", err
			}
			return string(out), nil
		}
		if err := setPath(&root, fragments[index].Path, replacement); err != nil {
			return "", err
		}
	}
	out, err := json.Marshal(root)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func setPath(root *any, path []string, value string) error {
	var current any = *root
	for i, part := range path {
		last := i == len(path)-1
		switch node := current.(type) {
		case map[string]any:
			if last {
				if _, ok := node[part]; !ok {
					return ErrMalformed
				}
				node[part] = value
				return nil
			}
			next, ok := node[part]
			if !ok {
				return ErrMalformed
			}
			current = next
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(node) {
				return ErrMalformed
			}
			if last {
				node[index] = value
				return nil
			}
			current = node[index]
		default:
			return ErrMalformed
		}
	}
	return ErrMalformed
}

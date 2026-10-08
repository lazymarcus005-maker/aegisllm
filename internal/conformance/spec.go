// Package conformance contains the privacy-safe provider compatibility lab.
// It is intentionally independent from gateway internals: all probes use
// public HTTP routes and fake providers are explicitly non-production.
package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aegisllm/gateway/internal/securetransport"
	"gopkg.in/yaml.v3"
)

const SchemaVersion = "aegisllm.conformance/v1"

type Specification struct {
	SchemaVersion string             `yaml:"schema_version" json:"schema_version"`
	Version       int                `yaml:"version" json:"version"`
	Profiles      []Profile          `yaml:"profiles" json:"profiles"`
	Unsupported   []UnsupportedField `yaml:"unsupported_fields" json:"unsupported_fields"`
	Semantics     []string           `yaml:"semantics" json:"semantics"`
}

type Profile struct {
	ID          string   `yaml:"id" json:"id"`
	Family      string   `yaml:"family" json:"family"`
	Routes      []string `yaml:"routes" json:"routes"`
	Streaming   bool     `yaml:"streaming" json:"streaming"`
	Tools       bool     `yaml:"tools" json:"tools"`
	Required    bool     `yaml:"required" json:"required"`
	Description string   `yaml:"description" json:"description"`
}

type UnsupportedField struct {
	Profile  string `yaml:"profile" json:"profile"`
	Field    string `yaml:"field" json:"field"`
	Behavior string `yaml:"behavior" json:"behavior"` // reject | ignore | pass-through
	Reason   string `yaml:"reason" json:"reason"`
}

func DefaultSpecification() Specification {
	return Specification{
		SchemaVersion: SchemaVersion, Version: 1,
		Profiles: []Profile{
			{ID: "openai-chat", Family: "openai", Routes: []string{"/v1/chat/completions"}, Streaming: true, Tools: true, Required: true, Description: "OpenAI chat/completions-compatible JSON and SSE."},
			{ID: "openai-responses", Family: "openai", Routes: []string{"/v1/responses"}, Streaming: true, Tools: true, Required: true, Description: "OpenAI Responses-compatible JSON and SSE."},
			{ID: "anthropic-messages", Family: "anthropic", Routes: []string{"/v1/messages", "/anthropic/v1/messages"}, Streaming: true, Tools: true, Required: true, Description: "Anthropic Messages-compatible JSON and SSE."},
			{ID: "generic-alias", Family: "generic", Routes: []string{"/v1/chatcompletion", "/v1/response"}, Streaming: true, Tools: true, Required: true, Description: "Generic alias route using conservative superset semantics."},
		},
		Unsupported: []UnsupportedField{
			{Profile: "openai-chat", Field: "provider_extensions", Behavior: "pass-through", Reason: "Unknown JSON members are preserved by the transport."},
			{Profile: "openai-responses", Field: "provider_extensions", Behavior: "pass-through", Reason: "Unknown JSON members are preserved by the transport."},
			{Profile: "anthropic-messages", Field: "logprobs", Behavior: "ignore", Reason: "No normalized contract exists for this field."},
			{Profile: "generic-alias", Field: "unknown_fields", Behavior: "pass-through", Reason: "Generic aliases retain provider-specific members."},
		},
		Semantics: []string{"non_stream_json", "sse_events_and_done", "tool_definitions_calls_results", "system_user_assistant_content", "unicode_thai_multimessage", "usage", "finish_and_stop_reason", "request_id", "model_alias_rewrite", "errors_rate_limits_timeouts_cancellation", "oversize_and_malformed_input"},
	}
}

func LoadSpecification(path string) (Specification, error) {
	if strings.TrimSpace(path) == "" {
		return DefaultSpecification(), nil
	}
	b, err := securetransport.ReadTrustedFile(path)
	if err != nil {
		return Specification{}, err
	}
	var s Specification
	if err := yaml.Unmarshal(b, &s); err != nil {
		return Specification{}, errors.New("conformance spec is malformed")
	}
	if err := s.Validate(); err != nil {
		return Specification{}, err
	}
	return s, nil
}

func (s Specification) Validate() error {
	if s.SchemaVersion != SchemaVersion || s.Version != 1 {
		return fmt.Errorf("conformance spec must be %s version 1", SchemaVersion)
	}
	seen := map[string]bool{}
	for _, p := range s.Profiles {
		if p.ID == "" || seen[p.ID] || p.Family == "" || len(p.Routes) == 0 {
			return errors.New("conformance profile ids, family, and routes must be unique and non-empty")
		}
		seen[p.ID] = true
	}
	return nil
}

type Case struct {
	ID       string
	Profile  string
	Required bool
	Method   string
	Path     string
	Stream   bool
	Kind     string
	Body     any
	RawBody  string
	Expected Expected
}

const httpStatusRequestEntityTooLarge = 413

type Expected struct {
	Statuses []int
	Shape    string
	ReasonID string
}

func Cases(spec Specification, profileFilter map[string]bool) []Case {
	var out []Case
	for _, p := range spec.Profiles {
		if len(profileFilter) > 0 && !profileFilter[p.ID] {
			continue
		}
		path := p.Routes[0]
		model := "conformance-alias"
		body := map[string]any{"model": model, "messages": []any{map[string]any{"role": "system", "content": "You are a careful assistant."}, map[string]any{"role": "user", "content": "สวัสดี AegisLLM — multimessage Unicode check."}}}
		if p.ID == "openai-responses" {
			body = map[string]any{"model": model, "input": []any{map[string]any{"role": "user", "content": []any{map[string]any{"type": "input_text", "text": "สวัสดี AegisLLM — responses check."}}}}}
		}
		if p.ID == "anthropic-messages" {
			body = map[string]any{"model": model, "max_tokens": 32, "system": "You are a careful assistant.", "messages": []any{map[string]any{"role": "user", "content": "สวัสดี AegisLLM — messages check."}}}
		}
		if p.ID == "generic-alias" {
			body = map[string]any{"model": model, "prompt": "สวัสดี AegisLLM — generic alias check."}
		}
		out = append(out,
			Case{ID: p.ID + "-clean", Profile: p.ID, Required: p.Required, Method: "POST", Path: path, Body: body, Expected: Expected{Statuses: []int{200}, Shape: "success"}},
			Case{ID: p.ID + "-unicode-multimessage", Profile: p.ID, Required: p.Required, Method: "POST", Path: path, Body: body, Expected: Expected{Statuses: []int{200}, Shape: "success"}},
		)
		toolBody := cloneMap(body)
		toolBody["tools"] = []any{map[string]any{"type": "function", "function": map[string]any{"name": "lookup", "description": "safe test tool", "parameters": map[string]any{"type": "object"}}}}
		out = append(out, Case{ID: p.ID + "-tool-call-result", Profile: p.ID, Required: p.Required, Method: "POST", Path: path, Body: toolBody, Expected: Expected{Statuses: []int{200}, Shape: "success"}})
		out = append(out,
			Case{ID: p.ID + "-malformed-json", Profile: p.ID, Required: p.Required, Method: "POST", Path: path, RawBody: "{malformed", Expected: Expected{Statuses: []int{400}, Shape: "error"}},
			Case{ID: p.ID + "-oversize-request", Profile: p.ID, Required: p.Required, Method: "POST", Path: path, RawBody: strings.Repeat("x", 1<<20+128), Expected: Expected{Statuses: []int{httpStatusRequestEntityTooLarge}, Shape: "error"}},
		)
		if p.Streaming {
			streamBody := cloneMap(body)
			streamBody["stream"] = true
			out = append(out, Case{ID: p.ID + "-stream", Profile: p.ID, Required: p.Required, Method: "POST", Path: path, Stream: true, Body: streamBody, Expected: Expected{Statuses: []int{200}, Shape: "stream"}})
		}
	}
	return out
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

type Report struct {
	SchemaVersion string       `json:"schema_version"`
	SpecVersion   int          `json:"spec_version"`
	Gateway       GatewayInfo  `json:"gateway"`
	Target        TargetInfo   `json:"target"`
	StartedAt     time.Time    `json:"started_at"`
	DurationMS    int64        `json:"duration_ms"`
	Required      Summary      `json:"required"`
	Optional      Summary      `json:"optional"`
	Cases         []CaseResult `json:"cases"`
}

type GatewayInfo struct {
	Commit  string `json:"commit,omitempty"`
	Version string `json:"version,omitempty"`
}
type TargetInfo struct {
	ID      string `json:"id"`
	BaseURL string `json:"base_url"`
}
type Summary struct {
	Total   int `json:"total"`
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
}
type CaseResult struct {
	ID         string        `json:"id"`
	Profile    string        `json:"profile"`
	Required   bool          `json:"required"`
	Status     string        `json:"status"`
	ReasonID   string        `json:"reason_id,omitempty"`
	DurationMS int64         `json:"duration_ms"`
	HTTPStatus int           `json:"http_status,omitempty"`
	Request    RequestShape  `json:"request"`
	Response   ResponseShape `json:"response"`
}
type RequestShape struct {
	Bytes  int      `json:"bytes"`
	SHA256 string   `json:"sha256"`
	Fields []string `json:"fields,omitempty"`
}
type ResponseShape struct {
	Bytes       int           `json:"bytes"`
	SHA256      string        `json:"sha256,omitempty"`
	ContentType string        `json:"content_type,omitempty"`
	Semantic    SemanticShape `json:"semantic"`
	Headers     []string      `json:"headers,omitempty"`
}
type SemanticShape struct {
	Kind      string `json:"kind,omitempty"`
	Object    string `json:"object,omitempty"`
	Model     string `json:"model,omitempty"`
	TextBytes int    `json:"text_bytes,omitempty"`
	Choices   int    `json:"choices,omitempty"`
	ToolCalls int    `json:"tool_calls,omitempty"`
	Finish    string `json:"finish,omitempty"`
	Stop      string `json:"stop,omitempty"`
	Usage     bool   `json:"usage"`
	Done      bool   `json:"done"`
	Events    int    `json:"events,omitempty"`
}

func (r *Report) Normalize() {
	sort.Slice(r.Cases, func(i, j int) bool { return r.Cases[i].ID < r.Cases[j].ID })
	for i := range r.Cases {
		sort.Strings(r.Cases[i].Response.Headers)
		sort.Strings(r.Cases[i].Request.Fields)
	}
}

func HashBytes(b []byte) string      { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func ArtifactSHA256(b []byte) string { return HashBytes(b) }
func MarshalDeterministic(r Report) ([]byte, error) {
	r.Normalize()
	return json.MarshalIndent(r, "", "  ")
}

func (r Report) Validate() error {
	if r.SchemaVersion != SchemaVersion || r.SpecVersion != 1 {
		return errors.New("report schema version is unsupported")
	}
	if r.Target.ID == "" || strings.Contains(r.Target.ID, "/") || strings.Contains(r.Target.ID, "?") {
		return errors.New("report target id is not sanitized")
	}
	for _, c := range r.Cases {
		if c.Status != "pass" && c.Status != "fail" && c.Status != "skip" {
			return fmt.Errorf("case %s has invalid status", c.ID)
		}
		if c.Status == "fail" && c.ReasonID == "" {
			return fmt.Errorf("case %s failure needs reason_id", c.ID)
		}
	}
	return nil
}

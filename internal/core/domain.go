// Package core defines the security gateway's domain models: normalized
// inspection envelopes, findings, and the enums every module shares.
//
// Findings are evidence only; enforcement actions come from the policy engine
// (handoff INV-001/INV-002).
package core

import (
	"encoding/json"
	"fmt"
)

// Direction identifies which data boundary content is crossing.
type Direction string

const (
	DirectionRequest    Direction = "REQUEST"
	DirectionResponse   Direction = "RESPONSE"
	DirectionToolCall   Direction = "TOOL_CALL"
	DirectionToolResult Direction = "TOOL_RESULT"
)

// FindingCategory classifies a security finding (spec §10).
type FindingCategory string

const (
	CategoryPII              FindingCategory = "PII"
	CategorySecret           FindingCategory = "SECRET"
	CategoryPromptSecurity   FindingCategory = "PROMPT_SECURITY"
	CategoryToolSecurity     FindingCategory = "TOOL_SECURITY"
	CategoryConfidentialData FindingCategory = "CONFIDENTIAL_DATA"
	CategoryPolicy           FindingCategory = "POLICY"
)

// Action is an enforcement action produced by the policy engine (FR-011).
type Action string

const (
	ActionAllow           Action = "ALLOW"
	ActionBlock           Action = "BLOCK"
	ActionRedact          Action = "REDACT"
	ActionTokenize        Action = "TOKENIZE"
	ActionReview          Action = "REVIEW"
	ActionRestrictTools   Action = "RESTRICT_TOOLS"
	ActionForceLocalModel Action = "FORCE_LOCAL_MODEL"
)

// Normalized content part types.
const (
	PartText       = "text"
	PartJSON       = "json"
	PartToolCall   = "tool_call"
	PartToolResult = "tool_result"
	PartImageRef   = "image_ref"
)

// Span locates a finding within a message part's text (spec §10 location).
type Span struct {
	MessageIndex int `json:"message_index"`
	PartIndex    int `json:"part_index"`
	Start        int `json:"start"`
	End          int `json:"end"`
}

// SecurityFinding is the internal finding schema (spec §10). It never carries
// the raw detected value; ValueHash enables correlation without exposure.
type SecurityFinding struct {
	ID         string            `json:"id"`
	Category   FindingCategory   `json:"category"`
	Subtype    string            `json:"subtype"`
	Detector   string            `json:"detector"`
	Confidence float64           `json:"confidence"`
	Location   Span              `json:"location"`
	ValueHash  string            `json:"value_hash,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Role is a normalized message role.
type Role string

const (
	RoleSystem    Role = "system"
	RoleDeveloper Role = "developer"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

// ContentPart is one normalized piece of message content.
type ContentPart struct {
	Type       string          `json:"type"`
	Text       string          `json:"text,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
	ToolName   string          `json:"tool_name,omitempty"`
	Arguments  json.RawMessage `json:"arguments,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
}

// Message is a normalized conversation message.
type Message struct {
	Role  Role          `json:"role"`
	Parts []ContentPart `json:"parts"`
}

// ToolDefinition is a normalized tool definition from the request.
type ToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Schema      json.RawMessage `json:"schema,omitempty"`
}

// Target identifies the destination model and provider class.
type Target struct {
	Provider string `json:"provider"`
	Model    string `json:"model,omitempty"`
}

// User carries caller identity metadata supplied by trusted headers.
type User struct {
	Subject string   `json:"subject,omitempty"`
	Roles   []string `json:"roles,omitempty"`
}

// InspectionEnvelope is the normalized inspection object every pipeline stage
// consumes (architecture §6.2).
type InspectionEnvelope struct {
	RequestID   string            `json:"request_id"`
	Direction   Direction         `json:"direction"`
	Application string            `json:"application,omitempty"`
	Tenant      string            `json:"tenant,omitempty"`
	User        User              `json:"user,omitempty"`
	Target      Target            `json:"target"`
	Messages    []Message         `json:"messages"`
	Tools       []ToolDefinition  `json:"tools,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// LocatedText is a text content part plus its position in the envelope.
type LocatedText struct {
	MessageIndex int
	PartIndex    int
	Role         Role
	Text         string
}

// TextParts returns every non-empty text content part in message order.
func (e *InspectionEnvelope) TextParts() []LocatedText {
	var out []LocatedText
	for mi, m := range e.Messages {
		for pi, p := range m.Parts {
			if p.Type == PartText && p.Text != "" {
				out = append(out, LocatedText{MessageIndex: mi, PartIndex: pi, Role: m.Role, Text: p.Text})
			}
		}
	}
	return out
}

// SafeString renders a content-free summary of the envelope, safe for logs,
// errors, and audit paths that must never carry raw content (T-002).
func (e InspectionEnvelope) SafeString() string {
	textParts := 0
	for _, m := range e.Messages {
		for _, p := range m.Parts {
			if p.Text != "" {
				textParts++
			}
		}
	}
	return fmt.Sprintf("request_id=%s direction=%s application=%s tenant=%s user=%s target=%s/%s messages=%d tools=%d text_parts=%d",
		e.RequestID, e.Direction, e.Application, e.Tenant, e.User.Subject,
		e.Target.Provider, e.Target.Model, len(e.Messages), len(e.Tools), textParts)
}

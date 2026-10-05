// Package audit produces sanitized decision events (FR-019, SEC-006). Events
// are built from metadata and finding types only — never raw content, never
// whole envelopes. Raw PII logging defaults to disabled (SEC-007).
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/aegisllm/gateway/internal/core"
)

// Event is the sanitized audit record. Only whitelisted fields exist by
// construction; there is no field that could accidentally carry raw content.
type Event struct {
	RequestID     string           `json:"request_id"`
	Timestamp     time.Time        `json:"timestamp"`
	Direction     core.Direction   `json:"direction"`
	Application   string           `json:"application,omitempty"`
	Tenant        string           `json:"tenant,omitempty"`
	User          string           `json:"user,omitempty"`
	PolicyID      string           `json:"policy_id,omitempty"`
	PolicyVersion int              `json:"policy_version,omitempty"`
	Mode          string           `json:"mode"`
	Action        core.Action      `json:"action"`
	Code          string           `json:"code,omitempty"`
	MatchedRule   string           `json:"matched_rule,omitempty"`
	FindingTypes  []string         `json:"finding_types,omitempty"`
	FindingCount  int              `json:"finding_count,omitempty"`
	LatencyMS     map[string]int64 `json:"latency_ms,omitempty"`
}

// Sink receives audit events.
type Sink interface {
	Record(Event)
}

// WriterSink writes one JSON object per line to an io.Writer.
type WriterSink struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func NewWriterSink(w io.Writer) *WriterSink {
	return &WriterSink{enc: json.NewEncoder(w)}
}

func (s *WriterSink) Record(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.enc.Encode(e)
}

// FindingTypes extracts distinct finding subtypes in order of appearance.
// This is the only projection of findings that may reach audit output.
func FindingTypes(findings []core.SecurityFinding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range findings {
		if !seen[f.Subtype] {
			seen[f.Subtype] = true
			out = append(out, f.Subtype)
		}
	}
	return out
}

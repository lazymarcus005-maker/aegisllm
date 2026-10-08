// Package audit defines the versioned, content-free audit contract and its
// sinks. Audit events are metadata projections: request/response bodies,
// tool arguments/results, credentials, tokens, decoded content, and errors
// are not representable in the production wire schema.
package audit

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/policy"
)

const SchemaVersion = "aegisllm.audit/v1"

// LayaDecision is bounded semantic evidence. It contains no model input or
// output, and question IDs are validated labels rather than arbitrary keys.
type LayaDecision struct {
	ID         string  `json:"id"`
	Value      bool    `json:"value"`
	Confidence float64 `json:"answer_confidence"`
}

type LayaInfo struct {
	Provider      string         `json:"provider"`
	Checkpoint    string         `json:"checkpoint,omitempty"`
	SchemaVersion string         `json:"question_schema,omitempty"`
	Route         string         `json:"route,omitempty"`
	Decisions     []LayaDecision `json:"decisions,omitempty"`
	Error         string         `json:"error,omitempty"`
}

// MarshalJSON keeps the historical semantic evidence shape while the
// in-memory representation remains a bounded typed slice. No caller can
// supply an arbitrary decisions map to the production event.
func (l LayaInfo) MarshalJSON() ([]byte, error) {
	var decisions bytes.Buffer
	decisions.WriteByte('{')
	for i, d := range l.Decisions {
		if i > 0 {
			decisions.WriteByte(',')
		}
		key, _ := json.Marshal(BoundedLabel(d.ID))
		value, _ := json.Marshal(struct {
			Value      bool    `json:"value"`
			Confidence float64 `json:"answer_confidence"`
		}{d.Value, d.Confidence})
		decisions.Write(key)
		decisions.WriteByte(':')
		decisions.Write(value)
	}
	decisions.WriteByte('}')
	type wire struct {
		Provider      string          `json:"provider"`
		Checkpoint    string          `json:"checkpoint,omitempty"`
		SchemaVersion string          `json:"question_schema,omitempty"`
		Route         string          `json:"route,omitempty"`
		Decisions     json.RawMessage `json:"decisions,omitempty"`
		Error         string          `json:"error,omitempty"`
	}
	return json.Marshal(wire{l.Provider, l.Checkpoint, l.SchemaVersion, l.Route, decisions.Bytes(), l.Error})
}

func (l *LayaInfo) UnmarshalJSON(data []byte) error {
	type wire struct {
		Provider      string          `json:"provider"`
		Checkpoint    string          `json:"checkpoint"`
		SchemaVersion string          `json:"question_schema"`
		Route         string          `json:"route"`
		Decisions     json.RawMessage `json:"decisions"`
		Error         string          `json:"error"`
	}
	var in wire
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	l.Provider, l.Checkpoint, l.SchemaVersion, l.Route, l.Error = in.Provider, in.Checkpoint, in.SchemaVersion, in.Route, in.Error
	if len(in.Decisions) == 0 || string(in.Decisions) == "null" {
		return nil
	}
	if in.Decisions[0] == '[' {
		return json.Unmarshal(in.Decisions, &l.Decisions)
	}
	var object map[string]struct {
		Value      bool    `json:"value"`
		Confidence float64 `json:"answer_confidence"`
	}
	if err := json.Unmarshal(in.Decisions, &object); err != nil {
		return err
	}
	for id, decision := range object {
		l.Decisions = append(l.Decisions, LayaDecision{ID: id, Value: decision.Value, Confidence: decision.Confidence})
	}
	return nil
}

// Latencies is intentionally a fixed shape. The legacy LatencyMS field on
// Event is retained for source compatibility with pre-P1.6 callers but is
// never serialized; production serialization uses this type only.
type Latencies struct {
	DeterministicMS int64 `json:"deterministic"`
	LayaMS          int64 `json:"laya,omitempty"`
	TotalSecurityMS int64 `json:"total_security"`
}

type Integrity struct {
	Sequence   uint64 `json:"sequence,omitempty"`
	Previous   string `json:"previous_hash,omitempty"`
	RecordHash string `json:"record_hash,omitempty"`
	KeyID      string `json:"key_id,omitempty"`
}

// Event is the only production audit payload. Keep additions explicit and
// reviewed: arbitrary maps and raw data fields are deliberately absent.
type Event struct {
	Schema             string                  `json:"schema"`
	EventID            string                  `json:"event_id"`
	RequestID          string                  `json:"request_id"`
	Timestamp          time.Time               `json:"timestamp"`
	TraceID            string                  `json:"trace_id,omitempty"`
	SpanID             string                  `json:"span_id,omitempty"`
	TraceFlags         string                  `json:"trace_flags,omitempty"`
	Direction          core.Direction          `json:"direction"`
	Application        string                  `json:"application,omitempty"`
	Tenant             string                  `json:"tenant,omitempty"`
	User               string                  `json:"user,omitempty"`
	Roles              []string                `json:"roles,omitempty"`
	Provider           string                  `json:"provider,omitempty"`
	PolicyID           string                  `json:"policy_id,omitempty"`
	PolicyVersion      int                     `json:"policy_version,omitempty"`
	PolicySequence     uint64                  `json:"policy_sequence,omitempty"`
	PolicyHash         string                  `json:"policy_hash,omitempty"`
	Mode               string                  `json:"mode"`
	Component          string                  `json:"component,omitempty"`
	Action             core.Action             `json:"action"`
	Code               string                  `json:"code,omitempty"`
	ReasonID           string                  `json:"reason_id,omitempty"`
	MatchedRule        string                  `json:"matched_rule,omitempty"`
	PrecedenceStage    string                  `json:"precedence_stage,omitempty"`
	Reason             string                  `json:"reason,omitempty"`
	FindingTypes       []string                `json:"finding_types,omitempty"`
	FindingCount       int                     `json:"finding_count,omitempty"`
	FindingSummary     []policy.FindingSummary `json:"finding_summary,omitempty"`
	EvasionTypes       []string                `json:"evasion_types,omitempty"`
	EncodingDepth      int                     `json:"encoding_depth,omitempty"`
	BudgetRejected     bool                    `json:"budget_rejected,omitempty"`
	Latencies          Latencies               `json:"latency_ms"`
	Laya               *LayaInfo               `json:"laya,omitempty"`
	PIIFallback        bool                    `json:"pii_fallback,omitempty"`
	PIIUnavailable     bool                    `json:"pii_unavailable,omitempty"`
	PredictedAction    core.Action             `json:"predicted_action,omitempty"`
	AppliedAction      core.Action             `json:"applied_action,omitempty"`
	Stream             bool                    `json:"stream,omitempty"`
	EndpointFamily     string                  `json:"endpoint_family,omitempty"`
	RouteID            string                  `json:"route_id,omitempty"`
	RouteClass         string                  `json:"route_class,omitempty"`
	RouteProvider      string                  `json:"route_provider,omitempty"`
	RequestedModel     string                  `json:"requested_model,omitempty"`
	RoutedModel        string                  `json:"routed_model,omitempty"`
	RouteReason        string                  `json:"route_reason,omitempty"`
	RouteFailover      bool                    `json:"route_failover,omitempty"`
	RAG                bool                    `json:"rag,omitempty"`
	RAGOperation       string                  `json:"rag_operation,omitempty"`
	RAGChunks          int                     `json:"rag_chunks,omitempty"`
	ToolProvider       string                  `json:"tool_provider,omitempty"`
	BytesInspected     int64                   `json:"bytes_inspected,omitempty"`
	EventsInspected    int                     `json:"events_inspected,omitempty"`
	DistributionEvent  string                  `json:"distribution_event,omitempty"`
	DistributionKeyID  string                  `json:"distribution_key_id,omitempty"`
	QuarantineID       string                  `json:"quarantine_id,omitempty"`
	QuarantineScope    string                  `json:"quarantine_scope,omitempty"`
	QuarantineStatus   string                  `json:"quarantine_status,omitempty"`
	QuarantineRevision uint64                  `json:"quarantine_revision,omitempty"`
	Integrity          Integrity               `json:"integrity,omitempty"`

	// Deprecated compatibility input. It is copied into Latencies by
	// SanitizeEvent and cannot enter JSON directly.
	LatencyMS map[string]int64 `json:"-"`
}

// SanitizeOptions controls principal privacy. Hashing uses a deployment
// secret and a stable SHA-256 digest, never a raw identity value.
type SanitizeOptions struct {
	PrincipalHMACKey []byte
	HashPrincipals   bool
}

func BoundedLabel(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 96 {
		value = value[:96]
	}
	out := []byte(value)
	for i, c := range out {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._:-/", rune(c)) {
			continue
		}
		out[i] = '_'
	}
	return string(out)
}

func ReasonID(value string) string { return BoundedLabel(value) }

func principal(value string, opts SanitizeOptions) string {
	value = BoundedLabel(value)
	if value == "" || !opts.HashPrincipals || len(opts.PrincipalHMACKey) == 0 {
		return value
	}
	h := sha256.New()
	_, _ = h.Write(opts.PrincipalHMACKey)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(value))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))[:32]
}

// SanitizeEvent normalizes all labels, strips compatibility data into the
// fixed latency struct, bounds collections, and fills required identifiers.
func SanitizeEvent(in Event, opts SanitizeOptions) Event {
	out := in
	if out.Schema == "" {
		out.Schema = SchemaVersion
	}
	if out.Timestamp.IsZero() {
		out.Timestamp = time.Now().UTC()
	}
	out.Timestamp = out.Timestamp.UTC()
	if out.EventID == "" {
		var id [16]byte
		if _, err := rand.Read(id[:]); err == nil {
			out.EventID = "evt-" + hex.EncodeToString(id[:])
		} else {
			seed := out.RequestID + "|" + out.Timestamp.Format(time.RFC3339Nano) + "|" + string(out.Direction) + "|" + string(out.Action)
			h := sha256.Sum256([]byte(seed))
			out.EventID = "evt-" + hex.EncodeToString(h[:])[:32]
		}
	}
	out.EventID = BoundedLabel(out.EventID)
	out.RequestID = BoundedLabel(out.RequestID)
	out.TraceID, out.SpanID, out.TraceFlags = BoundedLabel(out.TraceID), BoundedLabel(out.SpanID), BoundedLabel(out.TraceFlags)
	out.Application, out.Tenant, out.User = principal(out.Application, opts), principal(out.Tenant, opts), principal(out.User, opts)
	out.Provider, out.PolicyID, out.PolicyHash = BoundedLabel(out.Provider), BoundedLabel(out.PolicyID), BoundedLabel(out.PolicyHash)
	out.Mode, out.Component, out.Code, out.ReasonID, out.MatchedRule, out.PrecedenceStage, out.Reason = BoundedLabel(out.Mode), BoundedLabel(out.Component), ReasonID(out.Code), ReasonID(out.ReasonID), BoundedLabel(out.MatchedRule), BoundedLabel(out.PrecedenceStage), ReasonID(out.Reason)
	if out.ReasonID == "" {
		out.ReasonID = out.Code
	}
	out.EndpointFamily, out.RouteID, out.RouteClass, out.RouteProvider = BoundedLabel(out.EndpointFamily), BoundedLabel(out.RouteID), BoundedLabel(out.RouteClass), BoundedLabel(out.RouteProvider)
	out.RAGOperation = BoundedLabel(out.RAGOperation)
	if out.RAGChunks < 0 {
		out.RAGChunks = 0
	}
	if out.RAGChunks > 10000 {
		out.RAGChunks = 10000
	}
	out.RequestedModel, out.RoutedModel, out.RouteReason = BoundedLabel(out.RequestedModel), BoundedLabel(out.RoutedModel), ReasonID(out.RouteReason)
	out.ToolProvider, out.DistributionEvent, out.DistributionKeyID = BoundedLabel(out.ToolProvider), ReasonID(out.DistributionEvent), BoundedLabel(out.DistributionKeyID)
	out.QuarantineID, out.QuarantineScope, out.QuarantineStatus = BoundedLabel(out.QuarantineID), ReasonID(out.QuarantineScope), ReasonID(out.QuarantineStatus)
	if out.LatencyMS != nil {
		out.Latencies = Latencies{DeterministicMS: nonNegative(out.LatencyMS["deterministic"]), LayaMS: nonNegative(out.LatencyMS["laya"]), TotalSecurityMS: nonNegative(out.LatencyMS["total_security"])}
	}
	if out.Latencies.DeterministicMS < 0 {
		out.Latencies.DeterministicMS = 0
	}
	if out.Latencies.LayaMS < 0 {
		out.Latencies.LayaMS = 0
	}
	if out.Latencies.TotalSecurityMS < 0 {
		out.Latencies.TotalSecurityMS = 0
	}
	out.Roles = boundedStrings(out.Roles, 16)
	out.FindingTypes = boundedStrings(out.FindingTypes, 64)
	out.EvasionTypes = boundedStrings(out.EvasionTypes, 32)
	if out.Laya != nil {
		l := *out.Laya
		l.Provider, l.Checkpoint, l.SchemaVersion, l.Route, l.Error = BoundedLabel(l.Provider), BoundedLabel(l.Checkpoint), BoundedLabel(l.SchemaVersion), BoundedLabel(l.Route), ReasonID(l.Error)
		if len(l.Decisions) > 64 {
			l.Decisions = l.Decisions[:64]
		}
		for i := range l.Decisions {
			l.Decisions[i].ID = BoundedLabel(l.Decisions[i].ID)
		}
		out.Laya = &l
	}
	return out
}

func nonNegative(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}
func boundedStrings(values []string, max int) []string {
	if len(values) > max {
		values = values[:max]
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = BoundedLabel(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

// MarshalJSON is intentionally explicit. A future field added to Event is
// not serialized accidentally until it is added to this allowlist.
func (e Event) MarshalJSON() ([]byte, error) {
	type wire Event
	return json.Marshal(wire(SanitizeEvent(e, SanitizeOptions{})))
}

type Sink interface{ Record(Event) }

type WriterSink struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func NewWriterSink(w io.Writer) *WriterSink { return &WriterSink{enc: json.NewEncoder(w)} }
func (s *WriterSink) Record(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.enc.Encode(SanitizeEvent(e, SanitizeOptions{}))
}

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

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/aegisllm/gateway/internal/audit"
	"github.com/aegisllm/gateway/internal/auth"
	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/policy"
	"github.com/aegisllm/gateway/internal/quarantine"
	"github.com/aegisllm/gateway/internal/routing"
)

func quarantinePolicy(p *policy.Policy) quarantine.Policy {
	out := quarantine.DefaultPolicy()
	if p == nil || p.Quarantine == nil {
		out.Enabled = false
		return out
	}
	q := p.Quarantine
	out.Enabled = q.Enabled
	out.MaxStates = q.MaxStates
	if d, err := time.ParseDuration(q.MaxTTL); err == nil {
		out.MaxTTL = d
	}
	if d, err := time.ParseDuration(q.ProbationTTL); err == nil {
		out.ProbationTTL = d
	}
	convert := func(in policy.QuarantineRule) quarantine.Rule {
		r := quarantine.Rule{Reason: in.Reason, Level: in.Level, Scope: in.Scope, Threshold: in.Threshold, AllowBroad: in.AllowBroad}
		r.Window, _ = time.ParseDuration(in.Window)
		r.Cooldown, _ = time.ParseDuration(in.Cooldown)
		r.TTL, _ = time.ParseDuration(in.TTL)
		return r
	}
	out.Default = convert(q.Default)
	out.Rules = make([]quarantine.Rule, 0, len(q.Rules))
	for _, rule := range q.Rules {
		out.Rules = append(out.Rules, convert(rule))
	}
	return out
}

// QuarantinePolicyForPolicy converts the validated policy snapshot into the
// runtime containment contract for bootstrap and policy reload callers.
func QuarantinePolicyForPolicy(p *policy.Policy) quarantine.Policy { return quarantinePolicy(p) }

func (s *Server) SetQuarantine(manager *quarantine.Manager) {
	s.quarantine = manager
	if manager == nil {
		return
	}
	manager.SetObserver(func(state quarantine.State) {
		if state.Provenance != "trusted_server" {
			return
		}
		_ = s.recordAudit(context.Background(), audit.Event{RequestID: "quarantine-" + state.ID, Timestamp: time.Now().UTC(), Direction: core.DirectionRequest, Component: "quarantine", Mode: s.cfg.SecurityMode, Action: core.ActionReview, Code: "QUARANTINE_AUTOMATED_TRANSITION", ReasonID: state.Reason, QuarantineID: state.ID, QuarantineScope: state.Scope, QuarantineStatus: string(state.Status), QuarantineRevision: state.Revision})
	})
	if p := s.currentPolicy(); p != nil && p.Quarantine != nil {
		_ = manager.SetPolicy(quarantinePolicy(p))
	}
	if p, ok := s.pipeline.(interface{ SetQuarantine(*quarantine.Manager) }); ok {
		p.SetQuarantine(manager)
	}
	if s.routed != nil {
		s.routed.SetQuarantineCheck(func(ctx context.Context, r *http.Request, upstream routing.Upstream) (bool, error) {
			principal, verified := auth.PrincipalFromContext(r.Context())
			if !verified {
				return true, nil
			}
			decision, err := manager.Check(ctx, quarantine.Identity{Tenant: principal.Tenant, Application: principal.Application, Subject: principal.Subject, Session: principal.SessionID}, quarantine.Resource{Provider: upstream.Provider, Route: upstream.ID})
			if err != nil {
				return false, err
			}
			return decision.Allowed, nil
		})
	}
	if s.cfg.profile() == ProfileProduction {
		s.AddReadinessCheck("quarantine_state", func() string {
			if err := manager.Ready(context.Background()); err != nil {
				return "quarantine shared state unavailable"
			}
			return ""
		})
	}
}

func (s *Server) SetPolicyQuarantine(p *policy.Policy) {
	if s.quarantine != nil {
		_ = s.quarantine.SetPolicy(quarantinePolicy(p))
	}
}

func (s *Server) quarantineIdentity(r *http.Request, env *core.InspectionEnvelope) quarantine.Identity {
	if principal, ok := auth.PrincipalFromContext(r.Context()); ok {
		return quarantine.Identity{Tenant: principal.Tenant, Application: principal.Application, Subject: principal.Subject, Session: principal.SessionID}
	}
	return quarantine.Identity{Tenant: env.Tenant, Application: env.Application, Subject: env.User.Subject}
}

func (s *Server) checkQuarantine(ctx context.Context, r *http.Request, env *core.InspectionEnvelope, resource quarantine.Resource) (quarantine.Decision, error) {
	if s.quarantine == nil {
		return quarantine.Decision{Allowed: true}, nil
	}
	decision, err := s.quarantine.Check(ctx, s.quarantineIdentity(r, env), resource)
	if err != nil && s.cfg.profile() == ProfileProduction {
		return decision, err
	}
	return decision, nil
}

func (s *Server) enforceQuarantine(w http.ResponseWriter, decision quarantine.Decision, requestID string) bool {
	if decision.Allowed {
		if observer, ok := s.runtimeMetrics.(interface{ ObserveQuarantineDecision(string) }); ok {
			observer.ObserveQuarantineDecision("allowed")
		}
		return true
	}
	status := http.StatusForbidden
	if decision.Throttle {
		status = http.StatusTooManyRequests
		w.Header().Set("Retry-After", "60")
	}
	if observer, ok := s.runtimeMetrics.(interface{ ObserveQuarantineDecision(string) }); ok {
		if decision.Throttle {
			observer.ObserveQuarantineDecision("throttled")
		} else if decision.Code == "QUARANTINE_PROBATION" {
			observer.ObserveQuarantineDecision("probation")
		} else {
			observer.ObserveQuarantineDecision("blocked")
		}
	}
	code := decision.Code
	if code == "" {
		code = "QUARANTINED"
	}
	writeOpenAIError(w, status, "security_quarantine", code, "Request is temporarily contained by security policy.", requestID)
	return false
}

func identityFromEnvelope(env *core.InspectionEnvelope) quarantine.Identity {
	if env == nil {
		return quarantine.Identity{}
	}
	return quarantine.Identity{Tenant: env.Tenant, Application: env.Application, Subject: env.User.Subject, Session: env.Metadata["session_binding"]}
}

func signalFromFinding(env *core.InspectionEnvelope, reason string, f core.SecurityFinding, policyID string, policyVersion int) quarantine.Signal {
	return quarantine.Signal{Reason: reason, Identity: identityFromEnvelope(env), Policy: quarantine.Snapshot{ID: policyID, Version: policyVersion}, Evidence: []quarantine.EvidenceRef{{Kind: "finding", Digest: findingDigest(f)}}, Trusted: env != nil && env.Metadata["verified_identity"] == "true", IdempotencyKey: env.RequestID + ":" + reason + ":" + f.ID}
}

func findingDigest(f core.SecurityFinding) string {
	// The quarantine package validates the resulting digest as a SHA-256 hex
	// reference. The source finding itself never crosses the boundary.
	return digestFinding(f)
}

func digestFinding(f core.SecurityFinding) string {
	// Keep this helper in the gateway so signal construction cannot accidentally
	// serialize the finding's detected value or attributes.
	return quarantineDigest(string(f.Category) + "\x00" + f.Subtype + "\x00" + f.Detector + "\x00" + string(rune(f.Location.MessageIndex)) + ":" + string(rune(f.Location.PartIndex)))
}

func quarantineDigest(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}

func (s *Server) recordQuarantineSignal(ctx context.Context, signal quarantine.Signal) {
	if s.quarantine == nil || !signal.Trusted {
		return
	}
	state, created, _ := s.quarantine.Observe(ctx, signal)
	if created {
		if observer, ok := s.runtimeMetrics.(interface{ ObserveQuarantine(string, string, string) }); ok {
			observer.ObserveQuarantine(state.Reason, state.Level, state.Scope)
		}
	}
}

func (s *Server) handleQuarantineList(w http.ResponseWriter, r *http.Request) {
	if s.quarantine == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "quarantine is not configured"})
		return
	}
	summary, err := s.quarantine.ListSummary(r.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "quarantine state unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": 1, "summary": summary, "evidence": "sanitized_aggregate_only"})
}

func (s *Server) handleQuarantineInspect(w http.ResponseWriter, r *http.Request) {
	if s.quarantine == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "quarantine is not configured"})
		return
	}
	state, err := s.quarantine.Inspect(r.Context(), r.PathValue("id"))
	if errors.Is(err, quarantine.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "quarantine not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "quarantine state unavailable"})
		return
	}
	if principal, verified := auth.PrincipalFromContext(r.Context()); !verified || state.TenantDigest != quarantine.TenantDigest(principal.Tenant) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "quarantine belongs to another tenant"})
		return
	}
	writeJSON(w, http.StatusOK, state)
}

type quarantineOperatorRequest struct {
	ExpectedRevision uint64 `json:"expected_revision"`
	TTL              string `json:"ttl,omitempty"`
	Scope            string `json:"scope,omitempty"`
	Reason           string `json:"reason"`
	Confirm          bool   `json:"confirm"`
	Level            string `json:"level,omitempty"`
	Tool             string `json:"tool,omitempty"`
	Server           string `json:"server,omitempty"`
	Provider         string `json:"provider,omitempty"`
	Route            string `json:"route,omitempty"`
}

func decodeQuarantineOperatorRequest(w http.ResponseWriter, r *http.Request) (quarantineOperatorRequest, bool) {
	var req quarantineOperatorRequest
	if r.Body == nil || json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid quarantine operator request"})
		return req, false
	}
	return req, true
}

func (s *Server) handleQuarantineAction(w http.ResponseWriter, r *http.Request) {
	if s.quarantine == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "quarantine is not configured"})
		return
	}
	req, ok := decodeQuarantineOperatorRequest(w, r)
	if !ok {
		return
	}
	principal, verified := auth.PrincipalFromContext(r.Context())
	if !verified || !principal.HasRole(auth.RoleOperator) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "operator role required"})
		return
	}
	current, inspectErr := s.quarantine.Inspect(r.Context(), r.PathValue("id"))
	if inspectErr != nil || current.TenantDigest != quarantine.TenantDigest(principal.Tenant) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "quarantine belongs to another tenant"})
		return
	}
	var state quarantine.State
	var err error
	id := r.PathValue("id")
	switch r.PathValue("action") {
	case "acknowledge":
		state, err = s.quarantine.Acknowledge(r.Context(), id, req.ExpectedRevision, principal.Subject)
	case "extend":
		ttl, parseErr := time.ParseDuration(req.TTL)
		if parseErr != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ttl is invalid"})
			return
		}
		state, err = s.quarantine.Extend(r.Context(), id, req.ExpectedRevision, ttl, principal.Subject)
	case "narrow":
		state, err = s.quarantine.Narrow(r.Context(), id, req.ExpectedRevision, req.Scope, principal.Subject)
	case "release":
		state, err = s.quarantine.Release(r.Context(), id, req.ExpectedRevision, principal.Subject, req.Reason)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "quarantine action not found"})
		return
	}
	if errors.Is(err, quarantine.ErrConflict) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "stale quarantine revision"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "quarantine action rejected"})
		return
	}
	if auditErr := s.recordAudit(r.Context(), audit.Event{RequestID: "quarantine-" + state.ID, Timestamp: time.Now().UTC(), Direction: core.DirectionRequest, Component: "quarantine", Mode: s.cfg.SecurityMode, Action: core.ActionReview, Code: "QUARANTINE_OPERATOR_ACTION", ReasonID: "operator_reason", Tenant: principal.Tenant, User: principal.Subject}); auditErr != nil && s.cfg.profile() == ProfileProduction {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "durable quarantine audit unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) handleQuarantineEmergency(w http.ResponseWriter, r *http.Request) {
	if s.quarantine == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "quarantine is not configured"})
		return
	}
	req, ok := decodeQuarantineOperatorRequest(w, r)
	if !ok {
		return
	}
	principal, verified := auth.PrincipalFromContext(r.Context())
	if !verified || !principal.HasRole(auth.RoleOperator) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "operator role required"})
		return
	}
	if req.Reason == "" || !req.Confirm {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "broad containment requires confirm=true and a reason"})
		return
	}
	state, err := s.quarantine.Emergency(r.Context(), quarantine.Identity{Tenant: principal.Tenant, Application: principal.Application, Subject: principal.Subject, Session: principal.SessionID}, quarantine.Resource{Tool: req.Tool, Server: req.Server, Provider: req.Provider, Route: req.Route}, req.Scope, req.Level, principal.Subject, req.Reason, req.Confirm)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "emergency containment rejected"})
		return
	}
	if auditErr := s.recordAudit(r.Context(), audit.Event{RequestID: "quarantine-" + state.ID, Timestamp: time.Now().UTC(), Direction: core.DirectionRequest, Component: "quarantine", Mode: s.cfg.SecurityMode, Action: core.ActionReview, Code: "QUARANTINE_EMERGENCY", ReasonID: "operator_reason", Tenant: principal.Tenant, User: principal.Subject}); auditErr != nil && s.cfg.profile() == ProfileProduction {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "durable quarantine audit unavailable"})
		return
	}
	writeJSON(w, http.StatusAccepted, state)
}

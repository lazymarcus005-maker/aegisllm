package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aegisllm/gateway/internal/auth"
	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/limiter"
	"github.com/aegisllm/gateway/internal/policydistribution"
	"github.com/aegisllm/gateway/internal/routing"
	"github.com/aegisllm/gateway/internal/trace"
	"github.com/aegisllm/gateway/web/leaderboard"
)

// Handler returns the routed HTTP handler. LLM POST routes intentionally use
// one handler so every supported wire format crosses the same security gate.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /", s.protectLimited(http.HandlerFunc(s.handleLLMRequest), "aegis.invoke", "aegis.operator"))
	mux.Handle("GET /v1/models", s.protectLimited(http.HandlerFunc(s.handleModels), "aegis.invoke", "aegis.operator"))
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /ready", s.handleReady)
	mux.Handle("GET /api/protection-stats", s.protect(http.HandlerFunc(s.handleProtectionStats), "aegis.operator"))
	mux.Handle("GET /api/effective-policy", s.protect(http.HandlerFunc(s.handleEffectivePolicy), "aegis.operator"))
	mux.Handle("GET /api/policies/status", s.protect(http.HandlerFunc(s.handlePolicyStatus), auth.RoleOperator))
	mux.Handle("POST /api/policies/activate", s.protect(http.HandlerFunc(s.handlePolicyActivate), auth.RoleOperator))
	mux.Handle("POST /api/policies/rollback", s.protect(http.HandlerFunc(s.handlePolicyRollback), auth.RoleOperator))
	mux.Handle("GET /api/routes", s.protect(http.HandlerFunc(s.handleRoutes), "aegis.operator"))
	mux.Handle("GET /api/pii/providers", s.protect(http.HandlerFunc(s.handlePIIProviders), "aegis.operator"))
	mux.Handle("GET /api/audit/status", s.protect(http.HandlerFunc(s.handleAuditStatus), auth.RoleOperator))
	mux.Handle("POST /api/audit/verify", s.protect(http.HandlerFunc(s.handleAuditVerify), auth.RoleOperator))
	if s.mcp != nil {
		mux.Handle("POST /mcp/{server}", s.protectLimited(http.HandlerFunc(s.mcp.handler), auth.RoleToolInvoke, auth.RoleOperator))
		mux.Handle("GET /mcp/{server}", s.protect(http.HandlerFunc(s.mcp.handler), auth.RoleToolInvoke, auth.RoleOperator))
		mux.Handle("DELETE /mcp/{server}", s.protect(http.HandlerFunc(s.mcp.handler), auth.RoleToolInvoke, auth.RoleOperator))
		mux.Handle("GET /api/mcp/servers", s.protect(http.HandlerFunc(s.handleMCPServers), auth.RoleOperator))
		mux.Handle("GET /api/mcp/audit", s.protect(http.HandlerFunc(s.handleMCPAudit), auth.RoleOperator))
		mux.Handle("GET /api/mcp/metrics", s.protect(http.HandlerFunc(s.handleMCPMetrics), auth.RoleOperator))
	}
	mux.Handle("GET /dashboard", s.protect(http.HandlerFunc(s.handleDashboard), "aegis.operator"))
	mux.Handle("GET /dashboard/", s.protect(http.StripPrefix("/dashboard/", http.FileServer(http.FS(leaderboard.Files))), "aegis.operator"))
	if s.metrics != nil {
		mux.Handle("GET /metrics", s.protect(s.metrics, "aegis.operator"))
	}
	return mux
}

func (s *Server) handleAuditStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.AuditStatus())
}

func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if s.auditWAL == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit WAL unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := s.auditWAL.Verify(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit integrity verification failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "verified", "records": s.auditWAL.Status().Records})
}

func (s *Server) handlePolicyStatus(w http.ResponseWriter, _ *http.Request) {
	if s.distribution == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy distribution unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, s.distribution.Status())
}

func (s *Server) handlePolicyActivate(w http.ResponseWriter, r *http.Request) {
	if s.distribution == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy distribution unavailable"})
		return
	}
	var request struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid activation request"})
		return
	}
	if err := s.distribution.PromoteAuthorized(request.Reason, auth.RoleOperator); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "activation rejected"})
		return
	}
	if current := s.distribution.Current(); current != nil {
		s.SetRuntimePolicy(current.Policy)
	}
	writeJSON(w, http.StatusOK, s.distribution.Status())
}

func (s *Server) handlePolicyRollback(w http.ResponseWriter, r *http.Request) {
	if s.distribution == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy distribution unavailable"})
		return
	}
	var request struct {
		Version        int    `json:"version"`
		Action         string `json:"action"`
		TargetSequence uint64 `json:"target_sequence"`
		TargetHash     string `json:"target_hash"`
		Reason         string `json:"reason"`
		Role           string `json:"role"`
		Issuer         string `json:"issuer"`
		KeyID          string `json:"key_id"`
		Issued         string `json:"issued"`
		Signature      string `json:"signature"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid rollback authorization"})
		return
	}
	signature, err := base64.StdEncoding.DecodeString(request.Signature)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid rollback authorization"})
		return
	}
	authz := policydistribution.Authorization{Version: request.Version, Action: request.Action, TargetSequence: request.TargetSequence, TargetHash: request.TargetHash, Reason: request.Reason, Role: request.Role, Issuer: request.Issuer, KeyID: request.KeyID, Issued: request.Issued, Signature: signature}
	if err := s.distribution.Rollback(authz, nil); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "rollback rejected"})
		return
	}
	if current := s.distribution.Current(); current != nil {
		s.SetRuntimePolicy(current.Policy)
	}
	writeJSON(w, http.StatusOK, s.distribution.Status())
}

func (s *Server) handleMCPServers(w http.ResponseWriter, _ *http.Request) {
	if s.mcp == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "MCP unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": 1, "servers": s.mcp.status()})
}

func (s *Server) handleMCPAudit(w http.ResponseWriter, _ *http.Request) {
	if s.mcp == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "MCP unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": 1, "events": s.mcp.auditSnapshot()})
}

func (s *Server) handleMCPMetrics(w http.ResponseWriter, _ *http.Request) {
	if s.mcp == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "MCP unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": 1, "metrics": s.mcp.metricsSnapshot()})
}

func (s *Server) protect(next http.Handler, roles ...string) http.Handler {
	return s.authn.Middleware(next, roles...)
}

func (s *Server) protectLimited(next http.Handler, roles ...string) http.Handler {
	return s.authn.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := s.admissionKey(r)
		release, result := s.limiter.Allow(key)
		if result.Reason != nil {
			retry := int(result.RetryAfter / time.Second)
			if retry < 1 {
				retry = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			switch result.Reason {
			case limiter.ErrRateLimited:
				s.runtimeMetrics.ObserveRateLimited()
			default:
				s.runtimeMetrics.ObserveConcurrencyRejected()
			}
			writeOpenAIError(w, http.StatusTooManyRequests, "rate_limit_error", "REQUEST_LIMITED", "Request limit exceeded.", "")
			return
		}
		s.runtimeMetrics.IncActiveRequests()
		defer s.runtimeMetrics.DecActiveRequests()
		defer release()
		next.ServeHTTP(w, r)
	}), roles...)
}

func (s *Server) admissionKey(r *http.Request) string {
	if principal, ok := auth.PrincipalFromContext(r.Context()); ok {
		return "verified:" + strconv.Itoa(len(principal.Tenant)) + ":" + principal.Tenant + ":" + strconv.Itoa(len(principal.Application)) + ":" + principal.Application
	}
	application := strings.TrimSpace(r.Header.Get(s.cfg.HeaderApplication))
	if application == "" {
		application = "unknown"
	}
	return "development:" + application + ":" + remoteAddress(r.RemoteAddr)
}

func remoteAddress(remote string) string {
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return host
	}
	return remote
}

func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	requestCtx, traceCtx := trace.FromRequest(r)
	r = r.WithContext(requestCtx)
	env := &core.InspectionEnvelope{RequestID: newRequestID(), Direction: core.DirectionRequest, Target: core.Target{Provider: s.cfg.DefaultTargetProvider}, Metadata: map[string]string{"endpoint_family": "openai", "endpoint_path": r.URL.Path, "trace_id": traceCtx.TraceID, "span_id": traceCtx.SpanID, "trace_flags": traceCtx.Flags}}
	s.enrich(env, r)
	if auditor, ok := s.pipeline.(interface {
		AuditPassthrough(*core.InspectionEnvelope)
	}); ok {
		auditor.AuditPassthrough(env)
	}
	var resp *http.Response
	var selection routing.Selection
	var err error
	if s.routed != nil {
		resp, selection, err = s.routed.Forward(r, nil, routeInput(env, r.URL.Path, core.ActionAllow, s.routeConstraint(core.ActionAllow, env.Target.Provider)))
		if err == nil {
			s.recordRoute(env, core.ActionAllow, selection)
		}
	} else {
		resp, err = s.proxy.Forward(r, nil)
	}
	if err != nil {
		if s.routed != nil && strings.HasPrefix(err.Error(), "ROUTE_") {
			s.writeRouteError(w, err, env.RequestID)
			return
		}
		s.writeUpstreamError(w, err, env.RequestID)
		return
	}
	defer resp.Body.Close()
	body, tooLarge, err := readBounded(resp.Body, s.cfg.MaxResponseBytes)
	if err != nil {
		s.proxy.RecordFailure()
		s.writeUpstreamError(w, err, env.RequestID)
		return
	}
	if tooLarge {
		s.runtimeMetrics.ObserveResponseTooLarge()
		writeOpenAIError(w, http.StatusBadGateway, "upstream_error", "UPSTREAM_RESPONSE_TOO_LARGE", "Upstream response exceeds the configured limit.", env.RequestID)
		return
	}
	copyResponseHeaders(w, resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, bytes.NewReader(body))
}

func (s *Server) handleRoutes(w http.ResponseWriter, _ *http.Request) {
	if s.routed == nil {
		writeJSON(w, http.StatusOK, map[string]any{"registry": "legacy-development-compatibility", "routes": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": 1, "routes": s.routed.Status()})
}

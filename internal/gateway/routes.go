package gateway

import (
	"io"
	"net/http"

	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/web/leaderboard"
)

// Handler returns the routed HTTP handler. LLM POST routes intentionally use
// one handler so every supported wire format crosses the same security gate.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /", s.protect(http.HandlerFunc(s.handleLLMRequest), "aegis.invoke", "aegis.operator"))
	mux.Handle("GET /v1/models", s.protect(http.HandlerFunc(s.handleModels), "aegis.invoke", "aegis.operator"))
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /ready", s.handleReady)
	mux.Handle("GET /api/protection-stats", s.protect(http.HandlerFunc(s.handleProtectionStats), "aegis.operator"))
	mux.Handle("GET /dashboard", s.protect(http.HandlerFunc(s.handleDashboard), "aegis.operator"))
	mux.Handle("GET /dashboard/", s.protect(http.StripPrefix("/dashboard/", http.FileServer(http.FS(leaderboard.Files))), "aegis.operator"))
	if s.metrics != nil {
		mux.Handle("GET /metrics", s.protect(s.metrics, "aegis.operator"))
	}
	return mux
}

func (s *Server) protect(next http.Handler, roles ...string) http.Handler {
	return s.authn.Middleware(next, roles...)
}

func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	env := &core.InspectionEnvelope{RequestID: newRequestID(), Direction: core.DirectionRequest, Target: core.Target{Provider: s.cfg.DefaultTargetProvider}, Metadata: map[string]string{"endpoint_family": "openai", "endpoint_path": r.URL.Path}}
	s.enrich(env, r)
	if auditor, ok := s.pipeline.(interface {
		AuditPassthrough(*core.InspectionEnvelope)
	}); ok {
		auditor.AuditPassthrough(env)
	}
	resp, err := s.proxy.Forward(r, nil)
	if err != nil {
		writeOpenAIError(w, http.StatusBadGateway, "upstream_error", "", "Upstream gateway request failed.", env.RequestID)
		return
	}
	defer resp.Body.Close()
	copyResponseHeaders(w, resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

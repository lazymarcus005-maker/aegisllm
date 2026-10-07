package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/dashboard"
	"github.com/aegisllm/gateway/internal/pii"
	"github.com/aegisllm/gateway/web/leaderboard"
)

// RequestDecision is the pipeline outcome for one request.
type RequestDecision struct {
	Action          core.Action
	Code            string // error code for policy rejections (spec §9)
	TransformedBody []byte // non-nil when the pipeline rewrote the body
	Transformations []pii.Transformation
}

// Pipeline runs normalized content through detection and policy on both the
// request and response directions (FR-001, FR-015). Implementations receive
// the deployment mode from the server: the server is the single owner of
// mode (FR-018), pipelines predict and audit.
type Pipeline interface {
	ProcessRequest(env *core.InspectionEnvelope, raw []byte) (RequestDecision, error)
	ProcessResponse(reqEnv *core.InspectionEnvelope, raw []byte) (ResponseOutcome, error)
	SetSecurityMode(mode string)
}

// Server is the OpenAI-compatible security gateway HTTP server (FR-001).
type Server struct {
	cfg        Config
	proxy      *Proxy
	pipeline   Pipeline
	logger     *slog.Logger
	readyFns   map[string]func() string
	readyOrder []string
	metrics    http.Handler
	dashboard  *dashboard.Dashboard
}

// NewServer validates configuration and builds the server.
func NewServer(cfg Config, logger *slog.Logger) (*Server, error) {
	proxy, err := NewProxy(cfg)
	if err != nil {
		return nil, err
	}
	switch cfg.SecurityMode {
	case ModeOff, ModeShadow, ModeEnforce:
	default:
		return nil, errors.New("SECURITY_MODE must be one of: off, shadow, enforce")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{cfg: cfg, proxy: proxy, logger: logger, readyFns: map[string]func() string{}}, nil
}

// SetPipeline attaches the security pipeline and propagates the security
// mode: the pipeline predicts and audits, and can never disagree with the
// deployment it serves because the fact is stated once, here.
func (s *Server) SetPipeline(p Pipeline) {
	s.pipeline = p
	p.SetSecurityMode(s.cfg.SecurityMode)
}

// SetMetricsHandler mounts a handler at GET /metrics (spec §15). The
// production observability handler also provides the metrics source used by
// the protection dashboard, keeping dashboard wiring in the server boundary.
func (s *Server) SetMetricsHandler(h http.Handler) {
	s.metrics = h
	if provider, ok := h.(dashboard.MetricsProvider); ok {
		s.dashboard = dashboard.New(provider.ProtectionMetrics())
	}
}

// SetProtectionDashboard mounts the content-free protection statistics source
// used by /api/protection-stats.
func (s *Server) SetProtectionDashboard(d *dashboard.Dashboard) { s.dashboard = d }

// AddReadinessCheck registers a named readiness probe; a non-empty return
// string is the failure reason surfaced by /ready (FR-020).
func (s *Server) AddReadinessCheck(name string, fn func() string) {
	if _, ok := s.readyFns[name]; !ok {
		s.readyOrder = append(s.readyOrder, name)
	}
	s.readyFns[name] = fn
}

// Handler returns the routed HTTP handler.
func (s *Server) handleProtectionStats(w http.ResponseWriter, _ *http.Request) {
	if s.dashboard == nil {
		writeJSON(w, http.StatusOK, dashboard.Snapshot(nil))
		return
	}
	writeJSON(w, http.StatusOK, s.dashboard.Snapshot())
}

func (s *Server) handleDashboard(w http.ResponseWriter, _ *http.Request) {
	data, err := leaderboard.Files.ReadFile("index.html")
	if err != nil {
		http.Error(w, "dashboard unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	if reason := s.readyCheck(); reason != "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready", "reason": reason})
		return
	}
	for _, name := range s.readyOrder {
		if reason := s.readyFns[name](); reason != "" {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready", "reason": name + ": " + reason})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) readyCheck() string {
	if s.cfg.UpstreamBaseURL == "" {
		return "UPSTREAM_BASE_URL not configured"
	}
	u, err := url.Parse(s.cfg.UpstreamBaseURL)
	if err != nil {
		return "invalid UPSTREAM_BASE_URL"
	}
	host := u.Host
	if u.Port() == "" {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	conn, err := net.DialTimeout("tcp", host, time.Second)
	if err != nil {
		return "upstream unreachable: " + u.Host
	}
	_ = conn.Close()
	return ""
}

func (s *Server) handleLLMRequest(w http.ResponseWriter, r *http.Request) {
	normalizer := NormalizerFor(r.URL.Path)
	if normalizer == nil {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeOpenAIError(w, http.StatusRequestEntityTooLarge, "invalid_request_error", "REQUEST_TOO_LARGE", "Request body exceeds the configured limit.", "")
			return
		}
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "", "Failed to read request body.", "")
		return
	}

	env, err := normalizer.ParseRequest(body)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "", err.Error(), "")
		return
	}
	s.enrich(env, r)
	env.Metadata["endpoint_path"] = r.URL.Path
	isStream := env.Metadata["stream"] == "true" || strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream")
	if isStream {
		env.Metadata["skipped_stream"] = "true"
	}

	forwardBody := body
	if s.pipeline != nil {
		dec, perr := s.pipeline.ProcessRequest(env, body)
		if perr != nil {
			s.logger.Error("security pipeline failed", "request_id", env.RequestID, "error", perr)
			writeOpenAIError(w, http.StatusInternalServerError, "gateway_error", "", "Security pipeline failure.", env.RequestID)
			return
		}
		if !isStream {
			forwardBody = s.applyDecision(w, env, normalizer, dec, forwardBody)
		}
		if forwardBody == nil {
			return // response already written
		}
	}

	resp, ferr := s.proxy.Forward(r, forwardBody)
	if ferr != nil {
		s.logger.Error("upstream request failed", "request_id", env.RequestID, "error", ferr)
		writeOpenAIError(w, http.StatusBadGateway, "upstream_error", "", "Upstream gateway request failed.", env.RequestID)
		return
	}
	defer resp.Body.Close()

	// Outbound protection (ticket 07): non-streaming JSON responses are
	// scanned and policy-filtered before reaching the client. Streaming
	// follows the deferred plan in architecture §13.
	_, embeddingsResponse := normalizer.(openAIEmbeddingsNormalizer)
	if s.pipeline == nil || s.cfg.SecurityMode == ModeOff || isStream ||
		embeddingsResponse || resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		copyResponseHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}

	bodyBytes, rerr := io.ReadAll(io.LimitReader(resp.Body, s.cfg.MaxBodyBytes))
	if rerr != nil {
		s.logger.Error("upstream response read failed", "request_id", env.RequestID, "error", rerr)
		writeOpenAIError(w, http.StatusBadGateway, "upstream_error", "", "Upstream response read failed.", env.RequestID)
		return
	}

	out, perr := s.processOutbound(w, env, normalizer, bodyBytes)
	if perr != nil {
		return // response already written
	}
	copyResponseHeaders(w, resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, bytes.NewReader(out))
}

// processOutbound applies the response outcome for the current mode; a
// non-nil error means the response has already been written.
func (s *Server) processOutbound(w http.ResponseWriter, env *core.InspectionEnvelope, normalizer Normalizer, body []byte) ([]byte, error) {
	outcome, err := s.pipeline.ProcessResponse(env, body)
	if err != nil {
		s.logger.Error("outbound pipeline failed", "request_id", env.RequestID, "error", err)
		writeOpenAIError(w, http.StatusInternalServerError, "gateway_error", "", "Security pipeline failure.", env.RequestID)
		return nil, err
	}
	if s.cfg.SecurityMode != ModeEnforce {
		// Shadow: predicted outbound actions are audited; client behavior
		// follows the incumbent path.
		return body, nil
	}
	switch outcome.Action {
	case core.ActionBlock, core.ActionReview:
		code := outcome.Code
		if code == "" {
			code = "SECURITY_POLICY_BLOCKED"
		}
		writeOpenAIError(w, http.StatusForbidden, "security_policy_violation", code, "Response blocked by security policy.", env.RequestID)
		return nil, errors.New("response blocked")
	default:
		if outcome.TransformedBody != nil {
			return outcome.TransformedBody, nil
		}
		if len(outcome.Transformations) > 0 {
			transformed, err := normalizer.RewriteResponse(body, outcome.Transformations)
			if err != nil {
				s.logger.Error("response transformation failed", "request_id", env.RequestID, "error", err)
				writeOpenAIError(w, http.StatusInternalServerError, "gateway_error", "", "Security transformation failure.", env.RequestID)
				return nil, err
			}
			return transformed, nil
		}
		return body, nil
	}
}

// applyDecision translates a pipeline decision into forwarding behavior for
// the current mode. A nil return means the response has already been written.
func (s *Server) applyDecision(w http.ResponseWriter, env *core.InspectionEnvelope, normalizer Normalizer, dec RequestDecision, raw []byte) []byte {
	if s.cfg.SecurityMode != ModeEnforce {
		// off: no security behavior; shadow: predicted actions are audited by
		// the pipeline but traffic follows the incumbent path (FR-018).
		return raw
	}
	switch dec.Action {
	case core.ActionAllow, core.ActionRestrictTools, core.ActionForceLocalModel:
		// RESTRICT_TOOLS carries a tools-stripped TransformedBody (T-025).
		// FORCE_LOCAL_MODEL enforcement (local upstream routing) is a
		// documented V1.1 deferral (see docs/mvp-dod-checklist.md); the
		// predicted action is audited meanwhile.
		if dec.TransformedBody != nil {
			return dec.TransformedBody
		}
		if len(dec.Transformations) > 0 {
			body, err := normalizer.RewriteRequest(raw, dec.Transformations)
			if err != nil {
				s.logger.Error("request transformation failed", "request_id", env.RequestID, "error", err)
				writeOpenAIError(w, http.StatusInternalServerError, "gateway_error", "", "Security transformation failure.", env.RequestID)
				return nil
			}
			return body
		}
		return raw
	case core.ActionBlock, core.ActionReview:
		// REVIEW maps to a safe fallback: reject (FR-011).
		code := dec.Code
		if code == "" {
			code = "SECURITY_POLICY_BLOCKED"
		}
		writeOpenAIError(w, http.StatusForbidden, "security_policy_violation", code, "Request blocked by security policy.", env.RequestID)
		return nil
	case core.ActionRedact, core.ActionTokenize:
		if dec.TransformedBody != nil {
			return dec.TransformedBody
		}
		if len(dec.Transformations) == 0 {
			s.logger.Error("transform decision without transformed body", "request_id", env.RequestID, "action", string(dec.Action))
			writeOpenAIError(w, http.StatusInternalServerError, "gateway_error", "", "Security transformation failure.", env.RequestID)
			return nil
		}
		body, err := normalizer.RewriteRequest(raw, dec.Transformations)
		if err != nil {
			s.logger.Error("request transformation failed", "request_id", env.RequestID, "error", err)
			writeOpenAIError(w, http.StatusInternalServerError, "gateway_error", "", "Security transformation failure.", env.RequestID)
			return nil
		}
		return body
	default:
		s.logger.Error("unknown policy action", "request_id", env.RequestID, "action", string(dec.Action))
		writeOpenAIError(w, http.StatusInternalServerError, "gateway_error", "", "Unknown policy action.", env.RequestID)
		return nil
	}
}

func (s *Server) enrich(env *core.InspectionEnvelope, r *http.Request) {
	env.Application = headerOr(r, s.cfg.HeaderApplication, "unknown")
	env.Tenant = r.Header.Get(s.cfg.HeaderTenant)
	env.User.Subject = r.Header.Get(s.cfg.HeaderUser)
	provider := r.Header.Get(s.cfg.HeaderTargetProvider)
	if provider == "" {
		provider = s.cfg.DefaultTargetProvider
	}
	env.Target.Provider = provider
}

func headerOr(r *http.Request, name, def string) string {
	if v := r.Header.Get(name); v != "" {
		return v
	}
	return def
}

// hopByHop headers must not be forwarded (RFC 7230 §6.1). Content-Length is
// excluded too: outbound transformations may change the body size, so the
// server must recompute it.
var hopByHop = map[string]bool{
	"Connection": true, "Proxy-Connection": true, "Keep-Alive": true,
	"TE": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
	"Proxy-Authenticate": true, "Proxy-Authorization": true,
	"Content-Length": true,
}

func copyResponseHeaders(w http.ResponseWriter, h http.Header) {
	for k, vv := range h {
		if hopByHop[k] {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeOpenAIError renders the spec §9 error contract. The code field is
// omitted when empty; request_id is omitted when unknown.
func writeOpenAIError(w http.ResponseWriter, status int, errType, code, message, requestID string) {
	e := map[string]any{"type": errType, "message": message}
	if code != "" {
		e["code"] = code
	}
	if requestID != "" {
		e["request_id"] = requestID
	}
	writeJSON(w, status, map[string]any{"error": e})
}

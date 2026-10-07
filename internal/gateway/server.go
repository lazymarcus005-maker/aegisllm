package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aegisllm/gateway/internal/auth"
	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/dashboard"
	"github.com/aegisllm/gateway/internal/limiter"
	"github.com/aegisllm/gateway/internal/observability"
	"github.com/aegisllm/gateway/internal/pii"
	"github.com/aegisllm/gateway/internal/policy"
	"github.com/aegisllm/gateway/internal/routing"
	"github.com/aegisllm/gateway/internal/securetransport"
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

type contextualPipeline interface {
	ProcessRequestContext(context.Context, *core.InspectionEnvelope, []byte) (RequestDecision, error)
}

// Server is the OpenAI-compatible security gateway HTTP server (FR-001).
type Server struct {
	cfg            Config
	proxy          *Proxy
	routed         *RoutedProxy
	pipeline       Pipeline
	logger         *slog.Logger
	readyFns       map[string]func() string
	readyOrder     []string
	metrics        http.Handler
	runtimeMetrics observability.RuntimeRecorder
	limiter        *limiter.Limiter
	dashboard      *dashboard.Dashboard
	authn          *auth.Authenticator
	policy         *policy.Policy
	semanticStatus func() SemanticReadiness
	materials      map[string]func() securetransport.Status
}

// SemanticReadiness is the sanitized semantic contract exposed by /ready.
// It intentionally contains no URL, credentials, raw artifact data, or
// request content.
type SemanticReadiness struct {
	Status                 string `json:"status"`
	Provider               string `json:"provider,omitempty"`
	SchemaVersion          string `json:"schema_version,omitempty"`
	ThresholdPolicyID      string `json:"threshold_policy_id,omitempty"`
	ThresholdPolicyVersion int    `json:"threshold_policy_version,omitempty"`
	CheckpointID           string `json:"checkpoint_id,omitempty"`
	CalibrationTimestamp   string `json:"calibration_timestamp,omitempty"`
}

// NewServer validates configuration and builds the server.
func NewServer(cfg Config, logger *slog.Logger) (*Server, error) {
	cfg = cfg.withRuntimeDefaults()
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	if cfg.profile() == ProfileProduction && strings.TrimSpace(cfg.UpstreamRegistryFile) == "" {
		return nil, errors.New("production requires UPSTREAM_REGISTRY_FILE")
	}
	var proxy *Proxy
	var routed *RoutedProxy
	var err error
	if cfg.UpstreamRegistryFile != "" {
		manager, loadErr := routing.NewManagerFile(cfg.UpstreamRegistryFile)
		if loadErr != nil {
			return nil, loadErr
		}
		routed, err = NewRoutedProxy(cfg, manager)
	} else {
		proxy, err = NewProxy(cfg)
	}
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.DeploymentProfile == "" {
		cfg.DeploymentProfile = ProfileDevelopment
	}
	if cfg.JWTTenantClaim == "" {
		cfg.JWTTenantClaim = "tenant_id"
	}
	if cfg.JWTApplicationClaim == "" {
		cfg.JWTApplicationClaim = "azp"
	}
	if cfg.JWTSubjectClaim == "" {
		cfg.JWTSubjectClaim = "sub"
	}
	if cfg.JWTRolesClaim == "" {
		cfg.JWTRolesClaim = "roles"
	}
	if cfg.JWTProviderClaim == "" {
		cfg.JWTProviderClaim = "provider"
	}
	authn, err := auth.New(auth.Config{
		Mode: cfg.AuthMode, DeploymentProfile: string(cfg.profile()),
		AllowUnauthenticated: cfg.AllowUnauthenticatedShadow,
		PublicKeyFile:        cfg.JWTPublicKeyFile, HMACSecret: cfg.JWTHMACSecret,
		Issuer: cfg.JWTIssuer, Audience: cfg.JWTAudience,
		TenantClaim: cfg.JWTTenantClaim, ApplicationClaim: cfg.JWTApplicationClaim,
		SubjectClaim: cfg.JWTSubjectClaim, RolesClaim: cfg.JWTRolesClaim,
		ProviderClaim: cfg.JWTProviderClaim, ClientCertIdentity: cfg.AuthMode == auth.ModeMTLS,
	})
	if err != nil {
		return nil, err
	}
	srv := &Server{cfg: cfg, proxy: proxy, routed: routed, logger: logger, readyFns: map[string]func() string{}, authn: authn,
		materials:      map[string]func() securetransport.Status{},
		runtimeMetrics: observability.Noop{}, limiter: limiter.New(limiter.Config{
			RequestsPerSecond: cfg.RequestsPerSecond, Burst: cfg.RateBurst,
			MaxConcurrent: cfg.MaxConcurrentRequests, MaxKeys: cfg.LimiterMaxKeys,
			KeyIdleTimeout: cfg.LimiterKeyIdleTimeout,
		})}
	srv.semanticStatus = func() SemanticReadiness {
		status := "disabled"
		if cfg.SemanticEnforce {
			status = "unready"
		} else if cfg.SecurityMode == ModeShadow {
			status = "shadow"
		}
		return SemanticReadiness{Status: status}
	}
	if proxy != nil {
		for name, fn := range proxy.MaterialStatuses() {
			srv.AddMaterialReadiness(name, fn)
		}
	}
	if routed != nil {
		for name, fn := range routed.MaterialStatuses() {
			srv.AddMaterialReadiness(name, fn)
		}
	}
	if cfg.JWTPublicKeyFile != "" {
		srv.AddMaterialReadiness("jwt_verification_key", authn.KeyStatus)
	}
	return srv, nil
}

// SetPipeline attaches the security pipeline and propagates the security
// mode: the pipeline predicts and audits, and can never disagree with the
// deployment it serves because the fact is stated once, here.
func (s *Server) SetPipeline(p Pipeline) {
	s.pipeline = p
	p.SetSecurityMode(s.cfg.SecurityMode)
}

// SetPolicy attaches the already validated policy for the operator-only
// effective-policy endpoint. The endpoint exposes only Policy.Summary().
func (s *Server) SetPolicy(p *policy.Policy) { s.policy = p }

func (s *Server) routeConstraint(action core.Action, provider string) routing.Constraint {
	var out routing.Constraint
	if s.policy != nil && s.policy.Routing != nil {
		if action == core.ActionForceLocalModel {
			c := s.policy.Routing.ForceLocal
			out = routing.Constraint{Routes: c.Routes, Classes: c.Classes, Providers: c.Providers, FallbackChain: c.FallbackChain}
		} else {
			for name, c := range s.policy.Routing.Actions {
				if strings.EqualFold(name, string(action)) {
					out = routing.Constraint{Routes: c.Routes, Classes: c.Classes, Providers: c.Providers, FallbackChain: c.FallbackChain}
					break
				}
			}
			if len(out.Routes) == 0 && len(out.Classes) == 0 && len(out.Providers) == 0 && out.FallbackChain == "" {
				if c, ok := s.policy.Routing.ProviderBoundaries[provider]; ok {
					out = routing.Constraint{Routes: c.Routes, Classes: c.Classes, Providers: c.Providers, FallbackChain: c.FallbackChain}
				}
			}
		}
		if action != core.ActionForceLocalModel {
			if boundary, ok := s.policy.Routing.ProviderBoundaries[provider]; ok {
				if len(boundary.Classes) > 0 {
					out.Classes = boundary.Classes
				}
				if len(boundary.Providers) > 0 {
					out.Providers = boundary.Providers
				}
				if len(boundary.Routes) > 0 {
					out.Routes = boundary.Routes
				}
				if boundary.FallbackChain != "" {
					out.FallbackChain = boundary.FallbackChain
				}
			}
		}
	}
	if action == core.ActionForceLocalModel && len(out.Classes) == 0 && len(out.Routes) == 0 && out.FallbackChain == "" {
		out.Classes = []string{string(routing.ClassLocal)}
	}
	return out
}

func (s *Server) recordRoute(env *core.InspectionEnvelope, action core.Action, selection routing.Selection) {
	if selection.Route.ID == "" {
		return
	}
	if auditor, ok := s.pipeline.(interface {
		AuditRoute(*core.InspectionEnvelope, core.Action, string, string, string, string, string, bool)
	}); ok {
		auditor.AuditRoute(env, action, selection.Route.ID, string(selection.Route.Class), selection.Route.Provider, selection.RequestedModel, selection.RoutedModel, selection.Failover)
	}
	if recorder, ok := s.runtimeMetrics.(interface {
		ObserveRouteSelected(string, string, string, bool)
	}); ok {
		recorder.ObserveRouteSelected(selection.Route.ID, string(selection.Route.Class), env.Metadata["endpoint_family"], selection.Failover)
	}
}

func (s *Server) SetSemanticReadiness(fn func() SemanticReadiness) { s.semanticStatus = fn }

// SetMetricsHandler mounts a handler at GET /metrics (spec §15). The
// production observability handler also provides the metrics source used by
// the protection dashboard, keeping dashboard wiring in the server boundary.
func (s *Server) SetMetricsHandler(h http.Handler) {
	s.metrics = h
	if s.routed != nil {
		if provider, ok := h.(interface {
			RuntimeMetrics() observability.RuntimeRecorder
		}); ok {
			if routeMetrics, ok := provider.RuntimeMetrics().(interface {
				ObserveRouteHealth(string, string, string, bool)
			}); ok {
				s.routed.SetRouteMetrics(routeMetrics)
			}
		}
	}
	if provider, ok := h.(interface {
		RuntimeMetrics() observability.RuntimeRecorder
	}); ok {
		s.runtimeMetrics = provider.RuntimeMetrics()
	}
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

// AddMaterialReadiness registers sanitized status for reloadable TLS,
// certificate, secret, or keyring material. Names are operator-chosen bounded
// labels and status never contains the underlying path or value.
func (s *Server) AddMaterialReadiness(name string, fn func() securetransport.Status) {
	if name == "" || fn == nil {
		return
	}
	s.materials[name] = fn
}

func (s *Server) SetSecureMaterialMetrics(metrics securetransport.Metrics) {
	if s == nil {
		return
	}
	if s.proxy != nil {
		s.proxy.SetSecureMaterialMetrics(metrics)
	}
	if s.routed != nil {
		s.routed.SetSecureMaterialMetrics(metrics)
	}
	if s.authn != nil {
		s.authn.SetSecureMaterialMetrics(metrics)
	}
}

// Handler returns the routed HTTP handler.
func (s *Server) handleProtectionStats(w http.ResponseWriter, _ *http.Request) {
	if s.dashboard == nil {
		writeJSON(w, http.StatusOK, dashboard.Snapshot(nil))
		return
	}
	writeJSON(w, http.StatusOK, s.dashboard.Snapshot())
}

func (s *Server) handleEffectivePolicy(w http.ResponseWriter, _ *http.Request) {
	if s.policy == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "policy unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"policy_id": s.policy.ID, "policy_version": s.policy.Version,
		"owner": s.policy.Owner, "effective_date": s.policy.EffectiveDate,
		"rules": s.policy.Summary(),
	})
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
	dependencies := map[string]string{"upstream": "ready"}
	var firstReason string
	if reason := s.readyCheck(); reason != "" {
		dependencies["upstream"] = "not_ready"
		firstReason = reason
	}
	for _, name := range s.readyOrder {
		if reason := s.readyFns[name](); reason != "" {
			dependencies[name] = "not_ready"
			if firstReason == "" {
				firstReason = name + ": " + reason
			}
		} else {
			dependencies[name] = "ready"
		}
	}
	materialResponse := map[string]any{}
	for name, fn := range s.materials {
		status := fn()
		entry := map[string]any{"loaded": status.Loaded, "generation": status.Generation, "last_reload_success": status.LastSuccess}
		if !status.LastFailure.IsZero() {
			entry["last_reload_failure"] = status.LastFailure
			entry["reload_failures"] = status.FailureCount
		}
		if !status.CertificateExpiry.IsZero() {
			entry["certificate_expiry"] = status.CertificateExpiry
		}
		materialResponse[safeSemanticMetadata(name)] = entry
		if !status.Loaded || (s.cfg.profile() == ProfileProduction && status.FailureCount > 0 && status.LastFailure.After(status.LastSuccess)) {
			if firstReason == "" {
				firstReason = "secure material is not ready"
			}
		}
	}
	response := map[string]any{
		"status":             "ready",
		"deployment_profile": string(s.cfg.profile()),
		"security_mode":      s.cfg.SecurityMode,
		"dependencies":       dependencies,
		"secure_material":    materialResponse,
	}
	semantic := SemanticReadiness{Status: "disabled"}
	if s.semanticStatus != nil {
		semantic = s.semanticStatus()
	}
	semantic = sanitizeSemanticReadiness(semantic)
	response["semantic"] = semantic
	if semantic.Status == "unready" && firstReason == "" {
		firstReason = "semantic: semantic contract is not ready"
	}
	if firstReason != "" {
		response["status"] = "not_ready"
		response["reason"] = firstReason
		writeJSON(w, http.StatusServiceUnavailable, response)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func sanitizeSemanticReadiness(in SemanticReadiness) SemanticReadiness {
	switch in.Status {
	case "disabled", "shadow", "ready", "unready":
	default:
		in.Status = "unready"
	}
	in.Provider = safeSemanticMetadata(in.Provider)
	in.SchemaVersion = safeSemanticMetadata(in.SchemaVersion)
	in.ThresholdPolicyID = safeSemanticMetadata(in.ThresholdPolicyID)
	in.CheckpointID = safeSemanticMetadata(in.CheckpointID)
	in.CalibrationTimestamp = safeSemanticMetadata(in.CalibrationTimestamp)
	return in
}

func safeSemanticMetadata(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 64 {
		value = value[:64]
	}
	for i, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-", r) {
			continue
		}
		value = value[:i] + "_" + value[i+len(string(r)):]
	}
	return value
}

func (s *Server) readyCheck() string {
	if s.routed != nil {
		return s.routed.Readiness()
	}
	if s.proxy != nil {
		if reason := s.proxy.Readiness(); reason != "" {
			return reason
		}
	}
	if s.cfg.UpstreamBaseURL == "" {
		return "UPSTREAM_BASE_URL not configured"
	}
	u, err := url.Parse(s.cfg.UpstreamBaseURL)
	if err != nil {
		return "invalid UPSTREAM_BASE_URL"
	}
	if u.Scheme == "" || u.Host == "" {
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
		return "upstream unreachable"
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
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "", "Invalid request body.", "")
		return
	}
	s.enrich(env, r)
	env.Metadata["endpoint_path"] = r.URL.Path
	if promptChars(env) > s.cfg.MaxPromptChars {
		s.runtimeMetrics.ObservePromptBudgetRejected()
		writeOpenAIError(w, http.StatusRequestEntityTooLarge, "invalid_request_error", "PROMPT_TOO_LARGE", "Prompt exceeds the configured character limit.", env.RequestID)
		return
	}
	isStream := env.Metadata["stream"] == "true" || strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream")
	if isStream {
		env.Metadata["stream"] = "true"
	}
	requestCtx := r.Context()
	var streamCancel context.CancelFunc
	if isStream {
		requestCtx, streamCancel = context.WithTimeout(requestCtx, s.cfg.MaxStreamDuration)
		defer streamCancel()
		r = r.WithContext(requestCtx)
	}
	forwardBody := body
	routeAction := core.ActionAllow
	if s.pipeline != nil {
		var dec RequestDecision
		var perr error
		if contextual, ok := s.pipeline.(contextualPipeline); ok {
			dec, perr = contextual.ProcessRequestContext(requestCtx, env, body)
		} else {
			dec, perr = s.pipeline.ProcessRequest(env, body)
		}
		if perr != nil {
			s.logger.Error("security pipeline failed", "request_id", env.RequestID, "error", perr)
			writeOpenAIError(w, http.StatusInternalServerError, "gateway_error", "", "Security pipeline failure.", env.RequestID)
			return
		}
		if s.cfg.SecurityMode == ModeEnforce {
			routeAction = dec.Action
		}
		forwardBody = s.applyDecision(w, env, normalizer, dec, forwardBody)
		if forwardBody == nil {
			return // response already written
		}
	}

	var resp *http.Response
	var ferr error
	var selection routing.Selection
	if s.routed != nil {
		constraint := s.routeConstraint(routeAction, env.Target.Provider)
		resp, selection, ferr = s.routed.Forward(r, forwardBody, routeInput(env, r.URL.Path, routeAction, constraint))
		if ferr == nil {
			s.recordRoute(env, routeAction, selection)
		}
	} else {
		resp, ferr = s.proxy.Forward(r, forwardBody)
	}
	if ferr != nil {
		if s.routed != nil && strings.HasPrefix(ferr.Error(), "ROUTE_") {
			if recorder, ok := s.runtimeMetrics.(interface{ ObserveRouteRejected(string, string) }); ok {
				recorder.ObserveRouteRejected(ferr.Error(), env.Metadata["endpoint_family"])
			}
			if recorder, ok := s.runtimeMetrics.(interface{ ObserveRouteUnavailable(string, string) }); ok {
				class := "cloud"
				if routeAction == core.ActionForceLocalModel {
					class = "local"
				}
				recorder.ObserveRouteUnavailable(class, env.Metadata["endpoint_family"])
			}
			s.writeRouteError(w, ferr, env.RequestID)
			return
		}
		s.writeUpstreamError(w, ferr, env.RequestID)
		return
	}
	defer resp.Body.Close()

	// Outbound protection scans buffered JSON here and stateful SSE through the
	// bounded streaming adapter below.
	_, embeddingsResponse := normalizer.(openAIEmbeddingsNormalizer)
	if isStream {
		s.copyStreamResponse(w, resp, env, normalizer)
		return
	}

	bodyBytes, tooLarge, rerr := readBounded(resp.Body, s.cfg.MaxResponseBytes)
	if rerr != nil {
		s.proxy.RecordFailure()
		s.writeUpstreamError(w, rerr, env.RequestID)
		return
	}
	if tooLarge {
		s.runtimeMetrics.ObserveResponseTooLarge()
		writeOpenAIError(w, http.StatusBadGateway, "upstream_error", "UPSTREAM_RESPONSE_TOO_LARGE", "Upstream response exceeds the configured limit.", env.RequestID)
		return
	}
	if s.pipeline == nil || s.cfg.SecurityMode == ModeOff ||
		embeddingsResponse || resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		copyResponseHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, bytes.NewReader(bodyBytes))
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

func promptChars(env *core.InspectionEnvelope) int {
	n := 0
	for _, part := range env.TextParts() {
		n += len([]rune(part.Text))
	}
	return n
}

func readBounded(body io.Reader, max int64) ([]byte, bool, error) {
	if max <= 0 {
		max = 1
	}
	data, err := io.ReadAll(io.LimitReader(body, max+1))
	return data, int64(len(data)) > max, err
}

func (s *Server) writeUpstreamError(w http.ResponseWriter, err error, requestID string) {
	status := http.StatusBadGateway
	code := "UPSTREAM_REQUEST_FAILED"
	message := "Upstream gateway request failed."
	switch {
	case errors.Is(err, ErrUpstreamBreakerOpen):
		status, code, message = http.StatusServiceUnavailable, "UPSTREAM_BREAKER_OPEN", "Upstream dependency is temporarily unavailable."
		s.runtimeMetrics.ObserveBreakerOpen()
	case upstreamTimeout(err):
		status, code, message = http.StatusGatewayTimeout, "UPSTREAM_TIMEOUT", "Upstream gateway request timed out."
		s.runtimeMetrics.ObserveUpstreamTimeout()
	}
	writeOpenAIError(w, status, "upstream_error", code, message, requestID)
}

func (s *Server) writeRouteError(w http.ResponseWriter, err error, requestID string) {
	code := err.Error()
	status := http.StatusServiceUnavailable
	message := "No configured upstream route is available."
	switch code {
	case "ROUTE_MODEL_REJECTED":
		status, message = http.StatusBadRequest, "Requested model is not allowed for the configured route."
	case "ROUTE_CAPABILITY_REJECTED":
		status, message = http.StatusBadRequest, "Requested endpoint capability is not available on the configured route."
	case "ROUTE_PROVIDER_REJECTED":
		status, message = http.StatusForbidden, "Verified provider boundary rejected the route."
	case "ROUTE_LOCAL_UNAVAILABLE":
		status, message = http.StatusServiceUnavailable, "A healthy local model route is unavailable."
	}
	writeOpenAIError(w, status, "routing_error", code, message, requestID)
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
	if principal, ok := auth.PrincipalFromContext(r.Context()); ok {
		for _, header := range []string{s.cfg.HeaderApplication, s.cfg.HeaderTenant, s.cfg.HeaderUser, s.cfg.HeaderTargetProvider,
			"X-Tenant-Id", "X-Application-Id", "X-User-Id", "X-Target-Provider", "Authorization"} {
			if header != "" {
				r.Header.Del(header)
			}
		}
		env.Application = principal.Application
		env.Tenant = principal.Tenant
		env.User.Subject = principal.Subject
		env.User.Roles = append([]string(nil), principal.Roles...)
		env.Target.Provider = principal.Provider
		if env.Target.Provider == "" {
			env.Target.Provider = s.cfg.DefaultTargetProvider
		}
		if principal.Provider != "" {
			env.Metadata["verified_provider"] = "true"
		}
		return
	}
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

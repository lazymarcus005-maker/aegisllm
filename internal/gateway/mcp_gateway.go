package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/aegisllm/gateway/internal/audit"
	"github.com/aegisllm/gateway/internal/auth"
	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/credentialbroker"
	"github.com/aegisllm/gateway/internal/quarantine"
	"github.com/aegisllm/gateway/internal/securetransport"
	"github.com/aegisllm/gateway/internal/streaming"
	"github.com/aegisllm/gateway/internal/trace"
)

const (
	mcpMaxTools         = 2048
	mcpMaxAudit         = 1000
	mcpCredentialHeader = "X-Aegis-" + "Credential" + "-Source"
)

type mcpGateway struct {
	server    *Server
	registry  *mcpRegistryManager
	broker    *credentialbroker.Broker
	clients   sync.Map // server id -> *mcpTransport
	mu        sync.Mutex
	sessions  map[string]mcpSession
	audit     []MCPAuditEvent
	toolCache map[string]mcpToolCache
}

type mcpTransport struct {
	client       *http.Client
	sem          chan struct{}
	certs        []*securetransport.File[tls.Certificate]
	threshold    int
	openInterval time.Duration
	mu           sync.Mutex
	fails        int
	openAt       time.Time
}

type mcpSession struct {
	Tenant, Application, Subject, Server string
	Expires                              time.Time
}

type mcpToolCache struct {
	At      time.Time
	Version string
	Tools   []MCPTool
}

type MCPTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

type MCPAuditEvent struct {
	Timestamp    time.Time `json:"timestamp"`
	Server       string    `json:"server"`
	Tool         string    `json:"tool,omitempty"`
	Action       string    `json:"action"`
	Policy       string    `json:"policy,omitempty"`
	Rule         string    `json:"rule,omitempty"`
	Direction    string    `json:"direction"`
	LatencyMS    int64     `json:"latency_ms"`
	ResultStatus string    `json:"result_status"`
	Credential   string    `json:"credential_source_type,omitempty"`
}

type mcpJSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpJSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpRPCError    `json:"error,omitempty"`
}

type mcpRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func newMCPGateway(s *Server, registryPath, credentialPath string) (*mcpGateway, error) {
	reg, err := newMCPRegistry(registryPath, s.cfg.TLSReloadInterval, s.cfg.profile() != ProfileProduction)
	if err != nil {
		return nil, err
	}
	var broker *credentialbroker.Broker
	if credentialPath != "" {
		broker, err = credentialbroker.New(credentialPath, credentialbroker.Config{PollInterval: s.cfg.TLSReloadInterval, TLSMin: s.cfg.TLSMinVersion, TLSMax: s.cfg.TLSMaxVersion})
		if err != nil {
			reg.close()
			return nil, err
		}
	}
	g := &mcpGateway{server: s, registry: reg, broker: broker, sessions: map[string]mcpSession{}, toolCache: map[string]mcpToolCache{}}
	for _, cfg := range mustMCPServers(reg) {
		if cfg.credentialRef() != "" && broker == nil {
			reg.close()
			return nil, errors.New("MCP credential reference requires MCP_CREDENTIALS_FILE")
		}
	}
	return g, nil
}

func mustMCPServers(reg *mcpRegistryManager) []MCPServerConfig {
	snapshot, err := reg.snapshot()
	if err != nil {
		return nil
	}
	return snapshot.Servers
}

func (g *mcpGateway) close() {
	if g == nil {
		return
	}
	g.registry.close()
	if g.broker != nil {
		g.broker.Close()
	}
	g.clients.Range(func(_, value any) bool {
		if transport, ok := value.(*mcpTransport); ok && transport.client != nil {
			if t, ok := transport.client.Transport.(*http.Transport); ok {
				t.CloseIdleConnections()
			}
			for _, file := range transport.certs {
				file.Close()
			}
		}
		return true
	})
}

func (g *mcpGateway) setMetrics(metrics securetransport.Metrics) {
	if g != nil && g.registry != nil {
		g.registry.setMetrics(metrics)
	}
}

func (g *mcpGateway) handler(w http.ResponseWriter, r *http.Request) {
	requestCtx, traceCtx := trace.FromRequest(r)
	r = r.WithContext(requestCtx)
	_ = traceCtx // correlation is carried by the request context and outbound allowlisted header
	if _, ok := auth.PrincipalFromContext(r.Context()); !ok {
		writeMCPError(w, nil, http.StatusUnauthorized, -32001, "verified MCP principal required")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 2 || parts[0] != "mcp" || parts[1] == "" || !safeMCPValue(parts[1]) {
		writeMCPError(w, nil, http.StatusNotFound, -32602, "MCP server not found")
		return
	}
	serverID := parts[1]
	cfg, err := g.registry.server(serverID)
	if err != nil || !cfg.Enabled {
		writeMCPError(w, nil, http.StatusNotFound, -32602, "MCP server unavailable")
		return
	}
	principal, verified := auth.PrincipalFromContext(r.Context())
	if verified && g.server.quarantine != nil {
		env := &core.InspectionEnvelope{Tenant: principal.Tenant, Application: principal.Application, User: core.User{Subject: principal.Subject}, Metadata: map[string]string{"session_binding": principal.SessionID}}
		decision, checkErr := g.server.checkQuarantine(r.Context(), r, env, quarantine.Resource{Server: cfg.ID})
		if checkErr != nil {
			writeMCPError(w, nil, http.StatusServiceUnavailable, -32001, "MCP security state unavailable")
			return
		}
		if !decision.Allowed {
			writeMCPError(w, nil, http.StatusForbidden, -32003, "MCP request is quarantined")
			return
		}
	}
	if r.Method == http.MethodGet {
		g.handleSSE(w, r, cfg)
		return
	}
	if r.Method == http.MethodDelete {
		g.handleDelete(w, r, cfg)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, GET, DELETE")
		writeMCPError(w, nil, http.StatusMethodNotAllowed, -32600, "MCP method not allowed")
		return
	}
	g.handlePost(w, r, cfg)
}

func (g *mcpGateway) handlePost(w http.ResponseWriter, r *http.Request, cfg MCPServerConfig) {
	if r.Body == nil {
		writeMCPError(w, nil, http.StatusBadRequest, -32700, "MCP request is invalid")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, g.server.cfg.MCPMaxBodyBytes))
	if err != nil {
		writeMCPError(w, nil, http.StatusRequestEntityTooLarge, -32600, "MCP request is too large")
		return
	}
	var request mcpJSONRPCRequest
	if len(body) == 0 || json.Unmarshal(body, &request) != nil || request.JSONRPC != "2.0" || request.Method == "" {
		writeMCPError(w, request.ID, http.StatusBadRequest, -32600, "MCP JSON-RPC request is invalid")
		return
	}
	if !cfg.allowedMethod(request.Method) {
		writeMCPError(w, request.ID, http.StatusForbidden, -32601, "MCP method is not allowed")
		return
	}
	if request.Method == "tools/list" {
		g.handleToolsList(w, r, cfg, request.ID)
		return
	}
	if request.Method == "tools/call" {
		g.handleToolsCall(w, r, cfg, request)
		return
	}
	if request.Method == "initialize" {
		g.handleInitialize(w, r, cfg, request)
		return
	}
	g.proxyRPC(w, r, cfg, request, nil)
}

func (g *mcpGateway) handleInitialize(w http.ResponseWriter, r *http.Request, cfg MCPServerConfig, request mcpJSONRPCRequest) {
	resp, err := g.doUpstream(r.Context(), cfg, r, mustJSON(request), true)
	if err != nil {
		writeMCPError(w, request.ID, mcpStatus(err), -32001, "MCP server unavailable")
		return
	}
	defer resp.Body.Close()
	data, tooLarge, err := readBounded(resp.Body, g.server.cfg.MaxResponseBytes)
	if err != nil || tooLarge {
		writeMCPError(w, request.ID, http.StatusBadGateway, -32001, "MCP response unavailable")
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		writeMCPBody(w, resp.StatusCode, resp.Header, data)
		return
	}
	sessionID := resp.Header.Get("MCP-Session-Id")
	if !safeSessionID(sessionID) {
		sessionID = newMCPID()
	}
	if !g.bindSession(sessionID, cfg.ID, r) {
		writeMCPError(w, request.ID, http.StatusServiceUnavailable, -32001, "MCP session capacity exceeded")
		return
	}
	resp.Header.Set("MCP-Session-Id", sessionID)
	w.Header().Set("MCP-Session-Id", sessionID)
	writeMCPBody(w, resp.StatusCode, resp.Header, data)
}

func (g *mcpGateway) handleToolsList(w http.ResponseWriter, r *http.Request, cfg MCPServerConfig, id json.RawMessage) {
	tools, err := g.tools(r.Context(), cfg, r)
	if err != nil {
		writeMCPError(w, id, mcpStatus(err), -32001, "MCP tool catalog unavailable")
		return
	}
	filtered := make([]MCPTool, 0, len(tools))
	for _, tool := range tools {
		if g.toolAllowed(cfg, tool.Name) {
			filtered = append(filtered, tool)
		}
	}
	writeMCPJSON(w, http.StatusOK, mcpJSONRPCResponse{JSONRPC: "2.0", ID: id, Result: map[string]any{"tools": filtered}})
}

func (g *mcpGateway) handleToolsCall(w http.ResponseWriter, r *http.Request, cfg MCPServerConfig, request mcpJSONRPCRequest) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if json.Unmarshal(request.Params, &params) != nil || !safeToolName(params.Name) || len(params.Arguments) == 0 {
		writeMCPError(w, request.ID, http.StatusBadRequest, -32602, "MCP tool call arguments are invalid")
		return
	}
	if principal, verified := auth.PrincipalFromContext(r.Context()); verified && g.server.quarantine != nil {
		env := &core.InspectionEnvelope{Tenant: principal.Tenant, Application: principal.Application, User: core.User{Subject: principal.Subject}, Metadata: map[string]string{"session_binding": principal.SessionID}}
		decision, checkErr := g.server.checkQuarantine(r.Context(), r, env, quarantine.Resource{Server: cfg.ID, Tool: params.Name})
		if checkErr != nil {
			writeMCPError(w, request.ID, http.StatusServiceUnavailable, -32001, "MCP security state unavailable")
			return
		}
		if !decision.Allowed {
			writeMCPError(w, request.ID, http.StatusForbidden, -32003, "MCP tool is quarantined")
			return
		}
	}
	if !g.toolAllowed(cfg, params.Name) {
		principal, _ := auth.PrincipalFromContext(r.Context())
		g.server.recordQuarantineSignal(r.Context(), quarantine.Signal{Reason: quarantine.ReasonToolPolicyViolation, Identity: quarantine.Identity{Tenant: principal.Tenant, Application: principal.Application, Subject: principal.Subject, Session: principal.SessionID}, Resource: quarantine.Resource{Server: cfg.ID, Tool: params.Name}, Evidence: []quarantine.EvidenceRef{{Kind: "tool_policy", Digest: quarantineDigest(cfg.ID + "\x00" + params.Name)}}, Trusted: true, IdempotencyKey: "mcp:" + cfg.ID + ":" + params.Name})
		g.recordAudit(cfg.ID, params.Name, "BLOCK", "tool_allowlist", "tool_not_allowed", "", "blocked")
		writeMCPError(w, request.ID, http.StatusForbidden, -32003, "MCP tool is not permitted")
		return
	}
	args, err := normalizeJSON(params.Arguments, cfg)
	if err != nil {
		writeMCPError(w, request.ID, http.StatusBadRequest, -32602, "MCP tool arguments are invalid")
		return
	}
	tools, err := g.tools(r.Context(), cfg, r)
	if err != nil {
		writeMCPError(w, request.ID, mcpStatus(err), -32001, "MCP tool catalog unavailable")
		return
	}
	var schema json.RawMessage
	for _, tool := range tools {
		if tool.Name == params.Name {
			schema = tool.InputSchema
			break
		}
	}
	if schema == nil {
		writeMCPError(w, request.ID, http.StatusForbidden, -32003, "MCP tool is not permitted")
		return
	}
	_, schemaDepth, _ := cfg.schemaLimits()
	schemaBytes, _, _ := cfg.schemaLimits()
	if err := validateJSONSchema(args, schema, schemaBytes, schemaDepth); err != nil {
		writeMCPError(w, request.ID, http.StatusBadRequest, -32602, "MCP tool arguments do not match its schema")
		return
	}
	env := g.requestEnvelope(r, cfg.ID)
	decision := ToolDecision{Action: core.ActionAllow}
	if inspector, ok := g.server.pipeline.(interface {
		InspectToolCall(*core.InspectionEnvelope, ToolCall) (ToolDecision, error)
	}); ok {
		decision, err = inspector.InspectToolCall(env, ToolCall{Name: params.Name, Arguments: string(args)})
		if err != nil {
			writeMCPError(w, request.ID, http.StatusInternalServerError, -32000, "MCP security pipeline failed")
			return
		}
	}
	start := time.Now()
	g.recordAudit(cfg.ID, params.Name, string(decision.Action), decision.MatchedRule, decision.PolicyID, "", "inspected")
	if g.server.cfg.SecurityMode == ModeEnforce && (decision.Action == core.ActionBlock || decision.Action == core.ActionReview || decision.Action == core.ActionRestrictTools) {
		g.recordAudit(cfg.ID, params.Name, string(decision.Action), decision.MatchedRule, decision.PolicyID, "", "blocked")
		writeMCPError(w, request.ID, http.StatusForbidden, -32003, "MCP tool call blocked by security policy")
		return
	}
	if g.server.cfg.SecurityMode == ModeEnforce && (decision.Action == core.ActionRedact || decision.Action == core.ActionTokenize) && decision.TransformedContent != "" {
		args = []byte(decision.TransformedContent)
		if _, err := normalizeJSON(args, cfg); err != nil {
			writeMCPError(w, request.ID, http.StatusForbidden, -32003, "MCP transformed arguments are invalid")
			return
		}
	}
	params.Arguments = args
	forward := mcpJSONRPCRequest{JSONRPC: "2.0", ID: request.ID, Method: request.Method, Params: mustJSON(params)}
	g.proxyRPCWithStart(w, r, cfg, forward, start, params.Name)
}

func (g *mcpGateway) proxyRPC(w http.ResponseWriter, r *http.Request, cfg MCPServerConfig, request mcpJSONRPCRequest, _ any) {
	g.proxyRPCWithStart(w, r, cfg, request, time.Now(), "")
}

func (g *mcpGateway) proxyRPCWithStart(w http.ResponseWriter, r *http.Request, cfg MCPServerConfig, request mcpJSONRPCRequest, start time.Time, tool string) {
	resp, err := g.doUpstream(r.Context(), cfg, r, mustJSON(request), true)
	if err != nil {
		writeMCPError(w, request.ID, mcpStatus(err), -32001, "MCP server unavailable")
		return
	}
	defer resp.Body.Close()
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	data, tooLarge, readErr := readBounded(resp.Body, g.server.cfg.MaxResponseBytes)
	if readErr != nil || tooLarge {
		writeMCPError(w, request.ID, http.StatusBadGateway, -32001, "MCP response unavailable")
		return
	}
	if tool != "" && strings.Contains(contentType, "text/event-stream") {
		data, err = g.sanitizeMCPStream(r, cfg, tool, data)
		if err != nil {
			writeMCPError(w, request.ID, http.StatusForbidden, -32003, "MCP tool result blocked by security policy")
			return
		}
	} else if tool != "" && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		data, err = g.sanitizeMCPResult(r, cfg, tool, data)
		if err != nil {
			writeMCPError(w, request.ID, http.StatusForbidden, -32003, "MCP tool result blocked by security policy")
			return
		}
	}
	g.recordAudit(cfg.ID, tool, "ALLOW", "", "", credentialSource(resp), resultStatus(resp.StatusCode), time.Since(start))
	writeMCPBody(w, resp.StatusCode, resp.Header, data)
}

func (g *mcpGateway) tools(ctx context.Context, cfg MCPServerConfig, inbound *http.Request) ([]MCPTool, error) {
	bytesLimit, _, registryTTL := cfg.schemaLimits()
	ttl := g.server.cfg.MCPToolSchemaTTL
	if cfg.ToolSchemaPolicy.TTL != "" {
		ttl = registryTTL
	}
	if ttl <= 0 {
		ttl = registryTTL
	}
	cacheKey := cfg.ID
	g.mu.Lock()
	cached, ok := g.toolCache[cacheKey]
	g.mu.Unlock()
	if ok && time.Since(cached.At) < ttl {
		return cached.Tools, nil
	}
	request := mcpJSONRPCRequest{JSONRPC: "2.0", ID: json.RawMessage(`"aegis-tools-list"`), Method: "tools/list"}
	resp, err := g.doUpstream(ctx, cfg, inbound, mustJSON(request), true)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, tooLarge, err := readBounded(resp.Body, int64(bytesLimit))
	if err != nil || tooLarge || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New("tool catalog unavailable")
	}
	var envelope struct {
		Result struct {
			Tools []MCPTool `json:"tools"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &envelope) != nil || len(envelope.Result.Tools) > mcpMaxTools {
		return nil, errors.New("tool catalog invalid")
	}
	for i := range envelope.Result.Tools {
		if !safeToolName(envelope.Result.Tools[i].Name) {
			return nil, errors.New("tool catalog invalid")
		}
		if len(envelope.Result.Tools[i].Description) > 1024 {
			envelope.Result.Tools[i].Description = envelope.Result.Tools[i].Description[:1024]
		}
		if len(envelope.Result.Tools[i].InputSchema) > bytesLimit {
			return nil, errors.New("tool schema too large")
		}
		if _, err := normalizeJSON(envelope.Result.Tools[i].InputSchema, cfg); err != nil {
			return nil, errors.New("tool schema invalid")
		}
	}
	digest := sha256.Sum256(body)
	g.mu.Lock()
	g.toolCache[cacheKey] = mcpToolCache{At: time.Now(), Version: hex.EncodeToString(digest[:8]), Tools: envelope.Result.Tools}
	g.mu.Unlock()
	return envelope.Result.Tools, nil
}

func (g *mcpGateway) sanitizeMCPResult(r *http.Request, cfg MCPServerConfig, tool string, data []byte) ([]byte, error) {
	var envelope map[string]any
	if json.Unmarshal(data, &envelope) != nil {
		return data, nil
	}
	if result, ok := envelope["result"].(map[string]any); ok {
		if content, ok := result["content"].([]any); ok {
			for i, item := range content {
				obj, ok := item.(map[string]any)
				if !ok {
					continue
				}
				text, ok := obj["text"].(string)
				if !ok {
					continue
				}
				safe, err := g.inspectResultText(r, cfg, tool, text)
				if err != nil {
					return nil, err
				}
				obj["text"] = safe
				content[i] = obj
			}
			result["content"] = content
		}
	}
	return json.Marshal(envelope)
}

func (g *mcpGateway) sanitizeMCPStream(r *http.Request, cfg MCPServerConfig, tool string, data []byte) ([]byte, error) {
	parser := streaming.NewParser(bytes.NewReader(data), streaming.Config{MaxEventBytes: g.server.cfg.MCPMaxEventBytes, MaxBufferedBytes: g.server.cfg.MCPMaxBodyBytes})
	var aggregate strings.Builder
	for {
		event, err := parser.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if event.HasData && !event.IsDone {
			aggregate.WriteString(event.Data)
		}
	}
	if aggregate.Len() == 0 {
		return data, nil
	}
	safe, err := g.inspectResultText(r, cfg, tool, aggregate.String())
	if err != nil {
		return nil, err
	}
	if safe == aggregate.String() {
		return data, nil
	}
	return []byte("data: " + safe + "\n\n"), nil
}

func (g *mcpGateway) inspectResultText(r *http.Request, cfg MCPServerConfig, tool, text string) (string, error) {
	if len(text) > int(g.server.cfg.MCPMaxBodyBytes) {
		return "", errors.New("MCP result too large")
	}
	if inspector, ok := g.server.pipeline.(interface {
		InspectToolResult(*core.InspectionEnvelope, ToolResult) (ToolDecision, error)
	}); ok {
		decision, err := inspector.InspectToolResult(g.requestEnvelope(r, cfg.ID), ToolResult{Name: tool, Content: text})
		if err != nil {
			return "", err
		}
		if g.server.cfg.SecurityMode == ModeEnforce && (decision.Action == core.ActionBlock || decision.Action == core.ActionReview) {
			return "", errors.New("MCP result blocked")
		}
		if g.server.cfg.SecurityMode == ModeEnforce && (decision.Action == core.ActionRedact || decision.Action == core.ActionTokenize) && decision.TransformedContent != "" {
			return decision.TransformedContent, nil
		}
	}
	return text, nil
}

func (g *mcpGateway) doUpstream(ctx context.Context, cfg MCPServerConfig, inbound *http.Request, body []byte, credential bool) (*http.Response, error) {
	return g.doUpstreamMethod(ctx, cfg, inbound, body, credential, http.MethodPost)
}

func (g *mcpGateway) doUpstreamMethod(ctx context.Context, cfg MCPServerConfig, inbound *http.Request, body []byte, credential bool, method string) (*http.Response, error) {
	tc, _ := trace.From(ctx)
	if err := g.server.recordAudit(ctx, audit.Event{RequestID: newRequestID(), Timestamp: time.Now().UTC(), TraceID: tc.TraceID, SpanID: tc.SpanID, TraceFlags: tc.Flags, Direction: core.DirectionToolCall, Component: "mcp", Mode: g.server.cfg.SecurityMode, Action: core.ActionAllow, Code: "MCP_UPSTREAM_ATTEMPT", ToolProvider: safeSemanticMetadata(cfg.ID)}); err != nil {
		return nil, err
	}
	transport, err := g.transport(cfg)
	if err != nil {
		return nil, err
	}
	if !transport.allow() {
		return nil, ErrUpstreamBreakerOpen
	}
	timeout := cfg.timeout(g.server.cfg.MCPMaxStreamDuration)
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, method, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	if tc, ok := trace.From(requestCtx); ok {
		trace.Inject(req, trace.Child(tc))
	}
	accept := inbound.Header.Get("Accept")
	if accept == "" {
		accept = "application/json, text/event-stream"
	}
	req.Header.Set("Accept", accept)
	if version := inbound.Header.Get("MCP-Protocol-Version"); version != "" {
		req.Header.Set("MCP-Protocol-Version", version)
	}
	if sid := inbound.Header.Get("MCP-Session-Id"); sid != "" {
		if !g.validSession(sid, cfg.ID, inbound) {
			return nil, errors.New("MCP session is invalid")
		}
		req.Header.Set("MCP-Session-Id", sid)
	}
	credentialSourceType := ""
	if credential && cfg.credentialRef() != "" {
		cred, err := g.broker.Get(requestCtx, cfg.credentialRef())
		if err != nil {
			return nil, err
		}
		for key, values := range cred.Headers {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
		credentialSourceType = cred.SourceType
	}
	select {
	case transport.sem <- struct{}{}:
	case <-requestCtx.Done():
		return nil, requestCtx.Err()
	}
	defer func() { <-transport.sem }()
	resp, err := transport.client.Do(req)
	if err != nil {
		transport.failure()
		return nil, err
	}
	transport.success()
	if credentialSourceType != "" {
		resp.Header.Set(mcpCredentialHeader, credentialSourceType)
	}
	return resp, nil
}

func (g *mcpGateway) transport(cfg MCPServerConfig) (*mcpTransport, error) {
	if existing, ok := g.clients.Load(cfg.ID); ok {
		return existing.(*mcpTransport), nil
	}
	min, max := parseTLSVersions(cfg.TLS.MinVersion, cfg.TLS.MaxVersion, g.server.cfg.TLSMinVersion, g.server.cfg.TLSMaxVersion)
	tlsCfg, certs, err := (securetransport.ClientTLSOptions{CAFile: cfg.TLS.CAFile, CertificateFile: cfg.TLS.CertificateFile, KeyFile: cfg.TLS.KeyFile, ServerName: cfg.TLS.ServerName, MinVersion: min, MaxVersion: max, PollInterval: g.server.cfg.TLSReloadInterval}).TLSConfig()
	if err != nil {
		return nil, err
	}
	maxConcurrent := cfg.Concurrency
	if maxConcurrent <= 0 {
		maxConcurrent = 16
	}
	threshold := cfg.Breaker.Threshold
	if threshold <= 0 {
		threshold = 3
	}
	openInterval := 30 * time.Second
	if parsed, parseErr := time.ParseDuration(cfg.Breaker.OpenInterval); parseErr == nil && parsed > 0 {
		openInterval = parsed
	}
	t := &mcpTransport{client: &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}, Timeout: cfg.timeout(g.server.cfg.MCPMaxStreamDuration)}, sem: make(chan struct{}, maxConcurrent), certs: certs, threshold: threshold, openInterval: openInterval}
	actual, loaded := g.clients.LoadOrStore(cfg.ID, t)
	if loaded {
		return actual.(*mcpTransport), nil
	}
	return t, nil
}

func parseTLSVersions(min, max string, fallbackMin, fallbackMax uint16) (uint16, uint16) {
	if min != "" {
		fallbackMin = parseTLSVersion(min)
	}
	if max != "" {
		fallbackMax = parseTLSVersion(max)
	}
	return fallbackMin, fallbackMax
}

func (t *mcpTransport) allow() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.openAt.IsZero() || time.Now().After(t.openAt)
}
func (t *mcpTransport) success() { t.mu.Lock(); t.fails = 0; t.openAt = time.Time{}; t.mu.Unlock() }
func (t *mcpTransport) failure() {
	t.mu.Lock()
	t.fails++
	if t.fails >= t.threshold {
		t.openAt = time.Now().Add(t.openInterval)
	}
	t.mu.Unlock()
}

func (g *mcpGateway) toolAllowed(cfg MCPServerConfig, name string) bool {
	allowed := cfg.allowedTools()
	if len(allowed) > 0 && !matchMCPPattern(allowed, name) {
		return false
	}
	denied := []string{}
	if g.server.policy != nil {
		denied = append(denied, g.server.policy.RestrictedTools()...)
	}
	if pipe, ok := g.server.pipeline.(interface{ RestrictedTools() []string }); ok {
		denied = append(denied, pipe.RestrictedTools()...)
	}
	return !matchMCPPattern(denied, name)
}

func matchMCPPattern(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if ok, _ := path.Match(pattern, value); ok || pattern == value {
			return true
		}
	}
	return false
}
func safeToolName(name string) bool {
	return name != "" && len(name) <= 128 && !strings.ContainsAny(name, "\r\n")
}

func safeSessionID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._~-", r)) {
			return false
		}
	}
	return true
}

func (g *mcpGateway) requestEnvelope(r *http.Request, server string) *core.InspectionEnvelope {
	env := &core.InspectionEnvelope{RequestID: newRequestID(), Direction: core.DirectionToolCall, Target: core.Target{Provider: server}, Metadata: map[string]string{"mcp_server": server}}
	if p, ok := auth.PrincipalFromContext(r.Context()); ok {
		env.Tenant, env.Application, env.User = p.Tenant, p.Application, core.User{Subject: p.Subject, Roles: p.Roles}
		if p.SessionBound {
			env.Metadata["session_binding"] = p.SessionID
		}
	}
	return env
}

func (g *mcpGateway) bindSession(id, server string, r *http.Request) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cleanupSessionsLocked()
	if len(g.sessions) >= g.server.cfg.MCPMaxSessionCount {
		return false
	}
	p := principalIdentity(r)
	g.sessions[id] = mcpSession{Tenant: p.Tenant, Application: p.Application, Subject: p.Subject, Server: server, Expires: time.Now().Add(g.server.cfg.MCPSessionTTL)}
	return true
}
func (g *mcpGateway) validSession(id, server string, r *http.Request) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cleanupSessionsLocked()
	session, ok := g.sessions[id]
	if !ok || session.Server != server {
		return false
	}
	p := principalIdentity(r)
	return session.Tenant == p.Tenant && session.Application == p.Application && session.Subject == p.Subject
}
func (g *mcpGateway) deleteSession(id string, r *http.Request) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	session, ok := g.sessions[id]
	if !ok {
		return false
	}
	p := principalIdentity(r)
	if session.Tenant != p.Tenant || session.Application != p.Application || session.Subject != p.Subject {
		return false
	}
	delete(g.sessions, id)
	return true
}
func (g *mcpGateway) cleanupSessionsLocked() {
	now := time.Now()
	for id, session := range g.sessions {
		if now.After(session.Expires) {
			delete(g.sessions, id)
		}
	}
}
func principalIdentity(r *http.Request) auth.Principal {
	if p, ok := auth.PrincipalFromContext(r.Context()); ok {
		return p
	}
	return auth.Principal{Tenant: "anonymous", Application: "anonymous", Subject: remoteAddress(r.RemoteAddr)}
}

func (g *mcpGateway) handleSSE(w http.ResponseWriter, r *http.Request, cfg MCPServerConfig) {
	sid := r.Header.Get("MCP-Session-Id")
	if sid == "" {
		sid = r.URL.Query().Get("session_id")
	}
	if sid == "" || !g.validSession(sid, cfg.ID, r) {
		writeMCPError(w, nil, http.StatusNotFound, -32001, "MCP session is invalid")
		return
	}
	r.Header.Set("MCP-Session-Id", sid)
	resp, err := g.doUpstreamMethod(r.Context(), cfg, r, nil, true, http.MethodGet)
	if err != nil {
		writeMCPError(w, nil, mcpStatus(err), -32001, "MCP server unavailable")
		return
	}
	defer resp.Body.Close()
	body, tooLarge, err := readBounded(resp.Body, g.server.cfg.MCPMaxBodyBytes)
	if err != nil || tooLarge {
		writeMCPError(w, nil, http.StatusBadGateway, -32001, "MCP stream unavailable")
		return
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		body, err = g.sanitizeMCPStream(r, cfg, "", body)
		if err != nil {
			writeMCPError(w, nil, http.StatusForbidden, -32003, "MCP stream blocked by security policy")
			return
		}
	}
	writeMCPBody(w, resp.StatusCode, resp.Header, body)
}
func (g *mcpGateway) handleDelete(w http.ResponseWriter, r *http.Request, cfg MCPServerConfig) {
	sid := r.Header.Get("MCP-Session-Id")
	if sid == "" || !g.deleteSession(sid, r) {
		writeMCPError(w, nil, http.StatusNotFound, -32001, "MCP session is invalid")
		return
	}
	if p, ok := auth.PrincipalFromContext(r.Context()); ok {
		if revoker, ok := g.server.pipeline.(interface {
			RevokeTokenSession(context.Context, string, string, string, string) error
		}); ok {
			if err := revoker.RevokeTokenSession(r.Context(), p.Tenant, p.Application, p.Subject, p.SessionID); err != nil {
				writeMCPError(w, nil, http.StatusServiceUnavailable, -32001, "MCP session revocation unavailable")
				return
			}
		}
	}
	resp, err := g.doUpstreamMethod(r.Context(), cfg, r, nil, true, http.MethodDelete)
	if err == nil {
		defer resp.Body.Close()
	}
	writeMCPJSON(w, http.StatusOK, mcpJSONRPCResponse{JSONRPC: "2.0", Result: map[string]any{}})
}

func (g *mcpGateway) recordAudit(server, tool, action, rule, policy, credential, status string, extra ...time.Duration) {
	latency := int64(0)
	if len(extra) > 0 {
		latency = extra[0].Milliseconds()
	}
	event := MCPAuditEvent{Timestamp: time.Now().UTC(), Server: safeSemanticMetadata(server), Tool: safeSemanticMetadata(tool), Action: safeSemanticMetadata(action), Rule: safeSemanticMetadata(rule), Policy: safeSemanticMetadata(policy), Direction: "TOOL", LatencyMS: latency, ResultStatus: safeSemanticMetadata(status), Credential: safeSemanticMetadata(credential)}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.audit = append(g.audit, event)
	if len(g.audit) > mcpMaxAudit {
		g.audit = g.audit[len(g.audit)-mcpMaxAudit:]
	}
}

func (g *mcpGateway) status() []map[string]any {
	reg, err := g.registry.snapshot()
	if err != nil {
		return []map[string]any{}
	}
	out := make([]map[string]any, 0, len(reg.Servers))
	for _, cfg := range reg.Servers {
		state := "disabled"
		if cfg.Enabled {
			state = "configured"
		}
		out = append(out, map[string]any{"id": safeSemanticMetadata(cfg.ID), "enabled": cfg.Enabled, "status": state, "url_scheme": safeSemanticMetadata(urlScheme(cfg.URL)), "capabilities": cfg.Capabilities, "credential_configured": cfg.credentialRef() != ""})
	}
	return out
}

func urlScheme(raw string) string {
	if parsed, err := url.Parse(raw); err == nil {
		return parsed.Scheme
	}
	return "invalid"
}
func (g *mcpGateway) auditSnapshot() []MCPAuditEvent {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := append([]MCPAuditEvent(nil), g.audit...)
	return out
}

func (g *mcpGateway) metricsSnapshot() map[string]any {
	events := g.auditSnapshot()
	byAction := map[string]int{}
	byStatus := map[string]int{}
	for _, event := range events {
		byAction[event.Action]++
		byStatus[event.ResultStatus]++
	}
	return map[string]any{"audit_events": len(events), "actions": byAction, "result_status": byStatus}
}

func credentialSource(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	return resp.Header.Get(mcpCredentialHeader)
}
func resultStatus(status int) string {
	if status >= 200 && status < 300 {
		return "ok"
	}
	return "upstream_error"
}
func mcpStatus(err error) int {
	if errors.Is(err, ErrUpstreamBreakerOpen) {
		return http.StatusServiceUnavailable
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}
func newMCPID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "mcp-session"
	}
	return hex.EncodeToString(b[:])
}
func mustJSON(value any) []byte { data, _ := json.Marshal(value); return data }
func writeMCPJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(mustJSON(value))
}
func writeMCPBody(w http.ResponseWriter, status int, headers http.Header, body []byte) {
	if ct := headers.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	for _, name := range []string{"MCP-Session-Id", "MCP-Protocol-Version"} {
		if value := headers.Get(name); value != "" {
			w.Header().Set(name, value)
		}
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
func writeMCPError(w http.ResponseWriter, id json.RawMessage, status, code int, message string) {
	writeMCPJSON(w, status, mcpJSONRPCResponse{JSONRPC: "2.0", ID: id, Error: &mcpRPCError{Code: code, Message: message}})
}

func normalizeJSON(raw json.RawMessage, cfg MCPServerConfig) ([]byte, error) {
	limit, depth, _ := cfg.schemaLimits()
	if len(raw) > limit {
		return nil, errors.New("JSON too large")
	}
	var value any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	if err := jsonDepth(value, 0, depth); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}
func jsonDepth(value any, current, limit int) error {
	if current > limit {
		return errors.New("JSON too deep")
	}
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			if err := jsonDepth(item, current+1, limit); err != nil {
				return err
			}
		}
	case map[string]any:
		for _, item := range v {
			if err := jsonDepth(item, current+1, limit); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateJSONSchema(args []byte, schema json.RawMessage, limits ...interface{}) error {
	maxBytes, maxDepth := 256*1024, 16
	if len(limits) >= 2 {
		if v, ok := limits[0].(int); ok && v > 0 {
			maxBytes = v
		}
		if v, ok := limits[1].(int); ok && v > 0 {
			maxDepth = v
		}
	}
	if len(args) > maxBytes {
		return errors.New("arguments too large")
	}
	var value, doc any
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.UseNumber()
	if dec.Decode(&value) != nil || json.Unmarshal(schema, &doc) != nil {
		return errors.New("schema invalid")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("schema invalid")
	}
	return validateSchemaValue(value, doc, 0, maxDepth)
}
func validateSchemaValue(value, schema any, depth, maxDepth int) error {
	if depth > maxDepth {
		return errors.New("schema depth exceeded")
	}
	obj, ok := schema.(map[string]any)
	if !ok {
		return nil
	}
	if enum, ok := obj["enum"].([]any); ok {
		matched := false
		for _, candidate := range enum {
			if fmt.Sprint(candidate) == fmt.Sprint(value) {
				matched = true
			}
		}
		if !matched {
			return errors.New("enum mismatch")
		}
	}
	if typ, _ := obj["type"].(string); typ != "" && !jsonType(value, typ) {
		return errors.New("type mismatch")
	}
	if required, ok := obj["required"].([]any); ok {
		m, isMap := value.(map[string]any)
		if isMap {
			for _, item := range required {
				name, _ := item.(string)
				if _, exists := m[name]; !exists {
					return errors.New("required property missing")
				}
			}
		}
	}
	if properties, ok := obj["properties"].(map[string]any); ok {
		if m, isMap := value.(map[string]any); isMap {
			if additional, exists := obj["additionalProperties"].(bool); exists && !additional {
				for name := range m {
					if _, known := properties[name]; !known {
						return errors.New("additional property is not allowed")
					}
				}
			}
			for name, child := range properties {
				if v, exists := m[name]; exists {
					if err := validateSchemaValue(v, child, depth+1, maxDepth); err != nil {
						return err
					}
				}
			}
		}
	}
	if items, ok := obj["items"]; ok {
		if list, isList := value.([]any); isList {
			for _, item := range list {
				if err := validateSchemaValue(item, items, depth+1, maxDepth); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func jsonType(value any, typ string) bool {
	switch typ {
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "number", "integer":
		number, ok := value.(json.Number)
		if !ok {
			return false
		}
		if typ == "integer" {
			return !strings.ContainsAny(string(number), ".eE")
		}
		return true
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "null":
		return value == nil
	default:
		return true
	}
}

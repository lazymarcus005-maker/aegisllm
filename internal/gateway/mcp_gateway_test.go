package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aegisllm/gateway/internal/auth"
	"github.com/golang-jwt/jwt/v5"
)

func TestMCPGatewayEndToEndSecurityAndCredentialIsolation(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	var seenAuth, seenIdentity, seenCredential string
	mcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		seenAuth = r.Header.Get("Authorization")
		seenIdentity = r.Header.Get("X-Tenant-Id") + r.Header.Get("X-Application-Id") + r.Header.Get("X-User-Id")
		seenCredential = r.Header.Get("X-MCP-Key")
		body, _ := io.ReadAll(r.Body)
		var req mcpJSONRPCRequest
		_ = json.Unmarshal(body, &req)
		calls = append(calls, req.Method)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			w.Header().Set("MCP-Session-Id", "session-a")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"fake","version":"1"}}}`))
		case "tools/list":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"list","result":{"tools":[{"name":"safe","description":"untrusted text","inputSchema":{"type":"object","properties":{"phone":{"type":"string"}}}},{"name":"shell","inputSchema":{"type":"object"}},{"name":"result_secret","inputSchema":{"type":"object"}}]}}`))
		case "tools/call":
			var params struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}
			_ = json.Unmarshal(req.Params, &params)
			if params.Name == "result_secret" {
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}]}}`))
			} else {
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"customer phone 0812345678"}]}}`))
			}
		default:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
		}
	}))
	defer mcp.Close()

	dir := t.TempDir()
	registryPath := writeMCPTestFile(t, dir, "registry.yaml", fmt.Sprintf(`schema: aegisllm.mcp/v1
version: 1
servers:
  - id: cloud
    url: %s
    enabled: true
    allowed_tool_patterns: ["safe", "shell", "result_secret"]
    credential_ref: fake-header
    tool_schema_policy: {max_bytes: 2048, max_depth: 8, ttl: 1m}
    timeout: 2s
    concurrency: 2
    breaker: {threshold: 3, open_interval: 1m}
`, mcp.URL))
	secretPath := writeMCPTestFile(t, dir, "mcp.secret", "broker-secret")
	credentialsPath := writeMCPTestFile(t, dir, "credentials.yaml", fmt.Sprintf(`schema: aegisllm.credentials/v1
version: 1
profiles:
  - id: fake-header
    type: header
    header: X-MCP-Key
    secret_file: %s
`, secretPath))

	key, keyPath := gatewayTestKey(t)
	srv, gw, _ := newTestGateway(t, func(c *Config) {
		c.SecurityMode = ModeEnforce
		c.AuthMode = auth.ModeJWT
		c.JWTPublicKeyFile = keyPath
		c.JWTIssuer = "issuer"
		c.JWTAudience = "aud"
		c.MCPRegistryFile = registryPath
		c.MCPCredentialsFile = credentialsPath
		c.MCPMaxBodyBytes = 1 << 16
	}, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	pipe, _ := newRealPipeline(t)
	srv.SetPipeline(pipe)
	token := gatewayToken(t, key, jwt.MapClaims{"iss": "issuer", "aud": "aud", "exp": time.Now().Add(time.Minute).Unix(), "tenant_id": "tenant-a", "azp": "app-a", "sub": "subject-a", "roles": []string{auth.RoleToolInvoke}})

	post := func(body string) (int, []byte, http.Header) {
		req, _ := http.NewRequest(http.MethodPost, gw.URL+"/mcp/cloud", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Tenant-Id", "spoofed-tenant")
		req.Header.Set("X-Application-Id", "spoofed-app")
		req.Header.Set("X-User-Id", "spoofed-user")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, data, resp.Header.Clone()
	}
	status, _, headers := post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
	if status != http.StatusOK || headers.Get("MCP-Session-Id") != "session-a" {
		t.Fatalf("initialize status=%d session=%q", status, headers.Get("MCP-Session-Id"))
	}
	status, body, _ := post(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	if status != http.StatusOK || strings.Contains(string(body), `"name":"shell"`) {
		t.Fatalf("restricted tool was listed: status=%d body=%s", status, body)
	}
	status, body, _ = post(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"shell","arguments":{}}}`)
	if status != http.StatusForbidden || strings.Contains(string(body), "result") {
		t.Fatalf("guessed restricted tool was forwarded: %d %s", status, body)
	}
	status, body, _ = post(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"safe","arguments":{"phone":"0812345678"}}}`)
	if status != http.StatusOK || strings.Contains(string(body), "0812345678") {
		t.Fatalf("PII result was not protected: %d %s", status, body)
	}
	status, body, _ = post(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"result_secret","arguments":{}}}`)
	if status != http.StatusForbidden || strings.Contains(string(body), "eyJhbGci") {
		t.Fatalf("secret result was exposed: %d %s", status, body)
	}

	mu.Lock()
	gotCalls := append([]string(nil), calls...)
	gotAuth, gotIdentity, gotCredential := seenAuth, seenIdentity, seenCredential
	mu.Unlock()
	if gotAuth != "" || gotIdentity != "" || gotCredential != "broker-secret" {
		t.Fatalf("credential boundary failed auth=%q identity=%q credential=%q", gotAuth, gotIdentity, gotCredential)
	}
	for _, method := range gotCalls {
		if method == "tools/call" && strings.Contains(method, "shell") {
			t.Fatal("restricted call reached fake server")
		}
	}
	if len(gotCalls) < 4 {
		t.Fatalf("expected initialize/list/call traffic, got %v", gotCalls)
	}
	operator := gatewayToken(t, key, jwt.MapClaims{"iss": "issuer", "aud": "aud", "exp": time.Now().Add(time.Minute).Unix(), "roles": []string{auth.RoleOperator}})
	statusReq, _ := http.NewRequest(http.MethodGet, gw.URL+"/api/mcp/servers", nil)
	statusReq.Header.Set("Authorization", "Bearer "+operator)
	statusResp, err := http.DefaultClient.Do(statusReq)
	if err != nil {
		t.Fatal(err)
	}
	statusBody, _ := io.ReadAll(statusResp.Body)
	statusResp.Body.Close()
	if statusResp.StatusCode != http.StatusOK || strings.Contains(string(statusBody), mcp.URL) {
		t.Fatalf("MCP status was not sanitized: %d %s", statusResp.StatusCode, statusBody)
	}
	auditReq, _ := http.NewRequest(http.MethodGet, gw.URL+"/api/mcp/audit", nil)
	auditReq.Header.Set("Authorization", "Bearer "+operator)
	auditResp, err := http.DefaultClient.Do(auditReq)
	if err != nil {
		t.Fatal(err)
	}
	auditBody, _ := io.ReadAll(auditResp.Body)
	auditResp.Body.Close()
	if auditResp.StatusCode != http.StatusOK || strings.Contains(string(auditBody), "0812345678") || strings.Contains(string(auditBody), "broker-secret") || !strings.Contains(string(auditBody), "header") {
		t.Fatalf("MCP audit was not sanitized/bounded: %d %s", auditResp.StatusCode, auditBody)
	}
}

func TestMCPGatewayRejectsSchemaDepthAndSizeAndProtectsSplitSSE(t *testing.T) {
	var calls int
	mcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: {\"result\":{\"content\":[{\"text\":\"customer 0812\n\n"))
			_, _ = w.Write([]byte("data: 345678\"}]}}\n\n"))
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req mcpJSONRPCRequest
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			w.Header().Set("MCP-Session-Id", "split-session")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
		case "tools/list":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"safe","inputSchema":{"type":"object","properties":{"value":{"type":"string"}}}}]}}`))
		case "tools/call":
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: {\"result\":{\"content\":[{\"text\":\"customer 0812\"}]}}\n\n"))
			_, _ = w.Write([]byte("data: 345678\n\n"))
		}
	}))
	defer mcp.Close()
	dir := t.TempDir()
	registryPath := writeMCPTestFile(t, dir, "registry.yaml", fmt.Sprintf(`schema: aegisllm.mcp/v1
version: 1
servers:
  - id: cloud
    url: %s
    enabled: true
    tool_schema_policy: {max_bytes: 128, max_depth: 3, ttl: 1m}
`, mcp.URL))
	key, keyPath := gatewayTestKey(t)
	srv, gw, _ := newTestGateway(t, func(c *Config) {
		c.SecurityMode = ModeEnforce
		c.AuthMode = auth.ModeJWT
		c.JWTPublicKeyFile = keyPath
		c.JWTIssuer = "issuer"
		c.JWTAudience = "aud"
		c.MCPRegistryFile = registryPath
		// Keep the pre-expiry assertion independent of host scheduling. Expiry
		// semantics are asserted below by moving the test session past its
		// deadline under the gateway's own synchronization.
		c.MCPSessionTTL = 10 * time.Minute
	}, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	pipe, _ := newRealPipeline(t)
	srv.SetPipeline(pipe)
	token := gatewayToken(t, key, jwt.MapClaims{"iss": "issuer", "aud": "aud", "exp": time.Now().Add(time.Minute).Unix(), "tenant_id": "tenant-a", "azp": "app-a", "sub": "subject-a", "roles": []string{auth.RoleToolInvoke}})
	post := func(body string) (int, []byte) {
		req, _ := http.NewRequest(http.MethodPost, gw.URL+"/mcp/cloud", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, data
	}
	if status, _ := post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`); status != http.StatusOK {
		t.Fatalf("initialize status=%d", status)
	}
	other := gatewayToken(t, key, jwt.MapClaims{"iss": "issuer", "aud": "aud", "exp": time.Now().Add(time.Minute).Unix(), "tenant_id": "tenant-b", "azp": "app-b", "sub": "subject-b", "roles": []string{auth.RoleToolInvoke}})
	otherReq, _ := http.NewRequest(http.MethodGet, gw.URL+"/mcp/cloud?session_id=split-session", nil)
	otherReq.Header.Set("Authorization", "Bearer "+other)
	otherResp, err := http.DefaultClient.Do(otherReq)
	if err != nil {
		t.Fatal(err)
	}
	otherResp.Body.Close()
	if otherResp.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-principal session reuse status=%d", otherResp.StatusCode)
	}
	deep := `{"a":{"b":{"c":{"d":"x"}}}}`
	if status, _ := post(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"safe","arguments":` + deep + `}}`); status != http.StatusBadRequest {
		t.Fatalf("deep args status=%d", status)
	}
	if status, _ := post(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"safe","arguments":{"value":"` + strings.Repeat("x", 512) + `"}}}`); status != http.StatusBadRequest {
		t.Fatalf("large args status=%d", status)
	}
	resp, err := http.NewRequest(http.MethodGet, gw.URL+"/mcp/cloud?session_id=split-session", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Header.Set("Authorization", "Bearer "+token)
	got, err := http.DefaultClient.Do(resp)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(got.Body)
	got.Body.Close()
	if got.StatusCode != http.StatusOK || strings.Contains(string(data), "0812345678") {
		t.Fatalf("split SSE was not protected: %d %s", got.StatusCode, data)
	}
	srv.mcp.mu.Lock()
	if session, ok := srv.mcp.sessions["split-session"]; ok {
		session.Expires = time.Now().Add(-time.Second)
		srv.mcp.sessions["split-session"] = session
	}
	srv.mcp.mu.Unlock()
	expiredReq, _ := http.NewRequest(http.MethodGet, gw.URL+"/mcp/cloud?session_id=split-session", nil)
	expiredReq.Header.Set("Authorization", "Bearer "+token)
	expiredResp, err := http.DefaultClient.Do(expiredReq)
	if err != nil {
		t.Fatal(err)
	}
	expiredResp.Body.Close()
	if expiredResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expired MCP session status=%d", expiredResp.StatusCode)
	}
	if calls < 2 {
		t.Fatalf("expected catalog and stream calls, got %d", calls)
	}
}

func TestMCPRegistryRejectsInlineSecretsAndKeepsLastGood(t *testing.T) {
	dir := t.TempDir()
	path := writeMCPTestFile(t, dir, "registry.yaml", `schema: aegisllm.mcp/v1
version: 1
servers:
  - id: cloud
    url: https://example.invalid/mcp
    enabled: true
`)
	reg, err := newMCPRegistry(path, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reg.close)
	if _, err := reg.server("cloud"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`schema: aegisllm.mcp/v1
version: 1
servers:
  - id: cloud
    url: https://user:secret@example.invalid/mcp
    enabled: true
`), 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	server, err := reg.server("cloud")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(server.URL, "secret") {
		t.Fatal("malformed registry replaced last-known-good")
	}
}

func writeMCPTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	file := dir + "/" + name
	if err := os.WriteFile(file, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return file
}

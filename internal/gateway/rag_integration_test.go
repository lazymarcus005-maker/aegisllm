package gateway

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/aegisllm/gateway/internal/ragauth"
)

func TestGatewayRAGAuthorizationRunsBeforeUpstream(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"ok","choices":[]}`))
	}))
	defer upstream.Close()

	cfg := Config{DeploymentProfile: ProfileDevelopment, SecurityMode: ModeEnforce, AuthMode: "off", UpstreamBaseURL: upstream.URL, UpstreamAuthMode: "none", HeaderApplication: "X-Application-Id", HeaderTenant: "X-Tenant-Id", HeaderUser: "X-User-Id"}
	srv, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	g, err := ragauth.NewGateway(ragauth.Config{Mode: ragauth.ModeEnforce, Adapter: ragauth.AdapterFake, Limits: ragauth.Limits{}}, &ragauth.FakeAuthorizer{Allow: true})
	if err != nil {
		t.Fatal(err)
	}
	srv.SetRAGAuthorization(g)
	h := srv.Handler()
	body := []byte(`{"model":"m","messages":[{"role":"user","content":"answer"}],"retrieval":{"query":"q","collection":"knowledge","purpose":"answer","documents":[{"id":"doc-1","tenant_id":"tenant-a","application_id":"app-a","content":"authorized context"}]}}`)
	if _, err := ragauth.Parse(body, ragauth.Identity{Tenant: "tenant-a", Application: "app-a", Subject: "user-a"}, "req", "p", 1, ragauth.Limits{}); err != nil {
		t.Fatalf("rag parse: %v", err)
	}
	newRequest := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytesReader(body))
		req.Header.Set("X-Tenant-Id", "tenant-a")
		req.Header.Set("X-Application-Id", "app-a")
		req.Header.Set("X-User-Id", "user-a")
		return req
	}
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, newRequest())
	if resp.Code != http.StatusOK || upstreamCalls.Load() != 1 {
		t.Fatalf("status=%d upstream_calls=%d body=%s", resp.Code, upstreamCalls.Load(), resp.Body.String())
	}

	deny, err := ragauth.NewGateway(ragauth.Config{Mode: ragauth.ModeEnforce, Adapter: ragauth.AdapterDeny, Limits: ragauth.Limits{}}, ragauth.DenyByDefault{})
	if err != nil {
		t.Fatal(err)
	}
	srv.SetRAGAuthorization(deny)
	resp = httptest.NewRecorder()
	h.ServeHTTP(resp, newRequest())
	if resp.Code != http.StatusForbidden || upstreamCalls.Load() != 1 {
		t.Fatalf("denied status=%d upstream_calls=%d", resp.Code, upstreamCalls.Load())
	}
}

// bytesReader keeps this test independent of the gateway's request-body
// implementation while preserving a fresh body for each invocation.
func bytesReader(body []byte) *bytes.Buffer { return bytes.NewBuffer(body) }

package gateway

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aegisllm/gateway/internal/dashboard"
	"github.com/aegisllm/gateway/internal/observability"
	"github.com/aegisllm/gateway/internal/policy"
	"github.com/golang-jwt/jwt/v5"
)

func TestJWTIngressUsesVerifiedIdentityAndStripsHeaders(t *testing.T) {
	key, keyPath := gatewayTestKey(t)
	var gotHeaders http.Header
	srv, gw, _ := newTestGateway(t, func(c *Config) {
		c.AuthMode = "jwt"
		c.SecurityMode = ModeEnforce
		c.JWTPublicKeyFile = keyPath
		c.JWTIssuer = "issuer"
		c.JWTAudience = "aud"
	}, func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"ok","choices":[{"message":{"role":"assistant","content":"hi"}}]}`))
	})
	pipe, sink := newRealPipeline(t)
	srv.SetPipeline(pipe)
	token := gatewayToken(t, key, jwt.MapClaims{
		"iss": "issuer", "aud": "aud", "exp": time.Now().Add(time.Minute).Unix(),
		"tenant_id": "verified-tenant", "azp": "verified-app", "sub": "verified-user",
		"roles": []string{"aegis.invoke"}, "provider": "verified-provider",
	})
	req, err := http.NewRequest(http.MethodPost, gw.URL+"/v1/chat/completions", strings.NewReader(cleanRequest))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant-Id", "spoofed-tenant")
	req.Header.Set("X-Application-Id", "spoofed-app")
	req.Header.Set("X-User-Id", "spoofed-user")
	req.Header.Set("X-Target-Provider", "spoofed-provider")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	for _, header := range []string{"Authorization", "X-Tenant-Id", "X-Application-Id", "X-User-Id", "X-Target-Provider"} {
		if gotHeaders.Get(header) != "" {
			t.Fatalf("inbound header %s reached upstream: %q", header, gotHeaders.Get(header))
		}
	}
	auditOutput := sink.String()
	for _, value := range []string{"verified-tenant", "verified-app", "verified-user", "verified-provider"} {
		if !strings.Contains(auditOutput, value) {
			t.Fatalf("verified principal value %q missing from audit: %s", value, auditOutput)
		}
	}
	if strings.Contains(auditOutput, "spoofed-") {
		t.Fatalf("spoofed identity entered audit: %s", auditOutput)
	}
}

func TestJWTRouteRBAC(t *testing.T) {
	key, keyPath := gatewayTestKey(t)
	srv, gw, _ := newTestGateway(t, func(c *Config) {
		c.AuthMode = "jwt"
		c.JWTPublicKeyFile = keyPath
		c.JWTIssuer = "issuer"
		c.JWTAudience = "aud"
	}, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	pol, err := policy.LoadFile("../../policies/enterprise-default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	srv.SetPolicy(pol)
	metrics := observability.New()
	srv.SetProtectionDashboard(dashboard.New(metrics))
	srv.SetMetricsHandler(metrics.Handler())
	metricsGateway := httptest.NewServer(srv.Handler())
	t.Cleanup(metricsGateway.Close)
	get := func(path, token string) int {
		req, _ := http.NewRequest(http.MethodGet, gw.URL+path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	invoke := gatewayToken(t, key, jwt.MapClaims{"iss": "issuer", "aud": "aud", "exp": time.Now().Add(time.Minute).Unix(), "roles": []string{"aegis.invoke"}})
	operator := gatewayToken(t, key, jwt.MapClaims{"iss": "issuer", "aud": "aud", "exp": time.Now().Add(time.Minute).Unix(), "roles": []string{"aegis.operator"}})
	if got := get("/dashboard", ""); got != http.StatusUnauthorized {
		t.Fatalf("missing dashboard auth status=%d", got)
	}
	if got := get("/dashboard", invoke); got != http.StatusForbidden {
		t.Fatalf("invoke dashboard status=%d", got)
	}
	if got := get("/dashboard", operator); got != http.StatusOK {
		t.Fatalf("operator dashboard status=%d", got)
	}
	if got := get("/api/protection-stats", operator); got != http.StatusOK {
		t.Fatalf("operator stats status=%d", got)
	}
	if got := get("/api/routes", ""); got != http.StatusUnauthorized {
		t.Fatalf("missing routes auth status=%d", got)
	}
	if got := get("/api/routes", invoke); got != http.StatusForbidden {
		t.Fatalf("invoke routes status=%d", got)
	}
	if got := get("/api/routes", operator); got != http.StatusOK {
		t.Fatalf("operator routes status=%d", got)
	}
	if got := get("/api/effective-policy", ""); got != http.StatusUnauthorized {
		t.Fatalf("missing effective-policy auth status=%d", got)
	}
	if got := get("/api/effective-policy", invoke); got != http.StatusForbidden {
		t.Fatalf("invoke effective-policy status=%d", got)
	}
	if got := get("/api/effective-policy", operator); got != http.StatusOK {
		t.Fatalf("operator effective-policy status=%d", got)
	}
	for _, tc := range []struct {
		name  string
		token string
		want  int
	}{
		{name: "missing metrics auth", want: http.StatusUnauthorized},
		{name: "invoke metrics auth", token: invoke, want: http.StatusForbidden},
		{name: "operator metrics auth", token: operator, want: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, metricsGateway.URL+"/metrics", nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("status=%d want=%d", resp.StatusCode, tc.want)
			}
		})
	}
	req, _ := http.NewRequest(http.MethodPost, gw.URL+"/v1/chat/completions", strings.NewReader(cleanRequest))
	req.Header.Set("Authorization", "Bearer "+invoke)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("invoke route status=%d", resp.StatusCode)
	}
}

func gatewayTestKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/public.pem"
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return key, path
}

func gatewayToken(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

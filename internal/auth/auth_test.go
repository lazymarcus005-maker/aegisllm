package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestRS256ClaimsAndHeaderStripping(t *testing.T) {
	key := mustRSAKey(t)
	path := writePublicKey(t, &key.PublicKey)
	a, err := New(Config{Mode: ModeJWT, DeploymentProfile: "production", PublicKeyFile: path,
		Issuer: "issuer", Audience: "aud", TenantClaim: "tenant", ApplicationClaim: "app",
		SubjectClaim: "subject", RolesClaim: "roles", ProviderClaim: "provider"})
	if err != nil {
		t.Fatal(err)
	}
	token := signToken(t, jwt.SigningMethodRS256, key, jwt.MapClaims{
		"iss": "issuer", "aud": "aud", "exp": time.Now().Add(time.Minute).Unix(),
		"tenant": "tenant-from-token", "app": "app-from-token", "subject": "user-from-token",
		"roles": []string{RoleInvoke}, "provider": "local",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant-Id", "spoofed")
	req.Header.Set("X-Application-Id", "spoofed")
	req.Header.Set("X-User-Id", "spoofed")
	req.Header.Set("X-Target-Provider", "spoofed")
	var got Principal
	var ok bool
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok = PrincipalFromContext(r.Context())
		for _, name := range []string{"Authorization", "X-Tenant-Id", "X-Application-Id", "X-User-Id", "X-Target-Provider"} {
			if r.Header.Get(name) != "" {
				t.Errorf("%s was not stripped", name)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}), RoleInvoke)
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusNoContent || !ok || got.Tenant != "tenant-from-token" || got.Application != "app-from-token" || got.Subject != "user-from-token" || got.Provider != "local" || !got.HasRole(RoleInvoke) {
		t.Fatalf("status=%d principal=%+v ok=%v", resp.Code, got, ok)
	}
}

func TestJWTValidationRejectsInvalidTokens(t *testing.T) {
	key := mustRSAKey(t)
	path := writePublicKey(t, &key.PublicKey)
	a, err := New(Config{Mode: ModeJWT, DeploymentProfile: "production", PublicKeyFile: path, Issuer: "issuer", Audience: "aud", RolesClaim: "roles"})
	if err != nil {
		t.Fatal(err)
	}
	otherKey := mustRSAKey(t)
	base := jwt.MapClaims{"iss": "issuer", "aud": "aud", "exp": time.Now().Add(time.Minute).Unix(), "roles": []string{RoleInvoke}}
	tests := []struct {
		name  string
		token string
	}{
		{"expired", signToken(t, jwt.SigningMethodRS256, key, jwt.MapClaims{"iss": "issuer", "aud": "aud", "exp": time.Now().Add(-time.Minute).Unix(), "roles": []string{RoleInvoke}})},
		{"not yet valid", signToken(t, jwt.SigningMethodRS256, key, withTime(base, "nbf", time.Now().Add(time.Minute).Unix()))},
		{"wrong issuer", signToken(t, jwt.SigningMethodRS256, key, withClaim(base, "iss", "other"))},
		{"wrong audience", signToken(t, jwt.SigningMethodRS256, key, withClaim(base, "aud", "other"))},
		{"bad signature", signToken(t, jwt.SigningMethodRS256, otherKey, base)},
		{"none algorithm", signToken(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, base)},
		{"HS256 confusion", signToken(t, jwt.SigningMethodHS256, []byte("test-secret"), base)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			resp := httptest.NewRecorder()
			a.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("invalid token reached handler") })).ServeHTTP(resp, req)
			if resp.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
			}
		})
	}
}

func TestRoleAuthorizationAndDevelopmentHMAC(t *testing.T) {
	a, err := New(Config{Mode: ModeJWT, DeploymentProfile: "development", HMACSecret: "development-only-secret", Issuer: "issuer", Audience: "aud", RolesClaim: "roles"})
	if err != nil {
		t.Fatal(err)
	}
	makeRequest := func(roles []string) *httptest.ResponseRecorder {
		token := signToken(t, jwt.SigningMethodHS256, []byte("development-only-secret"), jwt.MapClaims{
			"iss": "issuer", "aud": "aud", "exp": time.Now().Add(time.Minute).Unix(), "roles": roles,
		})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp := httptest.NewRecorder()
		a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), RoleOperator).ServeHTTP(resp, req)
		return resp
	}
	if got := makeRequest([]string{RoleInvoke}).Code; got != http.StatusForbidden {
		t.Fatalf("invoke-only operator status=%d", got)
	}
	if got := makeRequest([]string{RoleOperator}).Code; got != http.StatusNoContent {
		t.Fatalf("operator status=%d", got)
	}
	if _, err := New(Config{Mode: ModeJWT, DeploymentProfile: "production", HMACSecret: "secret"}); err == nil {
		t.Fatal("production HMAC configuration accepted")
	}
}

func TestPublicKeyRotationKeepsRBACEnforced(t *testing.T) {
	first, second := mustRSAKey(t), mustRSAKey(t)
	path := writePublicKey(t, &first.PublicKey)
	a, err := New(Config{Mode: ModeJWT, DeploymentProfile: "production", PublicKeyFile: path, Issuer: "issuer", Audience: "aud", RolesClaim: "roles"})
	if err != nil {
		t.Fatal(err)
	}
	makeRequest := func(token string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp := httptest.NewRecorder()
		a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), RoleInvoke).ServeHTTP(resp, req)
		return resp.Code
	}
	oldToken := signToken(t, jwt.SigningMethodRS256, first, jwt.MapClaims{"iss": "issuer", "aud": "aud", "exp": time.Now().Add(time.Minute).Unix(), "roles": []string{RoleInvoke}})
	newToken := signToken(t, jwt.SigningMethodRS256, second, jwt.MapClaims{"iss": "issuer", "aud": "aud", "exp": time.Now().Add(time.Minute).Unix(), "roles": []string{RoleInvoke}})
	if got := makeRequest(oldToken); got != http.StatusNoContent {
		t.Fatalf("old token before rotation status=%d", got)
	}
	der, _ := x509.MarshalPKIXPublicKey(&second.PublicKey)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if got := makeRequest(newToken); got != http.StatusNoContent {
		t.Fatalf("new token after rotation status=%d", got)
	}
	if got := makeRequest(oldToken); got != http.StatusUnauthorized {
		t.Fatalf("old token after rotation status=%d", got)
	}
	operatorToken := signToken(t, jwt.SigningMethodRS256, second, jwt.MapClaims{"iss": "issuer", "aud": "aud", "exp": time.Now().Add(time.Minute).Unix(), "roles": []string{RoleInvoke}})
	if got := makeRequest(operatorToken); got != http.StatusNoContent {
		t.Fatalf("RBAC baseline status=%d", got)
	}
}

func TestMTLSIdentityCannotBeSpoofedByHeaders(t *testing.T) {
	a, err := New(Config{Mode: ModeMTLS, DeploymentProfile: "production", ClientCertIdentity: true})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "cert-user", Organization: []string{"tenant-cert"}, OrganizationalUnit: []string{"app-cert", "role:aegis.operator"}}}}, VerifiedChains: [][]*x509.Certificate{{{}}}}
	req.Header.Set("X-Tenant-Id", "spoofed")
	req.Header.Set("X-Application-Id", "spoofed")
	var principal Principal
	resp := httptest.NewRecorder()
	a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ = PrincipalFromContext(r.Context())
		if r.Header.Get("X-Tenant-Id") != "" {
			t.Error("tenant header was not stripped")
		}
		w.WriteHeader(http.StatusNoContent)
	}), RoleOperator).ServeHTTP(resp, req)
	if resp.Code != http.StatusNoContent || principal.Tenant != "tenant-cert" || principal.Application != "app-cert" || !principal.HasRole(RoleOperator) {
		t.Fatalf("status=%d principal=%+v", resp.Code, principal)
	}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func writePublicKey(t *testing.T, key *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/public.pem"
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func signToken(t *testing.T, method jwt.SigningMethod, key any, claims jwt.MapClaims) string {
	t.Helper()
	token, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func withClaim(base jwt.MapClaims, name string, value any) jwt.MapClaims {
	copy := jwt.MapClaims{}
	for k, v := range base {
		copy[k] = v
	}
	copy[name] = value
	return copy
}

func withTime(base jwt.MapClaims, name string, value int64) jwt.MapClaims {
	return withClaim(base, name, value)
}

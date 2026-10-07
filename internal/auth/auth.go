package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

const (
	ModeOff = "off"
	ModeJWT = "jwt"

	RoleInvoke   = "aegis.invoke"
	RoleOperator = "aegis.operator"
)

// Config contains the authentication settings needed by the HTTP boundary.
// HMAC secrets are intentionally accepted only for development and tests.
type Config struct {
	Mode                 string
	DeploymentProfile    string
	AllowUnauthenticated bool
	PublicKeyFile        string
	HMACSecret           string
	Issuer               string
	Audience             string
	TenantClaim          string
	ApplicationClaim     string
	SubjectClaim         string
	RolesClaim           string
	ProviderClaim        string
}

// Principal is the identity verified by the gateway. It contains selected
// claim values only; raw JWT claims are never retained in request context.
type Principal struct {
	Tenant      string
	Application string
	Subject     string
	Roles       []string
	Provider    string
}

type contextKey struct{}

// PrincipalFromContext returns the verified principal, if authentication ran.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(contextKey{}).(Principal)
	return p, ok
}

// WithPrincipal stores a verified principal in a request context.
func WithPrincipal(r *http.Request, p Principal) *http.Request {
	return r.WithContext(contextWithPrincipal(r.Context(), p))
}

// HasRole reports whether a principal has an exact role match.
func (p Principal) HasRole(role string) bool {
	for _, got := range p.Roles {
		if got == role {
			return true
		}
	}
	return false
}

// Authenticator validates bearer JWTs and applies route authentication and
// authorization. It deliberately emits generic errors and never logs token
// material or claim values.
type Authenticator struct {
	cfg       Config
	key       any
	algorithm string
}

// New loads and validates the configured verification material.
func New(cfg Config) (*Authenticator, error) {
	if cfg.Mode == "" {
		cfg.Mode = ModeOff
	}
	if cfg.DeploymentProfile == "" {
		cfg.DeploymentProfile = "development"
	}
	if cfg.TenantClaim == "" {
		cfg.TenantClaim = "tenant_id"
	}
	if cfg.ApplicationClaim == "" {
		cfg.ApplicationClaim = "azp"
	}
	if cfg.SubjectClaim == "" {
		cfg.SubjectClaim = "sub"
	}
	if cfg.RolesClaim == "" {
		cfg.RolesClaim = "roles"
	}
	if cfg.ProviderClaim == "" {
		cfg.ProviderClaim = "provider"
	}
	if cfg.Mode != ModeOff && cfg.Mode != ModeJWT {
		return nil, errors.New("AUTH_MODE must be off or jwt")
	}
	if cfg.Mode == ModeOff {
		if cfg.DeploymentProfile != "development" && cfg.DeploymentProfile != "test" && !(cfg.DeploymentProfile == "shadow" && cfg.AllowUnauthenticated) {
			return nil, errors.New("AUTH_MODE=off is allowed only in development or with the shadow waiver")
		}
		return &Authenticator{cfg: cfg}, nil
	}
	if strings.TrimSpace(cfg.Issuer) == "" || strings.TrimSpace(cfg.Audience) == "" {
		return nil, errors.New("JWT_ISSUER and JWT_AUDIENCE are required when AUTH_MODE=jwt")
	}
	if cfg.PublicKeyFile != "" && cfg.HMACSecret != "" {
		return nil, errors.New("configure only one JWT verification key")
	}
	if cfg.HMACSecret != "" {
		if cfg.DeploymentProfile != "development" && cfg.DeploymentProfile != "test" {
			return nil, errors.New("JWT_HMAC_SECRET is allowed only in development or test")
		}
		return &Authenticator{cfg: cfg, key: []byte(cfg.HMACSecret), algorithm: jwt.SigningMethodHS256.Alg()}, nil
	}
	if cfg.PublicKeyFile == "" {
		return nil, errors.New("JWT_PUBLIC_KEY_FILE is required when AUTH_MODE=jwt")
	}
	key, algorithm, err := loadPublicKey(cfg.PublicKeyFile)
	if err != nil {
		return nil, errors.New("JWT_PUBLIC_KEY_FILE is invalid")
	}
	return &Authenticator{cfg: cfg, key: key, algorithm: algorithm}, nil
}

// Middleware authenticates a request when JWT mode is enabled and enforces
// all supplied roles. In development/off mode it preserves trusted-header
// compatibility and does not require a caller token.
func (a *Authenticator) Middleware(next http.Handler, roles ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.cfg.Mode == ModeOff {
			next.ServeHTTP(w, r)
			return
		}
		principal, err := a.authenticate(r)
		if err != nil {
			writeAuthError(w, http.StatusUnauthorized)
			return
		}
		if len(roles) > 0 && !hasAnyRole(principal, roles) {
			writeAuthError(w, http.StatusForbidden)
			return
		}
		stripIdentityHeaders(r)
		next.ServeHTTP(w, WithPrincipal(r, principal))
	})
}

func hasAnyRole(p Principal, roles []string) bool {
	for _, role := range roles {
		if p.HasRole(role) {
			return true
		}
	}
	return false
}

func (a *Authenticator) authenticate(r *http.Request) (Principal, error) {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return Principal{}, errors.New("missing bearer token")
	}

	options := []jwt.ParserOption{
		jwt.WithValidMethods([]string{a.algorithm}),
		jwt.WithExpirationRequired(),
	}
	if a.cfg.Issuer != "" {
		options = append(options, jwt.WithIssuer(a.cfg.Issuer))
	}
	if a.cfg.Audience != "" {
		options = append(options, jwt.WithAudience(a.cfg.Audience))
	}
	token, err := jwt.Parse(parts[1], func(token *jwt.Token) (any, error) {
		if token.Method == nil || token.Method.Alg() != a.algorithm {
			return nil, errors.New("unexpected signing algorithm")
		}
		return a.key, nil
	}, options...)
	if err != nil || token == nil || !token.Valid {
		return Principal{}, errors.New("invalid bearer token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return Principal{}, errors.New("invalid claims")
	}
	p := Principal{
		Tenant:      claimString(claims, a.cfg.TenantClaim),
		Application: claimString(claims, a.cfg.ApplicationClaim),
		Subject:     claimString(claims, a.cfg.SubjectClaim),
		Provider:    claimString(claims, a.cfg.ProviderClaim),
		Roles:       claimRoles(claims, a.cfg.RolesClaim),
	}
	return p, nil
}

func loadPublicKey(path string) (any, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, "", errors.New("missing PEM block")
	}
	var key any
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		key = cert.PublicKey
	} else if key, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if rsaKey, rsaErr := x509.ParsePKCS1PublicKey(block.Bytes); rsaErr == nil {
			key = rsaKey
		} else {
			return nil, "", err
		}
	}
	switch k := key.(type) {
	case *rsa.PublicKey:
		return k, jwt.SigningMethodRS256.Alg(), nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, "", errors.New("only P-256 ES256 keys are supported")
		}
		return k, jwt.SigningMethodES256.Alg(), nil
	default:
		return nil, "", fmt.Errorf("unsupported public key type %T", key)
	}
}

func claimString(claims jwt.MapClaims, name string) string {
	if name == "" {
		return ""
	}
	value, ok := claims[name].(string)
	if !ok {
		return ""
	}
	return value
}

func claimRoles(claims jwt.MapClaims, name string) []string {
	if name == "" {
		return nil
	}
	switch value := claims[name].(type) {
	case string:
		if value == "" {
			return nil
		}
		return []string{value}
	case []any:
		roles := make([]string, 0, len(value))
		for _, item := range value {
			if role, ok := item.(string); ok && role != "" {
				roles = append(roles, role)
			}
		}
		return roles
	default:
		return nil
	}
}

func stripIdentityHeaders(r *http.Request) {
	for _, name := range []string{"Authorization", "X-Tenant-Id", "X-Application-Id", "X-User-Id", "X-Target-Provider"} {
		r.Header.Del(name)
	}
}

func writeAuthError(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":{"type":"authentication_error","message":"request authentication failed"}}`))
}

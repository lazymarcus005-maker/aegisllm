package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/aegisllm/gateway/internal/securetransport"
	"github.com/golang-jwt/jwt/v5"
)

const (
	ModeOff  = "off"
	ModeJWT  = "jwt"
	ModeMTLS = "mtls"

	RoleInvoke     = "aegis.invoke"
	RoleToolInvoke = "aegis.tools.invoke"
	RoleOperator   = "aegis.operator"
)

// Config contains the authentication settings needed by the HTTP boundary.
// HMAC secrets are intentionally accepted only for development and tests.
type Config struct {
	Mode                  string
	DeploymentProfile     string
	AllowUnauthenticated  bool
	PublicKeyFile         string
	HMACSecret            string
	Issuer                string
	Audience              string
	TenantClaim           string
	ApplicationClaim      string
	SubjectClaim          string
	RolesClaim            string
	ProviderClaim         string
	SessionClaim          string
	RequireSessionBinding bool
	ClientCertIdentity    bool
}

// Principal is the identity verified by the gateway. It contains selected
// claim values only; raw JWT claims are never retained in request context.
type Principal struct {
	Tenant       string
	Application  string
	Subject      string
	Roles        []string
	Provider     string
	SessionID    string
	SessionBound bool
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
	keyFile   *securetransport.File[any]
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
	if cfg.SessionClaim == "" {
		cfg.SessionClaim = "sid"
	}
	if cfg.Mode != ModeOff && cfg.Mode != ModeJWT && cfg.Mode != ModeMTLS {
		return nil, errors.New("AUTH_MODE must be off, jwt, or mtls")
	}
	if cfg.Mode == ModeOff {
		if cfg.DeploymentProfile != "development" && cfg.DeploymentProfile != "test" && !(cfg.DeploymentProfile == "shadow" && cfg.AllowUnauthenticated) {
			return nil, errors.New("AUTH_MODE=off is allowed only in development or with the shadow waiver")
		}
		return &Authenticator{cfg: cfg}, nil
	}
	if cfg.Mode == ModeMTLS {
		if !cfg.ClientCertIdentity {
			return nil, errors.New("mTLS authentication requires certificate identity")
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
	keyFile, err := securetransport.PublicKeyFile(cfg.PublicKeyFile, securetransport.MinPollInterval, nil)
	if err != nil {
		return nil, errors.New("JWT_PUBLIC_KEY_FILE is invalid")
	}
	key, err := keyFile.Get()
	if err != nil {
		keyFile.Close()
		return nil, errors.New("JWT_PUBLIC_KEY_FILE is invalid")
	}
	algorithm, err := keyAlgorithm(key)
	if err != nil {
		keyFile.Close()
		return nil, errors.New("JWT_PUBLIC_KEY_FILE is invalid")
	}
	return &Authenticator{cfg: cfg, key: key, algorithm: algorithm, keyFile: keyFile}, nil
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
		var principal Principal
		var err error
		if a.cfg.Mode == ModeMTLS {
			principal, err = a.authenticateCertificate(r)
		} else {
			principal, err = a.authenticate(r)
		}
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

func (a *Authenticator) KeyStatus() securetransport.Status {
	if a == nil || a.keyFile == nil {
		return securetransport.Status{Loaded: a != nil && a.key != nil}
	}
	return a.keyFile.Status()
}

func (a *Authenticator) SetSecureMaterialMetrics(metrics securetransport.Metrics) {
	if a != nil && a.keyFile != nil {
		a.keyFile.SetMetrics(metrics)
	}
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
	key := a.key
	algorithm := a.algorithm
	if a.keyFile != nil {
		var err error
		key, err = a.keyFile.Get()
		if err != nil {
			return Principal{}, errors.New("verification key unavailable")
		}
		algorithm, err = keyAlgorithm(key)
		if err != nil {
			return Principal{}, errors.New("verification key invalid")
		}
	}
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return Principal{}, errors.New("missing bearer token")
	}

	options := []jwt.ParserOption{
		jwt.WithValidMethods([]string{algorithm}),
		jwt.WithExpirationRequired(),
	}
	if a.cfg.Issuer != "" {
		options = append(options, jwt.WithIssuer(a.cfg.Issuer))
	}
	if a.cfg.Audience != "" {
		options = append(options, jwt.WithAudience(a.cfg.Audience))
	}
	token, err := jwt.Parse(parts[1], func(token *jwt.Token) (any, error) {
		if token.Method == nil || token.Method.Alg() != algorithm {
			return nil, errors.New("unexpected signing algorithm")
		}
		return key, nil
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
		SessionID:   claimString(claims, a.cfg.SessionClaim),
		Roles:       claimRoles(claims, a.cfg.RolesClaim),
	}
	if a.cfg.RequireSessionBinding && p.SessionID == "" {
		return Principal{}, errors.New("verified session binding required")
	}
	p.SessionBound = p.SessionID != ""
	return p, nil
}

func (a *Authenticator) authenticateCertificate(r *http.Request) (Principal, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		return Principal{}, errors.New("verified client certificate required")
	}
	cert := r.TLS.PeerCertificates[0]
	application := first(cert.Subject.OrganizationalUnit)
	tenant := first(cert.Subject.Organization)
	if application == "" {
		application = tenant
	}
	roles := []string{RoleInvoke}
	for _, value := range cert.Subject.OrganizationalUnit {
		if strings.HasPrefix(value, "role:") && len(value) > len("role:") {
			roles = append(roles, value[len("role:"):])
		}
	}
	// Bind mTLS records to the verified public key rather than a client header.
	// The digest is stable for the certificate/key binding and contains no
	// certificate material.
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return Principal{Tenant: tenant, Application: application, Subject: cert.Subject.CommonName, Roles: roles,
		SessionID: "mtls-" + hex.EncodeToString(digest[:16]), SessionBound: true}, nil
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func keyAlgorithm(key any) (string, error) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return jwt.SigningMethodRS256.Alg(), nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return "", errors.New("unsupported EC curve")
		}
		return jwt.SigningMethodES256.Alg(), nil
	default:
		return "", errors.New("unsupported verification key")
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

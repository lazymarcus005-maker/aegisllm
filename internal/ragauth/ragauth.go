// Package ragauth defines the bounded, fail-closed authorization contract for
// retrieval augmented generation inputs. It intentionally carries digests and
// labels, never query or document content, across the private authorization
// boundary.
package ragauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aegisllm/gateway/internal/securetransport"
)

const (
	ModeOff     = "off"
	ModeShadow  = "shadow"
	ModeEnforce = "enforce"

	AdapterDeny = "deny"
	AdapterFake = "fake"
	AdapterHTTP = "http"

	OperationRetrieve       = "retrieve"
	OperationRetrieveResult = "retrieve_result"

	ActionAllow    = "allow"
	ActionDeny     = "deny"
	ActionRedact   = "redact"
	ActionRestrict = "restrict"
)

var (
	ErrUnavailable = errors.New("retrieval authorization unavailable")
	ErrMalformed   = errors.New("retrieval authorization malformed")
	ErrStale       = errors.New("retrieval authorization stale")
	ErrMismatch    = errors.New("retrieval authorization binding mismatch")
)

// Identity is derived from verified ingress authentication. Values parsed
// from a request are compared with this identity and never replace it.
type Identity struct {
	Tenant      string   `json:"tenant"`
	Application string   `json:"application"`
	Subject     string   `json:"subject"`
	Roles       []string `json:"roles,omitempty"`
	Groups      []string `json:"groups,omitempty"`
}

type Resource struct {
	DocumentID     string   `json:"document_id"`
	ChunkID        string   `json:"chunk_id,omitempty"`
	Collection     string   `json:"collection"`
	Index          string   `json:"index,omitempty"`
	Tenant         string   `json:"tenant"`
	Application    string   `json:"application"`
	Subject        string   `json:"subject,omitempty"`
	Roles          []string `json:"roles,omitempty"`
	Groups         []string `json:"groups,omitempty"`
	Classification []string `json:"classification,omitempty"`
	Labels         []string `json:"labels,omitempty"`
	Purpose        string   `json:"purpose"`
	ContentDigest  string   `json:"content_digest"`
}

type Retrieval struct {
	Operation   string     `json:"operation"`
	Collection  string     `json:"collection"`
	Index       string     `json:"index,omitempty"`
	Purpose     string     `json:"purpose"`
	QueryDigest string     `json:"query_digest"`
	Resources   []Resource `json:"resources,omitempty"`
}

// Request is the only wire contract sent to the authorization service. It is
// content-free and binds every decision to the identity, policy snapshot,
// retrieval query, and resource/chunk identifier.
type Request struct {
	Version       int       `json:"version"`
	RequestID     string    `json:"request_id"`
	Identity      Identity  `json:"identity"`
	PolicyID      string    `json:"policy_id"`
	PolicyVersion int       `json:"policy_version"`
	Retrieval     Retrieval `json:"retrieval"`
	Resource      *Resource `json:"resource,omitempty"`
}

type Decision struct {
	DecisionID string    `json:"decision_id"`
	Action     string    `json:"action"`
	ExpiresAt  time.Time `json:"expires_at"`
	Binding    string    `json:"binding"`
	ReasonCode string    `json:"reason_code,omitempty"`
}

type AuthorizeResponse struct {
	Version  int      `json:"version"`
	Decision Decision `json:"decision"`
}

// Authorizer is deliberately small so tests can use a deterministic fake and
// production can use the private HTTP/mTLS adapter.
type Authorizer interface {
	Authorize(context.Context, Request) (Decision, error)
}

type Limits struct {
	MaxBytes       int64
	MaxResults     int
	MaxResultBytes int64
	MaxDepth       int
	MaxNodes       int
	MaxConcurrency int
	DecisionMaxAge time.Duration
}

func (l Limits) withDefaults() Limits {
	if l.MaxBytes <= 0 {
		l.MaxBytes = 1 << 20
	}
	if l.MaxResults <= 0 {
		l.MaxResults = 64
	}
	if l.MaxResultBytes <= 0 {
		l.MaxResultBytes = 1 << 20
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = 8
	}
	if l.MaxNodes <= 0 {
		l.MaxNodes = 512
	}
	if l.MaxConcurrency <= 0 {
		l.MaxConcurrency = 4
	}
	if l.DecisionMaxAge <= 0 {
		l.DecisionMaxAge = 30 * time.Second
	}
	return l
}

type Config struct {
	Mode       string
	Adapter    string
	URL        string
	Timeout    time.Duration
	Production bool
	TLS        securetransport.ClientTLSOptions
	Limits     Limits
}

// Controls is the sanitized policy projection consumed by the gateway.
type Controls struct {
	Mode                  string
	RequirePurpose        bool
	RequireCollection     bool
	RequireClassification bool
	AllowedOperations     []string
}

type Status struct {
	Mode       string `json:"mode"`
	Adapter    string `json:"adapter"`
	Configured bool   `json:"configured"`
	Available  bool   `json:"available"`
	LastError  string `json:"last_error,omitempty"`
}

// Gateway is the request/result enforcement boundary. It rejects a whole
// retrieval set when any request or result decision is missing, denied,
// stale, substituted, or malformed. Redaction is not attempted because the
// gateway cannot soundly rewrite arbitrary provider/vector-store shapes.
type Gateway struct {
	authorizer Authorizer
	limits     Limits
	mode       string
	production bool
	controls   Controls
	mu         sync.RWMutex
	status     Status
}

type Outcome struct {
	Detected bool
	Allowed  bool
	Chunks   int
	Code     string
	Reason   string
}

func NewGateway(cfg Config, authorizer Authorizer) (*Gateway, error) {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = ModeOff
	}
	if mode != ModeOff && mode != ModeShadow && mode != ModeEnforce {
		return nil, errors.New("RAG_AUTH_MODE must be off, shadow, or enforce")
	}
	adapter := strings.ToLower(strings.TrimSpace(cfg.Adapter))
	if adapter == "" {
		adapter = AdapterDeny
	}
	if adapter != AdapterDeny && adapter != AdapterFake && adapter != AdapterHTTP {
		return nil, errors.New("RAG_AUTH_ADAPTER must be deny, fake, or http")
	}
	limits := cfg.Limits.withDefaults()
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	g := &Gateway{authorizer: authorizer, limits: limits, mode: mode, production: cfg.Production,
		status: Status{Mode: mode, Adapter: adapter, Configured: authorizer != nil, Available: authorizer != nil}}
	if _, deny := authorizer.(DenyByDefault); deny {
		g.status.Available = false
	}
	if _, deny := authorizer.(*DenyByDefault); deny {
		g.status.Available = false
	}
	if mode == ModeEnforce && authorizer == nil {
		g.status.Available = false
	}
	return g, nil
}

func (g *Gateway) Status() Status { g.mu.RLock(); defer g.mu.RUnlock(); return g.status }
func (g *Gateway) Mode() string   { return g.mode }

func (g *Gateway) SetControls(controls Controls) {
	g.mu.Lock()
	g.controls = controls
	g.mu.Unlock()
}

func (g *Gateway) fail(code string, err error) (Outcome, error) {
	g.mu.Lock()
	g.status.Available = false
	g.status.LastError = code
	g.mu.Unlock()
	return Outcome{Detected: true, Allowed: false, Code: code, Reason: "retrieval authorization failed"}, err
}

// Authorize parses supported RAG metadata and authorizes the retrieval request
// plus every returned resource. A non-RAG payload is a no-op.
func (g *Gateway) Authorize(ctx context.Context, body []byte, identity Identity, requestID, policyID string, policyVersion int) (Outcome, error) {
	if int64(len(body)) > g.limits.MaxBytes {
		return g.fail("RAG_PAYLOAD_TOO_LARGE", ErrMalformed)
	}
	batch, err := Parse(body, identity, requestID, policyID, policyVersion, g.limits)
	if err != nil {
		return g.fail(codeForParse(err), err)
	}
	if !batch.Detected {
		return Outcome{}, nil
	}
	g.mu.RLock()
	mode, controls := g.mode, g.controls
	g.mu.RUnlock()
	if controls.Mode == ModeEnforce || mode == ModeEnforce {
		mode = ModeEnforce
	} else if controls.Mode == ModeShadow && mode == ModeOff {
		mode = ModeShadow
	}
	if controls.RequirePurpose && (batch.Request.Retrieval.Purpose == "" || anyResourceMissingPurpose(batch.Resources)) {
		return g.fail("RAG_PURPOSE_REQUIRED", ErrMalformed)
	}
	if controls.RequireCollection && (batch.Request.Retrieval.Collection == "" || anyResourceMissingCollection(batch.Resources)) {
		return g.fail("RAG_COLLECTION_REQUIRED", ErrMalformed)
	}
	if controls.RequireClassification && anyResourceMissingClassification(batch.Resources) {
		return g.fail("RAG_CLASSIFICATION_REQUIRED", ErrMalformed)
	}
	if len(controls.AllowedOperations) > 0 && !contains(controls.AllowedOperations, batch.Request.Retrieval.Operation) {
		return g.fail("RAG_OPERATION_DENIED", ErrMismatch)
	}
	if mode == ModeOff {
		if g.production {
			return g.fail("RAG_AUTH_REQUIRED", ErrUnavailable)
		}
		return Outcome{Detected: true, Allowed: true, Chunks: len(batch.Resources), Code: "RAG_AUTH_DISABLED"}, nil
	}
	if g.authorizer == nil {
		return g.fail("RAG_AUTH_UNAVAILABLE", ErrUnavailable)
	}
	requestDecision, err := g.authorizer.Authorize(ctx, batch.Request)
	if err != nil {
		return g.fail("RAG_AUTH_UNAVAILABLE", err)
	}
	if err := ValidateDecision(batch.Request, requestDecision, g.limits.DecisionMaxAge); err != nil {
		return g.fail(codeForDecision(err), err)
	}
	if requestDecision.Action != ActionAllow {
		return g.fail("RAG_REQUEST_DENIED", nil)
	}

	sem := make(chan struct{}, g.limits.MaxConcurrency)
	decisions := make([]Decision, len(batch.Resources))
	errs := make(chan error, len(batch.Resources))
	var wg sync.WaitGroup
	for i := range batch.Resources {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				errs <- ctx.Err()
				return
			}
			defer func() { <-sem }()
			r := batch.Request
			r.Retrieval.Operation = OperationRetrieveResult
			resource := batch.Resources[i]
			r.Resource = &resource
			decision, callErr := g.authorizer.Authorize(ctx, r)
			if callErr == nil {
				callErr = ValidateDecision(r, decision, g.limits.DecisionMaxAge)
			}
			if callErr == nil && decision.Action != ActionAllow {
				callErr = ErrMismatch
			}
			if callErr != nil {
				errs <- callErr
				return
			}
			decisions[i] = decision
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return g.fail(codeForDecision(err), err)
		}
	}
	g.mu.Lock()
	g.status.Available = true
	g.status.LastError = ""
	g.mu.Unlock()
	// Every resource was independently bound and allowed. The normalized
	// provider payload is forwarded unchanged only after this complete check.
	return Outcome{Detected: true, Allowed: true, Chunks: len(decisions), Code: "RAG_AUTH_ALLOWED"}, nil
}

func codeForParse(err error) string {
	if errors.Is(err, ErrMalformed) {
		return "RAG_MALFORMED"
	}
	return "RAG_METADATA_REJECTED"
}
func codeForDecision(err error) string {
	switch {
	case errors.Is(err, ErrUnavailable):
		return "RAG_AUTH_UNAVAILABLE"
	case errors.Is(err, ErrStale):
		return "RAG_DECISION_STALE"
	case errors.Is(err, ErrMismatch):
		return "RAG_DECISION_MISMATCH"
	default:
		return "RAG_DECISION_MALFORMED"
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}
func anyResourceMissingPurpose(values []Resource) bool {
	for _, value := range values {
		if value.Purpose == "" {
			return true
		}
	}
	return false
}
func anyResourceMissingCollection(values []Resource) bool {
	for _, value := range values {
		if value.Collection == "" {
			return true
		}
	}
	return false
}
func anyResourceMissingClassification(values []Resource) bool {
	for _, value := range values {
		if len(value.Classification) == 0 {
			return true
		}
	}
	return false
}

type batch struct {
	Detected  bool
	Request   Request
	Resources []Resource
}

// Parse recognizes bounded, common OpenAI/Anthropic/generic retrieval shapes.
// It never returns document text; only a digest is retained in Resource.
func Parse(body []byte, identity Identity, requestID, policyID string, policyVersion int, limits Limits) (batch, error) {
	limits = limits.withDefaults()
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return batch{}, fmt.Errorf("%w: invalid JSON", ErrMalformed)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return batch{}, fmt.Errorf("%w: trailing JSON", ErrMalformed)
	}
	state := walker{limits: limits}
	var candidate map[string]any
	if err := state.find(root, 0, func(m map[string]any) bool {
		if isRetrievalObject(m) {
			candidate = m
			return true
		}
		return false
	}); err != nil {
		return batch{}, err
	}
	if candidate == nil {
		return batch{}, nil
	}
	retrieval, resources, err := parseRetrieval(candidate, identity, limits)
	if err != nil {
		return batch{}, err
	}
	if len(resources) == 0 {
		return batch{}, fmt.Errorf("%w: retrieval results are required", ErrMalformed)
	}
	if len(resources) > limits.MaxResults {
		return batch{}, fmt.Errorf("%w: retrieval result count exceeds limit", ErrMalformed)
	}
	if retrieval.Operation == "" {
		retrieval.Operation = OperationRetrieve
	}
	if retrieval.QueryDigest == "" {
		return batch{}, fmt.Errorf("%w: query digest is required", ErrMalformed)
	}
	retrieval.Resources = resources
	return batch{Detected: true, Request: Request{Version: 1, RequestID: bounded(requestID, 128), Identity: identity, PolicyID: bounded(policyID, 96), PolicyVersion: policyVersion, Retrieval: retrieval}, Resources: resources}, nil
}

type walker struct {
	limits Limits
	nodes  int
}

func (w *walker) find(v any, depth int, hit func(map[string]any) bool) error {
	if depth > w.limits.MaxDepth {
		return fmt.Errorf("%w: traversal depth exceeds limit", ErrMalformed)
	}
	w.nodes++
	if w.nodes > w.limits.MaxNodes {
		return fmt.Errorf("%w: traversal nodes exceed limit", ErrMalformed)
	}
	switch x := v.(type) {
	case map[string]any:
		if hit(x) {
			return nil
		}
		for _, child := range x {
			if err := w.find(child, depth+1, hit); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range x {
			if err := w.find(child, depth+1, hit); err != nil {
				return err
			}
		}
	}
	return nil
}

func isRetrievalObject(m map[string]any) bool {
	for _, key := range []string{"retrieval", "rag", "retrieved_context", "retrieval_context"} {
		if value, ok := m[key]; ok {
			_, isMap := value.(map[string]any)
			if isMap {
				return true
			}
		}
	}
	for _, key := range []string{"documents", "chunks", "results", "contexts", "context", "retrieval_results", "retrieved_documents", "tool_results", "tool_result"} {
		if _, ok := m[key]; ok {
			return true
		}
	}
	return false
}

func parseRetrieval(m map[string]any, identity Identity, limits Limits) (Retrieval, []Resource, error) {
	if nested, ok := m["retrieval"].(map[string]any); ok {
		m = nested
	}
	if nested, ok := m["rag"].(map[string]any); ok {
		m = nested
	}
	for _, key := range []string{"retrieved_context", "retrieval_context", "context"} {
		if nested, ok := m[key].(map[string]any); ok {
			m = nested
			break
		}
	}
	get := func(keys ...string) string {
		for _, key := range keys {
			if value, ok := m[key].(string); ok && strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		}
		return ""
	}
	r := Retrieval{Operation: get("operation", "requested_operation"), Collection: get("collection", "collection_id"), Index: get("index", "index_id"), Purpose: get("purpose", "use_purpose")}
	query := get("query", "search_query", "query_text")
	if query != "" {
		r.QueryDigest = Digest(query)
	} else if digest := get("query_digest"); digest != "" {
		r.QueryDigest = digest
	}
	var raw []any
	for _, key := range []string{"documents", "chunks", "results", "contexts", "context", "retrieval_results", "retrieved_documents", "tool_results", "tool_result", "items"} {
		if values, ok := m[key].([]any); ok {
			raw = values
			break
		}
	}
	if len(raw) == 0 {
		return Retrieval{}, nil, fmt.Errorf("%w: no supported result list", ErrMalformed)
	}
	resources := make([]Resource, 0, len(raw))
	for i, value := range raw {
		obj, ok := value.(map[string]any)
		if !ok {
			return Retrieval{}, nil, fmt.Errorf("%w: result %d is not an object", ErrMalformed, i)
		}
		resource, err := parseResource(obj, r, identity, limits)
		if err != nil {
			return Retrieval{}, nil, fmt.Errorf("%w: result %d", err, i)
		}
		resources = append(resources, resource)
	}
	return r, resources, nil
}

func parseResource(m map[string]any, retrieval Retrieval, identity Identity, limits Limits) (Resource, error) {
	metadata, _ := m["metadata"].(map[string]any)
	get := func(keys ...string) string {
		for _, key := range keys {
			if value, ok := m[key].(string); ok && strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
			if value, ok := metadata[key].(string); ok && strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		}
		return ""
	}
	doc := get("document_id", "resource_id", "document", "id")
	chunk := get("chunk_id", "segment_id", "chunk")
	collection := get("collection", "collection_id")
	if collection == "" {
		collection = retrieval.Collection
	}
	index := get("index", "index_id")
	if index == "" {
		index = retrieval.Index
	}
	purpose := get("purpose", "use_purpose")
	if purpose == "" {
		purpose = retrieval.Purpose
	}
	resource := Resource{DocumentID: doc, ChunkID: chunk, Collection: collection, Index: index, Tenant: get("tenant", "tenant_id"), Application: get("application", "application_id"), Subject: get("subject", "user", "user_id"), Purpose: purpose}
	resource.Classification = stringsListWithMetadata(m, metadata, "classification", "classifications")
	resource.Labels = stringsListWithMetadata(m, metadata, "labels", "label")
	resource.Roles = stringsListWithMetadata(m, metadata, "roles", "role")
	resource.Groups = stringsListWithMetadata(m, metadata, "groups", "group")
	content := get("content", "text", "page_content", "snippet")
	hasContent := false
	for _, key := range []string{"content", "text", "page_content", "snippet", "content_digest"} {
		if _, ok := m[key]; ok {
			hasContent = true
			break
		}
		if _, ok := metadata[key]; ok {
			hasContent = true
			break
		}
	}
	if len(content) > int(limits.MaxResultBytes) {
		return Resource{}, fmt.Errorf("%w: result content exceeds limit", ErrMalformed)
	}
	resource.ContentDigest = Digest(content)
	if supplied := get("content_digest"); supplied != "" {
		resource.ContentDigest = supplied
	}
	if resource.DocumentID == "" || resource.Collection == "" || resource.Purpose == "" || resource.Tenant == "" || resource.Application == "" || resource.ContentDigest == "" || !hasContent {
		return Resource{}, fmt.Errorf("%w: required resource metadata is missing", ErrMalformed)
	}
	if resource.Tenant != identity.Tenant || resource.Application != identity.Application {
		return Resource{}, fmt.Errorf("%w: resource identity mismatch", ErrMismatch)
	}
	if resource.Collection != retrieval.Collection || (retrieval.Index != "" && resource.Index != retrieval.Index) || resource.Purpose != retrieval.Purpose {
		return Resource{}, fmt.Errorf("%w: resource retrieval scope mismatch", ErrMismatch)
	}
	if resource.Subject != "" && resource.Subject != identity.Subject {
		return Resource{}, fmt.Errorf("%w: resource subject mismatch", ErrMismatch)
	}
	if !subset(resource.Roles, identity.Roles) || !subset(resource.Groups, identity.Groups) {
		return Resource{}, fmt.Errorf("%w: resource role or group mismatch", ErrMismatch)
	}
	return resource, nil
}

func stringsListWithMetadata(m, metadata map[string]any, keys ...string) []string {
	for _, key := range keys {
		switch v := m[key].(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				return []string{strings.TrimSpace(v)}
			}
		case []any:
			out := make([]string, 0, len(v))
			for _, item := range v {
				if value, ok := item.(string); ok && strings.TrimSpace(value) != "" {
					out = append(out, strings.TrimSpace(value))
				}
			}
			return out
		}
		if metadata != nil {
			switch v := metadata[key].(type) {
			case string:
				if strings.TrimSpace(v) != "" {
					return []string{strings.TrimSpace(v)}
				}
			case []any:
				out := make([]string, 0, len(v))
				for _, item := range v {
					if value, ok := item.(string); ok && strings.TrimSpace(value) != "" {
						out = append(out, strings.TrimSpace(value))
					}
				}
				return out
			}
		}
	}
	return nil
}
func subset(values, allowed []string) bool {
	for _, value := range values {
		found := false
		for _, candidate := range allowed {
			if value == candidate {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func bounded(v string, max int) string {
	v = strings.TrimSpace(v)
	if len(v) > max {
		return v[:max]
	}
	return v
}
func Digest(v string) string {
	sum := sha256.Sum256([]byte(v))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func Binding(req Request, decisionID, action string, expiresAt time.Time) string {
	resource := ""
	if req.Resource != nil {
		resource = req.Resource.DocumentID + "|" + req.Resource.ChunkID + "|" + req.Resource.ContentDigest
	}
	seed := fmt.Sprintf("v1|%s|%s|%s|%s|%s|%d|%s|%s|%s|%s|%s|%s|%d|%s", req.RequestID, req.Identity.Tenant, req.Identity.Application, req.Identity.Subject, req.PolicyID, req.PolicyVersion, req.Retrieval.Operation, req.Retrieval.Collection, req.Retrieval.Index, req.Retrieval.Purpose, req.Retrieval.QueryDigest, resource, expiresAt.UnixNano(), decisionID+"|"+action)
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

func ValidateDecision(req Request, decision Decision, maxAge time.Duration) error {
	if decision.DecisionID == "" || (decision.Action != ActionAllow && decision.Action != ActionDeny && decision.Action != ActionRedact && decision.Action != ActionRestrict) || decision.ExpiresAt.IsZero() || decision.Binding == "" {
		return ErrMalformed
	}
	now := time.Now()
	if decision.ExpiresAt.Before(now) || decision.ExpiresAt.After(now.Add(maxAge)) {
		return ErrStale
	}
	if !strings.EqualFold(decision.Binding, Binding(req, decision.DecisionID, decision.Action, decision.ExpiresAt)) {
		return ErrMismatch
	}
	return nil
}

// DenyByDefault is the safe in-process implementation for development/tests.
type DenyByDefault struct{}

func (DenyByDefault) Authorize(context.Context, Request) (Decision, error) {
	return Decision{}, ErrUnavailable
}

// FakeAuthorizer is deterministic and intended only for tests and the local
// Compose integration profile. It never reads or returns resource content.
type FakeAuthorizer struct {
	Allow bool
	TTL   time.Duration
	Calls *int
}

func (f *FakeAuthorizer) Authorize(_ context.Context, req Request) (Decision, error) {
	if f == nil || !f.Allow {
		return Decision{}, ErrUnavailable
	}
	if f.Calls != nil {
		(*f.Calls)++
	}
	ttl := f.TTL
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	expiry := time.Now().Add(ttl)
	d := Decision{DecisionID: "fake-allow", Action: ActionAllow, ExpiresAt: expiry}
	d.Binding = Binding(req, d.DecisionID, d.Action, d.ExpiresAt)
	return d, nil
}

type HTTPAuthorizer struct {
	client      *http.Client
	endpoint    string
	maxResponse int64
	certs       []*securetransport.File[tls.Certificate]
}

// NewHTTPAuthorizer uses the same TLS/mTLS transport and hostname verification
// contract as the other private services. Production callers must use HTTPS.
func NewHTTPAuthorizer(cfg Config) (*HTTPAuthorizer, error) {
	u, err := url.Parse(strings.TrimSpace(cfg.URL))
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("RAG_AUTH_URL is invalid")
	}
	if cfg.Production && !strings.EqualFold(u.Scheme, "https") {
		return nil, errors.New("RAG_AUTH_URL must use verified TLS")
	}
	if cfg.Production && blockedHost(u.Hostname()) {
		return nil, errors.New("RAG_AUTH_URL host is not allowed")
	}
	if !cfg.Production && u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("RAG_AUTH_URL must use HTTP or HTTPS")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	tlsConfig, certs, err := cfg.TLS.TLSConfig()
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: cfg.Timeout, KeepAlive: 30 * time.Second}).DialContext, TLSHandshakeTimeout: cfg.Timeout, ResponseHeaderTimeout: cfg.Timeout, IdleConnTimeout: 90 * time.Second, MaxIdleConns: 32, MaxIdleConnsPerHost: 8, TLSClientConfig: tlsConfig}
	return &HTTPAuthorizer{client: &http.Client{Timeout: cfg.Timeout, Transport: transport}, endpoint: strings.TrimRight(cfg.URL, "/") + "/v1/authorize", maxResponse: cfg.Limits.withDefaults().MaxResultBytes, certs: certs}, nil
}

func blockedHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
	}
	return false
}
func (h *HTTPAuthorizer) Close() {
	if h == nil {
		return
	}
	for _, cert := range h.certs {
		cert.Close()
	}
	if t, ok := h.client.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
}
func (h *HTTPAuthorizer) MaterialStatuses() map[string]func() securetransport.Status {
	result := map[string]func() securetransport.Status{}
	for i, cert := range h.certs {
		result[fmt.Sprintf("rag_auth_client_certificate_%d", i+1)] = cert.Status
	}
	return result
}
func (h *HTTPAuthorizer) Authorize(ctx context.Context, request Request) (Decision, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return Decision{}, ErrMalformed
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint, bytes.NewReader(body))
	if err != nil {
		return Decision{}, ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return Decision{}, ErrUnavailable
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, h.maxResponse+1))
	if err != nil || int64(len(data)) > h.maxResponse {
		return Decision{}, ErrMalformed
	}
	if resp.StatusCode != http.StatusOK {
		return Decision{}, ErrUnavailable
	}
	var out AuthorizeResponse
	if err := json.Unmarshal(data, &out); err != nil || out.Version != 1 {
		return Decision{}, ErrMalformed
	}
	return out.Decision, nil
}

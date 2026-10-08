package ragauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const retrievalBody = `{"model":"m","retrieval":{"query":"secret query","collection":"knowledge","index":"tenant-index","purpose":"answer","documents":[{"id":"doc-1","chunk_id":"chunk-1","tenant_id":"tenant-a","application_id":"app-a","subject":"user-a","roles":["reader"],"groups":["support"],"classification":["internal"],"labels":["case"],"content":"document text"}]}}`

func identity() Identity {
	return Identity{Tenant: "tenant-a", Application: "app-a", Subject: "user-a", Roles: []string{"reader"}, Groups: []string{"support"}}
}
func limits() Limits {
	return Limits{MaxBytes: 32 << 10, MaxResults: 4, MaxResultBytes: 1024, MaxDepth: 8, MaxNodes: 100, MaxConcurrency: 2, DecisionMaxAge: time.Minute}
}

func TestGatewayAuthorizesRequestAndEveryResult(t *testing.T) {
	calls := 0
	g, err := NewGateway(Config{Mode: ModeEnforce, Adapter: AdapterFake, Limits: limits()}, &FakeAuthorizer{Allow: true, Calls: &calls})
	if err != nil {
		t.Fatal(err)
	}
	out, err := g.Authorize(context.Background(), []byte(retrievalBody), identity(), "req-1", "policy", 9)
	if err != nil || !out.Allowed || out.Chunks != 1 {
		t.Fatalf("outcome=%+v err=%v", out, err)
	}
	if calls != 2 {
		t.Fatalf("authorization calls=%d, want request plus one result", calls)
	}
}

func TestGatewayRejectsTenantConfusionAndMixedScope(t *testing.T) {
	for name, body := range map[string]string{
		"tenant":     strings.Replace(retrievalBody, `"tenant_id":"tenant-a"`, `"tenant_id":"tenant-b"`, 1),
		"purpose":    strings.Replace(retrievalBody, `"content":"document text"`, `"purpose":"training","content":"document text"`, 1),
		"collection": strings.Replace(retrievalBody, `"content":"document text"`, `"collection":"other","content":"document text"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(body), identity(), "req", "p", 1, limits())
			if err == nil || !errors.Is(err, ErrMismatch) {
				t.Fatalf("Parse error=%v, want mismatch", err)
			}
		})
	}
}

func TestGatewayRejectsForgedSubjectRoleAndInjectedResult(t *testing.T) {
	cases := []string{
		strings.Replace(retrievalBody, `"subject":"user-a"`, `"subject":"user-b"`, 1),
		strings.Replace(retrievalBody, `"roles":["reader"]`, `"roles":["admin"]`, 1),
		strings.Replace(retrievalBody, `"id":"doc-1"`, `"id":""`, 1),
	}
	for _, body := range cases {
		_, err := Parse([]byte(body), identity(), "req", "p", 1, limits())
		if err == nil {
			t.Fatal("forged or injected result accepted")
		}
	}
}

type decisionAuthorizer struct {
	mu           sync.Mutex
	denyResource string
	stale        bool
	mismatch     bool
}

func (a *decisionAuthorizer) Authorize(_ context.Context, req Request) (Decision, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	action := ActionAllow
	if req.Resource != nil && req.Resource.DocumentID == a.denyResource {
		action = ActionDeny
	}
	expires := time.Now().Add(10 * time.Second)
	if a.stale {
		expires = time.Now().Add(-time.Second)
	}
	d := Decision{DecisionID: "decision-1", Action: action, ExpiresAt: expires}
	d.Binding = Binding(req, d.DecisionID, d.Action, d.ExpiresAt)
	if a.mismatch {
		d.Binding = "substituted"
	}
	return d, nil
}

func TestGatewayRejectsStaleSubstitutedAndUnauthorizedResult(t *testing.T) {
	for name, authz := range map[string]*decisionAuthorizer{
		"stale": {stale: true}, "substituted": {mismatch: true}, "result-denied": {denyResource: "doc-1"},
	} {
		t.Run(name, func(t *testing.T) {
			g, err := NewGateway(Config{Mode: ModeEnforce, Adapter: AdapterFake, Limits: limits()}, authz)
			if err != nil {
				t.Fatal(err)
			}
			out, err := g.Authorize(context.Background(), []byte(retrievalBody), identity(), "req", "policy", 1)
			if err == nil || out.Allowed {
				t.Fatalf("outcome=%+v err=%v, want fail closed", out, err)
			}
		})
	}
}

func TestGatewayRejectsOversizedMalformedAndUnavailable(t *testing.T) {
	g, _ := NewGateway(Config{Mode: ModeEnforce, Adapter: AdapterDeny, Limits: limits()}, DenyByDefault{})
	for name, body := range map[string][]byte{
		"oversized":   []byte(strings.Repeat("x", int(limits().MaxBytes)+1)),
		"malformed":   []byte(`{"retrieval":{"documents":[1]}}`),
		"unsupported": []byte(`{"retrieval":{"query":"q","collection":"c","purpose":"p","documents":[]}}`),
	} {
		t.Run(name, func(t *testing.T) {
			out, err := g.Authorize(context.Background(), body, identity(), "req", "p", 1)
			if err == nil || out.Allowed {
				t.Fatalf("outcome=%+v err=%v", out, err)
			}
		})
	}
}

func TestGatewayPolicyControlsRequireClassification(t *testing.T) {
	body := strings.Replace(retrievalBody, `,"classification":["internal"]`, "", 1)
	g, err := NewGateway(Config{Mode: ModeEnforce, Adapter: AdapterFake, Limits: limits()}, &FakeAuthorizer{Allow: true})
	if err != nil {
		t.Fatal(err)
	}
	g.SetControls(Controls{Mode: ModeEnforce, RequirePurpose: true, RequireCollection: true, RequireClassification: true})
	out, err := g.Authorize(context.Background(), []byte(body), identity(), "req", "p", 1)
	if err == nil || out.Code != "RAG_CLASSIFICATION_REQUIRED" {
		t.Fatalf("outcome=%+v err=%v", out, err)
	}
}

func TestHTTPAuthorizerIsContentFreeAndBindsTLSContract(t *testing.T) {
	var wire Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
			t.Fatal(err)
		}
		expires := time.Now().Add(10 * time.Second)
		d := Decision{DecisionID: "http-1", Action: ActionAllow, ExpiresAt: expires}
		d.Binding = Binding(wire, d.DecisionID, d.Action, d.ExpiresAt)
		_ = json.NewEncoder(w).Encode(AuthorizeResponse{Version: 1, Decision: d})
	}))
	defer server.Close()
	a, err := NewHTTPAuthorizer(Config{URL: server.URL, Timeout: time.Second, Limits: limits()})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	d, err := a.Authorize(context.Background(), Request{Version: 1, RequestID: "r", Identity: identity(), PolicyID: "p", PolicyVersion: 1, Retrieval: Retrieval{Operation: OperationRetrieve, Collection: "c", Purpose: "answer", QueryDigest: Digest("query")}})
	if err != nil || d.Action != ActionAllow {
		t.Fatalf("decision=%+v err=%v", d, err)
	}
	data, _ := json.Marshal(wire)
	if strings.Contains(string(data), "secret query") || strings.Contains(string(data), "document text") {
		t.Fatal("authorization wire contains content")
	}
	if _, err := NewHTTPAuthorizer(Config{URL: "http://auth.example.invalid", Production: true, Timeout: time.Second}); err == nil {
		t.Fatal("production accepted plaintext authorization URL")
	}
	if _, err := NewHTTPAuthorizer(Config{URL: "https://auth.example.invalid/path?x=1", Production: true, Timeout: time.Second}); err == nil {
		t.Fatal("authorization URL with query accepted")
	}
}

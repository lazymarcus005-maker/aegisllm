package decision

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aegisllm/gateway/internal/securetransport"
	"github.com/aegisllm/gateway/internal/trace"
)

// NoopProvider returns empty evidence without calling anything; used to
// disable semantics or in tests.
type NoopProvider struct{}

func (NoopProvider) Name() string { return "noop" }

func (NoopProvider) Evaluate(context.Context, DecisionRequest, []string) (DecisionEvidence, error) {
	return DecisionEvidence{Provider: "noop"}, nil
}

// FakeProvider returns canned decisions; used in tests and local demos.
type FakeProvider struct {
	// Answers maps question id → decision. Missing ids default to
	// {Value: false, Confidence: 0.9}.
	Answers map[string]Decision
}

func (f *FakeProvider) Name() string { return "fake" }

func (f *FakeProvider) Evaluate(_ context.Context, _ DecisionRequest, questionIDs []string) (DecisionEvidence, error) {
	decisions := map[string]Decision{}
	for _, id := range questionIDs {
		if d, ok := f.Answers[id]; ok {
			decisions[id] = d
			continue
		}
		decisions[id] = Decision{Value: false, Confidence: 0.9}
	}
	return DecisionEvidence{
		Provider:      "fake",
		Checkpoint:    "fake-checkpoint",
		SchemaVersion: "security-v1",
		Decisions:     decisions,
	}, nil
}

// layaRequest is the wire shape sent to laya-serve (spec §4 conceptual
// contract). The Laya adapter is the only place this shape exists.
type layaRequest struct {
	State          layaState `json:"state"`
	QuestionSchema string    `json:"question_schema"`
	Questions      []string  `json:"questions"`
}

type layaState struct {
	Direction    string   `json:"direction"`
	Role         string   `json:"role,omitempty"`
	Content      string   `json:"content"`
	Application  string   `json:"application,omitempty"`
	ModelID      string   `json:"model_id,omitempty"`
	ModelVersion string   `json:"model_version,omitempty"`
	ToolContext  []string `json:"tool_context,omitempty"`
}

// layaResponse mirrors laya-serve's normalized result (spec §4).
type layaResponse struct {
	Provider      string `json:"provider"`
	Checkpoint    string `json:"checkpoint"`
	SchemaVersion string `json:"schema_version"`
	Route         string `json:"route"`
	ModelID       string `json:"model_id,omitempty"`
	ModelVersion  string `json:"model_version,omitempty"`
	ModelDigest   string `json:"model_digest,omitempty"`
	Decisions     map[string]struct {
		Value            bool    `json:"value"`
		AnswerConfidence float64 `json:"answer_confidence"`
	} `json:"decisions"`
}

// LayaProvider calls a local laya-serve HTTP service. Preferred production
// mode (FR-007). Never expose laya-serve publicly (architecture §7.2).
type LayaProvider struct {
	baseURL string
	path    string
	schema  string
	client  *http.Client
	certs   []*securetransport.File[tls.Certificate]
}

func NewLayaProvider(baseURL, path string, timeout time.Duration) *LayaProvider {
	p, err := NewSecureLayaProvider(baseURL, path, timeout, securetransport.ClientTLSOptions{})
	if err != nil {
		return &LayaProvider{baseURL: baseURL, path: path, schema: "security-v1", client: &http.Client{Timeout: timeout}}
	}
	return p
}

// NewSecureLayaProvider builds the Laya client with the shared verified TLS
// transport. It keeps Laya's CA, client certificate, and server name separate
// from upstream settings.
func NewSecureLayaProvider(baseURL, path string, timeout time.Duration, tlsOptions securetransport.ClientTLSOptions) (*LayaProvider, error) {
	if path == "" {
		path = "/v1/evaluate"
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	tlsConfig, certs, err := tlsOptions.TLSConfig()
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout,
		IdleConnTimeout: 90 * time.Second, MaxIdleConns: 100, MaxIdleConnsPerHost: 100,
		TLSClientConfig: tlsConfig,
	}
	return &LayaProvider{
		baseURL: baseURL,
		path:    path,
		schema:  "security-v1",
		client:  &http.Client{Timeout: timeout, Transport: transport}, certs: certs,
	}, nil
}

func (l *LayaProvider) Close() {
	for _, file := range l.certs {
		file.Close()
	}
	if transport, ok := l.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func (l *LayaProvider) MaterialStatuses() map[string]func() securetransport.Status {
	result := map[string]func() securetransport.Status{}
	for i, file := range l.certs {
		result[fmt.Sprintf("laya_client_certificate_%d", i+1)] = file.Status
	}
	return result
}

func (l *LayaProvider) Name() string { return "laya" }

// SetQuestionSchema binds the wire request to the schema loaded by the
// gateway. It is deliberately a public setter so evaltool and the gateway
// share the same provider adapter without duplicating HTTP code.
func (l *LayaProvider) SetQuestionSchema(schema string) {
	if schema != "" {
		l.schema = schema
	}
}

// Health reports whether laya-serve is reachable (FR-020).
func (l *LayaProvider) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.baseURL+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := l.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("laya health: status %d", resp.StatusCode)
	}
	return nil
}

func (l *LayaProvider) Evaluate(ctx context.Context, dreq DecisionRequest, questionIDs []string) (DecisionEvidence, error) {
	if len(questionIDs) == 0 {
		return DecisionEvidence{Provider: "laya"}, nil
	}
	body, err := json.Marshal(layaRequest{
		State: layaState{
			Direction:   dreq.Direction,
			Role:        dreq.Role,
			Content:     dreq.Content,
			Application: dreq.Application,
			ModelID:     dreq.ModelID, ModelVersion: dreq.ModelVersion,
		},
		QuestionSchema: l.schema,
		Questions:      questionIDs,
	})
	if err != nil {
		return DecisionEvidence{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.baseURL+l.path, bytes.NewReader(body))
	if err != nil {
		return DecisionEvidence{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if tc, ok := trace.From(ctx); ok {
		trace.Inject(req, trace.Child(tc))
	}
	resp, err := l.client.Do(req)
	if err != nil {
		return DecisionEvidence{}, fmt.Errorf("laya call failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return DecisionEvidence{}, fmt.Errorf("laya call: status %d", resp.StatusCode)
	}
	var lr layaResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return DecisionEvidence{}, fmt.Errorf("laya response decode: %w", err)
	}
	if strings.TrimSpace(lr.Provider) == "" || strings.EqualFold(lr.Provider, "noop") || !strings.EqualFold(lr.Provider, "laya") {
		return DecisionEvidence{}, fmt.Errorf("laya response: invalid provider identity")
	}
	ev := DecisionEvidence{
		Provider:      lr.Provider,
		Checkpoint:    lr.Checkpoint,
		SchemaVersion: lr.SchemaVersion,
		Route:         lr.Route,
		ModelID:       lr.ModelID, ModelVersion: lr.ModelVersion, ModelDigest: lr.ModelDigest,
		Decisions: map[string]Decision{},
	}
	for id, d := range lr.Decisions {
		ev.Decisions[id] = Decision{Value: d.Value, Confidence: d.AnswerConfidence}
	}
	return ev, nil
}

package decision

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
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
	Direction   string   `json:"direction"`
	Role        string   `json:"role,omitempty"`
	Content     string   `json:"content"`
	Application string   `json:"application,omitempty"`
	ToolContext []string `json:"tool_context,omitempty"`
}

// layaResponse mirrors laya-serve's normalized result (spec §4).
type layaResponse struct {
	Provider      string `json:"provider"`
	Checkpoint    string `json:"checkpoint"`
	SchemaVersion string `json:"schema_version"`
	Route         string `json:"route"`
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
	client  *http.Client
}

func NewLayaProvider(baseURL, path string, timeout time.Duration) *LayaProvider {
	if path == "" {
		path = "/v1/evaluate"
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &LayaProvider{
		baseURL: baseURL,
		path:    path,
		client:  &http.Client{Timeout: timeout},
	}
}

func (l *LayaProvider) Name() string { return "laya" }

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
	if resp.StatusCode >= 500 {
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
		},
		QuestionSchema: "security-v1",
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
	ev := DecisionEvidence{
		Provider:      "laya",
		Checkpoint:    lr.Checkpoint,
		SchemaVersion: lr.SchemaVersion,
		Route:         lr.Route,
		Decisions:     map[string]Decision{},
	}
	for id, d := range lr.Decisions {
		ev.Decisions[id] = Decision{Value: d.Value, Confidence: d.AnswerConfidence}
	}
	return ev, nil
}

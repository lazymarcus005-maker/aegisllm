package gateway

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aegisllm/gateway/internal/audit"
	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/decision"
	"github.com/aegisllm/gateway/internal/detectors"
	"github.com/aegisllm/gateway/internal/observability"
	"github.com/aegisllm/gateway/internal/pii"
	"github.com/aegisllm/gateway/internal/policy"
	"github.com/aegisllm/gateway/internal/tokenization"
)

// SecurityPipeline wires deterministic inspection, policy evaluation,
// semantic evidence, and content transformation for every gateway boundary.
// Boundary-specific behavior lives in inspect.go, semantic.go, and
// transform_apply.go; this file owns the pipeline's dependencies and options.
type SecurityPipeline struct {
	registry        *detectors.Registry
	engine          *policy.Engine
	spans           pii.SpanProvider
	audit           audit.Sink
	mode            string
	vault           tokenization.Vault
	crypto          tokenization.Cipher
	vaultTTL        time.Duration
	provider        decision.DecisionProvider
	questions       *decision.QuestionSchema
	planner         *decision.Planner
	thresholds      *policy.SemanticThresholds
	semanticEnforce bool
	recorder        observability.Recorder
	spanRequired    bool
	runtime         atomic.Pointer[RuntimeSnapshot]
	candidate       atomic.Pointer[RuntimeSnapshot]
	canaryEligible  func(*core.InspectionEnvelope) bool
	canaryObserve   func(bool)
}

// RuntimeSnapshot groups every policy-bound artifact used by one request.
// The pointer is swapped once, so readers can never observe a mixed policy,
// question schema, and threshold configuration.
type RuntimeSnapshot struct {
	Engine     *policy.Engine
	Questions  *decision.QuestionSchema
	Planner    *decision.Planner
	Thresholds *policy.SemanticThresholds
}

// NewSecurityPipeline constructs a pipeline in OFF mode with no-op metrics.
func NewSecurityPipeline(registry *detectors.Registry, engine *policy.Engine, sink audit.Sink) *SecurityPipeline {
	p := &SecurityPipeline{registry: registry, engine: engine, audit: sink, mode: ModeOff, recorder: observability.Noop{}}
	p.runtime.Store(&RuntimeSnapshot{Engine: engine})
	return p
}

func (p *SecurityPipeline) current() *RuntimeSnapshot {
	if snapshot := p.runtime.Load(); snapshot != nil {
		return snapshot
	}
	return &RuntimeSnapshot{Engine: p.engine, Questions: p.questions, Planner: p.planner, Thresholds: p.thresholds}
}

// ActivateRuntimeSnapshot atomically changes the complete policy artifact set.
func (p *SecurityPipeline) ActivateRuntimeSnapshot(engine *policy.Engine, questions *decision.QuestionSchema, thresholds *policy.SemanticThresholds) error {
	if engine == nil || engine.Policy() == nil {
		return fmt.Errorf("runtime policy snapshot is empty")
	}
	p.runtime.Store(&RuntimeSnapshot{Engine: engine, Questions: questions, Planner: decision.NewPlanner(questions), Thresholds: thresholds})
	return nil
}

func (p *SecurityPipeline) SetCandidateRuntimeSnapshot(engine *policy.Engine, questions *decision.QuestionSchema, thresholds *policy.SemanticThresholds) error {
	if engine == nil || engine.Policy() == nil {
		return fmt.Errorf("candidate policy snapshot is empty")
	}
	p.candidate.Store(&RuntimeSnapshot{Engine: engine, Questions: questions, Planner: decision.NewPlanner(questions), Thresholds: thresholds})
	return nil
}

func (p *SecurityPipeline) ClearCandidateRuntimeSnapshot() { p.candidate.Store(nil) }
func (p *SecurityPipeline) SetCanaryAssignment(fn func(*core.InspectionEnvelope) bool) {
	p.canaryEligible = fn
}
func (p *SecurityPipeline) SetCanaryObserver(fn func(bool)) { p.canaryObserve = fn }

// SetSecurityMode sets the deployment mode. The HTTP server is the owner of
// this value and propagates it when it attaches the pipeline.
func (p *SecurityPipeline) SetSecurityMode(mode string) { p.mode = mode }

// SetRecorder attaches content-free pipeline metrics.
func (p *SecurityPipeline) SetRecorder(r observability.Recorder) { p.recorder = r }

// SetSpanProvider attaches span-oriented PII detection.
func (p *SecurityPipeline) SetSpanProvider(sp pii.SpanProvider) { p.spans = sp }

// SetSpanPolicy controls provider outage behavior. Strict protected routes
// fail closed; balanced/development routes retain deterministic findings and
// expose the fallback through sanitized audit and metrics.
func (p *SecurityPipeline) SetSpanPolicy(required bool) { p.spanRequired = required }

func (p *SecurityPipeline) evasionConfig() detectors.EvasionConfig {
	if p == nil || p.engine == nil || p.engine.Policy() == nil {
		return detectors.DefaultEvasionConfig()
	}
	e := p.current().Engine.Policy().Evasion
	// Policies written before P1.4 receive the safe defaults. A non-empty
	// evasion block is authoritative, including enabled: false.
	if !e.Enabled && len(e.Transforms) == 0 && e.MaxDecodeDepth == 0 && e.MaxDecodeWorkBytes == 0 && e.MaxJSONDepth == 0 && e.MaxJSONNodes == 0 {
		return detectors.DefaultEvasionConfig()
	}
	cfg := detectors.EvasionConfig{Enabled: e.Enabled, Transforms: e.Transforms,
		MaxDecodeDepth: e.MaxDecodeDepth, MaxDecodeWorkBytes: e.MaxDecodeWorkBytes,
		MaxExpansionRatio: e.MaxDecodedExpansion, MaxJSONDepth: e.MaxJSONDepth,
		MaxJSONNodes: e.MaxJSONNodes, MaxJSONStringBytes: e.MaxJSONStringBytes,
		BudgetAction: e.BudgetAction.Action, Allowlist: map[string]bool{}}
	for _, exception := range e.Allowlists {
		cfg.Allowlist[exception.ID] = true
		cfg.Allowlist[exception.EvasionType] = true
	}
	for _, transform := range e.Transforms {
		if strings.EqualFold(transform, "hex") {
			cfg.EnableHex = true
		}
	}
	return cfg
}

func (p *SecurityPipeline) Close() {
	if provider, ok := p.spans.(interface{ Close() }); ok {
		provider.Close()
	}
}

// SetTokenStore attaches the encrypted vault used by TOKENIZE.
func (p *SecurityPipeline) SetTokenStore(vault tokenization.Vault, crypto tokenization.Cipher, ttl time.Duration) {
	p.vault, p.crypto, p.vaultTTL = vault, crypto, ttl
}

// SetDecisionProvider attaches semantic classification and its question schema.
func (p *SecurityPipeline) SetDecisionProvider(dp decision.DecisionProvider, qs *decision.QuestionSchema) {
	p.provider = dp
	p.questions = qs
	p.planner = decision.NewPlanner(qs)
	current := p.current()
	p.runtime.Store(&RuntimeSnapshot{Engine: current.Engine, Questions: qs, Planner: p.planner, Thresholds: current.Thresholds})
}

// EnableSemanticEnforce opts into calibrated semantic enforcement.
func (p *SecurityPipeline) EnableSemanticEnforce() { p.semanticEnforce = true }

// SetSemanticThresholds attaches the calibrated semantic threshold policy.
func (p *SecurityPipeline) SetSemanticThresholds(t *policy.SemanticThresholds) {
	p.thresholds = t
	current := p.current()
	p.runtime.Store(&RuntimeSnapshot{Engine: current.Engine, Questions: current.Questions, Planner: current.Planner, Thresholds: t})
}

// RestrictedTools returns the policy's deterministic tool deny set to the MCP
// transport. The transport applies this before schema validation or network
// execution, so guessed tool names cannot bypass RESTRICT_TOOLS.
func (p *SecurityPipeline) RestrictedTools() []string {
	if p == nil || p.current().Engine == nil {
		return nil
	}
	return p.current().Engine.RestrictedTools()
}

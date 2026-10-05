package decision

import (
	"github.com/aegisllm/gateway/internal/core"
)

// Planner decides which semantic questions to ask, if any, per request
// (T-016). It implements the fast path: deterministic evidence that already
// settles the outcome means Laya is not called (NFR-PERF-004), and detected
// secrets never reach the semantic engine (SEC-002).
type Planner struct {
	schema *QuestionSchema
}

func NewPlanner(schema *QuestionSchema) *Planner {
	return &Planner{schema: schema}
}

// Plan is the inspection decision for one request.
type Plan struct {
	Ask         bool
	QuestionIDs []string
	Reason      string
	// MaxRisk is the highest risk class among the questions that would be
	// asked; it drives the Laya-unavailable fallback route risk.
	MaxRisk string
}

var riskRank = map[string]int{"high": 3, "medium": 2, "low": 1}

// Plan evaluates the planner rules deterministically.
func (p *Planner) Plan(direction core.Direction, application string, target core.Target, findings []core.SecurityFinding) Plan {
	// 1. Detected secrets are conclusive: policy blocks on them and the
	// content must not be forwarded to Laya (SEC-002).
	for _, f := range findings {
		if f.Category == core.CategorySecret {
			return Plan{Ask: false, Reason: "deterministic secret finding; semantic inspection skipped"}
		}
	}

	// 2. Questions are configured per direction; nothing to ask otherwise.
	directionKey := lowerDirection(direction)
	ids := p.schema.ForDirection(directionKey)
	if len(ids) == 0 {
		return Plan{Ask: false, Reason: "no questions configured for direction " + directionKey}
	}

	return Plan{Ask: true, QuestionIDs: ids, Reason: "semantic inspection required", MaxRisk: maxRiskOf(ids, p.schema)}
}

func lowerDirection(d core.Direction) string {
	switch d {
	case core.DirectionToolCall:
		return directionToolCall
	case core.DirectionToolResult:
		return directionToolResult
	case core.DirectionResponse:
		return directionResponse
	default:
		return directionRequest
	}
}

// MaxRiskOf returns the highest risk class among question ids.
func MaxRiskOf(ids []string, schema *QuestionSchema) string {
	return maxRiskOf(ids, schema)
}

func maxRiskOf(ids []string, schema *QuestionSchema) string {
	best := ""
	for _, id := range ids {
		r := schema.RiskOf(id)
		if riskRank[r] > riskRank[best] {
			best = r
		}
	}
	return best
}

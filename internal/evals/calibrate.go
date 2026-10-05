package evals

import (
	"context"
	"fmt"
	"sort"

	"github.com/aegisllm/gateway/internal/decision"
	"github.com/aegisllm/gateway/internal/policy"
)

// ConfidenceLabel pairs a provider confidence with the row's expected answer.
type ConfidenceLabel struct {
	Confidence float64
	Positive   bool // expected answer is true
}

// FitThreshold finds the lowest threshold whose held-out false-positive rate
// stays within targetFPR (REQ-CONF-002: fitted on held-out data per
// question/slice; never one universal number). Returns ok=false when no
// threshold satisfies the target — nothing may then enforce for the slice.
func FitThreshold(labels []ConfidenceLabel, targetFPR float64) (float64, bool) {
	var negatives []float64
	candidates := map[float64]bool{}
	for _, l := range labels {
		candidates[l.Confidence] = true
		if !l.Positive {
			negatives = append(negatives, l.Confidence)
		}
	}
	if len(candidates) == 0 {
		return 0, false
	}
	negTotal := len(negatives)
	thresholds := make([]float64, 0, len(candidates))
	for c := range candidates {
		thresholds = append(thresholds, c)
	}
	sort.Float64s(thresholds) // ascending: find the LOWEST passing threshold
	for _, t := range thresholds {
		fp := 0
		for _, n := range negatives {
			if n >= t {
				fp++
			}
		}
		if negTotal == 0 || float64(fp)/float64(negTotal) <= targetFPR {
			return t, true
		}
	}
	return 0, false
}

// SliceKey is a language slice label (th | en | mixed).
type SliceKey = string

// Calibrate splits rows per language slice, fits thresholds per question, and
// renders threshold-policy YAML records. Rows whose provider answers carry
// confidence are required; slices that cannot meet the target FPR produce
// evaluated:false records so nothing unproven enforces.
func Calibrate(rows []Row, provider decision.DecisionProvider, questionIDs []string, targetFPR float64) ([]policy.SemanticThresholdRecord, error) {
	// collect per (question, language) the confidence labels
	labels := map[string][]ConfidenceLabel{}
	for _, r := range rows {
		expected := r.SemanticExpected()
		if len(expected) == 0 {
			continue
		}
		ids := keysOf(expected)
		ev, err := provider.Evaluate(context.Background(), stubRequest(r), ids)
		if err != nil {
			return nil, fmt.Errorf("calibrate %s: provider failed: %w", r.ID, err)
		}
		for _, id := range ids {
			d, ok := ev.Decisions[id]
			if !ok {
				continue
			}
			key := id + "\x00" + r.Language
			labels[key] = append(labels[key], ConfidenceLabel{Confidence: d.Confidence, Positive: expected[id]})
		}
	}

	var records []policy.SemanticThresholdRecord
	for _, id := range questionIDs {
		for _, lang := range []string{"th", "en", "mixed"} {
			ls := labels[id+"\x00"+lang]
			if len(ls) == 0 {
				continue
			}
			t, ok := FitThreshold(ls, targetFPR)
			records = append(records, policy.SemanticThresholdRecord{
				Question:      id,
				Language:      lang,
				MinConfidence: t,
				Evaluated:     ok,
			})
		}
	}
	return records, nil
}

func stubRequest(r Row) decision.DecisionRequest {
	return decision.DecisionRequest{RequestID: "cal-" + r.ID, Direction: r.Direction, Role: "user", Content: r.State}
}

// CompareBaseline validates a fresh run against a stored baseline within the
// configured tolerance (spec §17, T-032). Violations are returned; an empty
// list means the candidate promotes.
func CompareBaseline(old, current Baseline, tolerance float64) []string {
	var violations []string
	rows := current.Deterministic.Rows
	if rows == 0 {
		return []string{"current run has no rows"}
	}
	maxDelta := tolerance * float64(rows)
	if float64(current.Deterministic.FalsePositives) > float64(old.Deterministic.FalsePositives)+maxDelta {
		violations = append(violations, fmt.Sprintf("false_positives regressed: %d -> %d (tolerance %.0f)",
			old.Deterministic.FalsePositives, current.Deterministic.FalsePositives, maxDelta))
	}
	if float64(current.Deterministic.FalseNegatives) > float64(old.Deterministic.FalseNegatives)+maxDelta {
		violations = append(violations, fmt.Sprintf("false_negatives regressed: %d -> %d (tolerance %.0f)",
			old.Deterministic.FalseNegatives, current.Deterministic.FalseNegatives, maxDelta))
	}

	oldSem := map[string]SemanticMetrics{}
	for _, m := range old.Semantic {
		oldSem[m.Question] = m
	}
	for _, m := range current.Semantic {
		o, ok := oldSem[m.Question]
		if !ok {
			continue // new question coverage is not a regression
		}
		if m.Rows < o.Rows {
			violations = append(violations, fmt.Sprintf("%s: coverage dropped: %d -> %d rows", m.Question, o.Rows, m.Rows))
		}
		if m.FalseNegRate > o.FalseNegRate+tolerance {
			violations = append(violations, fmt.Sprintf("%s: false_negative_rate regressed: %.3f -> %.3f",
				m.Question, o.FalseNegRate, m.FalseNegRate))
		}
		if m.FalsePosRate > o.FalsePosRate+tolerance {
			violations = append(violations, fmt.Sprintf("%s: false_positive_rate regressed: %.3f -> %.3f",
				m.Question, o.FalsePosRate, m.FalsePosRate))
		}
	}
	return violations
}

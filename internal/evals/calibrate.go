package evals

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

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
	if targetFPR < 0 || targetFPR > 1 || math.IsNaN(targetFPR) || math.IsInf(targetFPR, 0) {
		return 0, false
	}
	var negatives []float64
	candidates := map[float64]bool{}
	for _, l := range labels {
		if l.Confidence < 0 || l.Confidence > 1 || math.IsNaN(l.Confidence) || math.IsInf(l.Confidence, 0) {
			return 0, false
		}
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
		for id := range ev.Decisions {
			if _, expectedID := expected[id]; !expectedID {
				return nil, fmt.Errorf("calibrate %s: unknown decision for %s", r.ID, id)
			}
		}
		for _, id := range ids {
			d, ok := ev.Decisions[id]
			if !ok {
				return nil, fmt.Errorf("calibrate %s: missing decision for %s", r.ID, id)
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
				SampleCount:   len(ls),
			})
		}
	}
	return records, nil
}

// VerifyArtifact checks immutable provenance bindings and promotion criteria.
func VerifyArtifact(artifact *policy.SemanticThresholds, schemaData, datasetData []byte, schemaID string, schemaVersion int, questionIDs []string, provider string) error {
	if artifact == nil {
		return fmt.Errorf("calibration artifact is nil")
	}
	if !strings.EqualFold(artifact.QuestionSchemaSHA256, SHA256Hex(schemaData)) || !strings.EqualFold(artifact.DatasetSHA256, SHA256Hex(datasetData)) {
		return fmt.Errorf("calibration provenance hash mismatch")
	}
	// Verification validates a candidate before promotion; use the strict
	// binding rules while temporarily satisfying only the state predicate.
	candidate := *artifact
	candidate.Promoted, candidate.State = true, "promoted"
	if err := candidate.ValidateForEnforcement(schemaID, schemaVersion, questionIDs, provider); err != nil {
		return err
	}
	for _, m := range artifact.Metrics {
		c := artifact.PromotionCriteria
		if m.FalsePositive > c.MaxFPR || m.FalseNegative > c.MaxFNR || m.Precision < c.MinPrecision || m.Recall < c.MinRecall || m.Samples < c.MinSamples {
			return fmt.Errorf("promotion criteria failed for %s/%s/%s", m.Question, m.Language, m.Risk)
		}
	}
	return nil
}

// NewArtifact creates a reviewed, non-promoted artifact. Promotion is a
// separate explicit operation in evaltool.
func NewArtifact(rows []Row, provider decision.DecisionProvider, schemaData, datasetData []byte, schema *decision.QuestionSchema, targetFPR float64, toolVersion string) (*policy.SemanticThresholds, error) {
	return NewArtifactWithCriteria(rows, provider, schemaData, datasetData, schema, policy.PromotionCriteria{MaxFPR: targetFPR, MaxFNR: 1, MinPrecision: 0, MinRecall: 0, MinSamples: 1}, toolVersion)
}

// NewArtifactWithCriteria is the explicit calibration path used by promotion
// tooling. Criteria are stored in the artifact and rechecked at promotion.
func NewArtifactWithCriteria(rows []Row, provider decision.DecisionProvider, schemaData, datasetData []byte, schema *decision.QuestionSchema, criteria policy.PromotionCriteria, toolVersion string) (*policy.SemanticThresholds, error) {
	ids := make([]string, 0, len(schema.Questions))
	riskByQuestion := map[string]string{}
	for _, q := range schema.Questions {
		ids = append(ids, q.ID)
		riskByQuestion[q.ID] = q.Risk
	}
	records, err := Calibrate(rows, provider, ids, criteria.MaxFPR)
	if err != nil {
		return nil, err
	}
	counts := map[string]*sliceCounts{}
	for _, row := range rows {
		expected := row.SemanticExpected()
		if len(expected) == 0 {
			continue
		}
		ev, evalErr := provider.Evaluate(context.Background(), stubRequest(row), keysOf(expected))
		if evalErr != nil {
			return nil, fmt.Errorf("evaluate %s: %w", row.ID, evalErr)
		}
		for id, want := range expected {
			d, ok := ev.Decisions[id]
			if !ok {
				return nil, fmt.Errorf("evaluate %s: missing decision for %s", row.ID, id)
			}
			key := id + "\x00" + row.Language + "\x00" + riskByQuestion[id]
			if counts[key] == nil {
				counts[key] = &sliceCounts{Question: id, Language: row.Language, Risk: riskByQuestion[id]}
			}
			c := counts[key]
			c.Samples++
			if want {
				c.Positive++
			} else {
				c.Negative++
			}
			switch {
			case want && d.Value:
				c.TP++
			case want && !d.Value:
				c.FN++
			case !want && d.Value:
				c.FP++
			default:
				c.TN++
			}
		}
	}
	checkpoint := ""
	if len(rows) > 0 {
		ev, evalErr := provider.Evaluate(context.Background(), stubRequest(rows[0]), ids)
		if evalErr != nil {
			return nil, evalErr
		}
		checkpoint = ev.Checkpoint
	}
	stats := make([]policy.SemanticSliceStats, 0, len(counts))
	for _, c := range counts {
		stats = append(stats, c.Stats())
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Question != stats[j].Question {
			return stats[i].Question < stats[j].Question
		}
		return stats[i].Language < stats[j].Language
	})
	now := time.Now().UTC().Format(time.RFC3339)
	artifact := &policy.SemanticThresholds{
		ID: "semantic-thresholds-" + schema.Schema, Version: 1, ArtifactVersion: 1,
		Owner: "security-team", EffectiveDate: now[:10], QuestionSchema: schema.Schema,
		QuestionSchemaID: schema.Schema, QuestionSchemaVersion: schema.Version, QuestionSchemaSHA256: SHA256Hex(schemaData),
		Provider: provider.Name(), Checkpoint: checkpoint, ModelRevision: checkpoint,
		DatasetID: "held-out", DatasetVersion: "dataset-v1", DatasetSHA256: SHA256Hex(datasetData),
		CalibrationMethod: "held-out-quantile-fpr", CalibrationTimestamp: now, EvaluationTimestamp: now,
		ToolVersion: toolVersion, Evaluated: true, Promoted: false, State: "non_promoted",
		PromotionCriteria: criteria,
		SampleCounts:      stats, Metrics: stats, Thresholds: records,
	}
	for i := range artifact.Thresholds {
		for _, stat := range stats {
			if artifact.Thresholds[i].Question == stat.Question && artifact.Thresholds[i].Language == stat.Language {
				artifact.Thresholds[i].Risk = stat.Risk
				artifact.Thresholds[i].SampleCount = stat.Samples
			}
		}
	}
	return artifact, nil
}

type sliceCounts struct {
	Question, Language, Risk    string
	Samples, Positive, Negative int
	TP, FP, FN, TN              int
}

func (c *sliceCounts) Stats() policy.SemanticSliceStats {
	return policy.SemanticSliceStats{Question: c.Question, Language: c.Language, Risk: c.Risk,
		Samples: c.Samples, Positive: c.Positive, Negative: c.Negative,
		FalsePositive: ratio(c.FP, c.FP+c.TN), FalseNegative: ratio(c.FN, c.FN+c.TP),
		Precision: ratio(c.TP, c.TP+c.FP), Recall: ratio(c.TP, c.TP+c.FN)}
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

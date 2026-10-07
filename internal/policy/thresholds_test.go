package policy

import (
	"strings"
	"testing"
)

func TestValidateForEnforcementRequiresPromotionAndCoverage(t *testing.T) {
	tc := strictThresholdFixture()
	if err := tc.ValidateForEnforcement("security-v1", 1, []string{"prompt_injection"}, "laya"); err != nil {
		t.Fatalf("valid promoted artifact rejected: %v", err)
	}
	tc.Promoted = false
	if err := tc.ValidateForEnforcement("security-v1", 1, []string{"prompt_injection"}, "laya"); err == nil {
		t.Fatal("unpromoted artifact accepted")
	}
	tc = strictThresholdFixture()
	tc.Thresholds = tc.Thresholds[:1]
	if err := tc.ValidateForEnforcement("security-v1", 1, []string{"prompt_injection"}, "laya"); err == nil {
		t.Fatal("incomplete language coverage accepted")
	}
}

func TestValidateForEnforcementRejectsProviderAndHashBinding(t *testing.T) {
	tc := strictThresholdFixture()
	if err := tc.ValidateForEnforcement("security-v1", 1, []string{"prompt_injection"}, "noop"); err == nil {
		t.Fatal("noop provider accepted")
	}
	tc = strictThresholdFixture()
	tc.QuestionSchemaSHA256 = strings.Repeat("f", 63)
	if err := tc.ValidateForEnforcement("security-v1", 1, []string{"prompt_injection"}, "laya"); err == nil {
		t.Fatal("tampered schema hash accepted")
	}
}

func strictThresholdFixture() *SemanticThresholds {
	stats := []SemanticSliceStats{}
	records := []SemanticThresholdRecord{}
	for _, language := range []string{"th", "en", "mixed"} {
		stats = append(stats, SemanticSliceStats{Question: "prompt_injection", Language: language, Risk: "high", Samples: 10, Positive: 5, Negative: 5, Precision: 1, Recall: 1})
		records = append(records, SemanticThresholdRecord{Question: "prompt_injection", Language: language, MinConfidence: 0.9, Evaluated: true, SampleCount: 10})
	}
	return &SemanticThresholds{ID: "fixture", Version: 1, ArtifactVersion: 1, EffectiveDate: "2026-10-07", QuestionSchema: "security-v1", QuestionSchemaID: "security-v1", QuestionSchemaVersion: 1, QuestionSchemaSHA256: strings.Repeat("a", 64), Provider: "laya", Checkpoint: "checkpoint-1", ModelRevision: "revision-1", DatasetID: "dataset", DatasetVersion: "1", DatasetSHA256: strings.Repeat("b", 64), CalibrationMethod: "quantile", CalibrationTimestamp: "2026-10-07T00:00:00Z", EvaluationTimestamp: "2026-10-07T00:00:00Z", ToolVersion: "test", Evaluated: true, Promoted: true, State: "promoted", SampleCounts: stats, Metrics: stats, PromotionCriteria: PromotionCriteria{MaxFPR: 0.1, MaxFNR: 0.2, MinPrecision: 0.9, MinRecall: 0.9, MinSamples: 5}, Thresholds: records}
}

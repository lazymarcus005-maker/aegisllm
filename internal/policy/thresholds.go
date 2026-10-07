package policy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// SemanticThresholdRecord gates semantic enforcement for one calibrated
// question/language slice.
type SemanticThresholdRecord struct {
	Question      string  `yaml:"question"`
	Language      string  `yaml:"language,omitempty"`
	Risk          string  `yaml:"risk,omitempty"`
	Application   string  `yaml:"application,omitempty"`
	Provider      string  `yaml:"provider,omitempty"`
	MinConfidence float64 `yaml:"min_confidence"`
	Evaluated     bool    `yaml:"evaluated"`
	SampleCount   int     `yaml:"sample_count,omitempty"`
}

// SemanticSliceStats is bounded, content-free evaluation provenance for one
// question/language/risk slice.
type SemanticSliceStats struct {
	Question      string  `yaml:"question"`
	Language      string  `yaml:"language"`
	Risk          string  `yaml:"risk"`
	Samples       int     `yaml:"samples"`
	Positive      int     `yaml:"positive"`
	Negative      int     `yaml:"negative"`
	FalsePositive float64 `yaml:"false_positive_rate"`
	FalseNegative float64 `yaml:"false_negative_rate"`
	Precision     float64 `yaml:"precision"`
	Recall        float64 `yaml:"recall"`
}

type PromotionCriteria struct {
	MaxFPR       float64 `yaml:"max_false_positive_rate"`
	MaxFNR       float64 `yaml:"max_false_negative_rate"`
	MinPrecision float64 `yaml:"min_precision"`
	MinRecall    float64 `yaml:"min_recall"`
	MinSamples   int     `yaml:"min_samples"`
}

// SemanticThresholds is the versioned threshold policy document. The legacy
// fields remain accepted so shadow and deterministic-only deployments can
// continue to load the existing artifact. ValidateForEnforcement is the
// stricter P0.5 contract used before semantic enforcement is enabled.
type SemanticThresholds struct {
	ID                    string                    `yaml:"id"`
	Version               int                       `yaml:"version"`
	ArtifactVersion       int                       `yaml:"artifact_version,omitempty"`
	Owner                 string                    `yaml:"owner"`
	EffectiveDate         string                    `yaml:"effective_date"`
	QuestionSchema        string                    `yaml:"question_schema"`
	QuestionSchemaID      string                    `yaml:"question_schema_id,omitempty"`
	QuestionSchemaVersion int                       `yaml:"question_schema_version,omitempty"`
	QuestionSchemaSHA256  string                    `yaml:"question_schema_sha256,omitempty"`
	Checkpoint            string                    `yaml:"checkpoint,omitempty"`
	CheckpointRevision    string                    `yaml:"checkpoint_revision,omitempty"`
	ModelRevision         string                    `yaml:"model_revision,omitempty"`
	Provider              string                    `yaml:"provider,omitempty"`
	DatasetID             string                    `yaml:"dataset_id,omitempty"`
	DatasetVersion        string                    `yaml:"dataset_version,omitempty"`
	DatasetSHA256         string                    `yaml:"dataset_sha256,omitempty"`
	CalibrationMethod     string                    `yaml:"calibration_method,omitempty"`
	CalibrationTimestamp  string                    `yaml:"calibration_timestamp,omitempty"`
	EvaluationTimestamp   string                    `yaml:"evaluation_timestamp,omitempty"`
	ToolVersion           string                    `yaml:"tool_version,omitempty"`
	Evaluated             bool                      `yaml:"evaluated,omitempty"`
	Promoted              bool                      `yaml:"promoted,omitempty"`
	State                 string                    `yaml:"state,omitempty"`
	SampleCounts          []SemanticSliceStats      `yaml:"sample_counts,omitempty"`
	Metrics               []SemanticSliceStats      `yaml:"metrics,omitempty"`
	PromotionCriteria     PromotionCriteria         `yaml:"promotion_criteria,omitempty"`
	TargetFPR             float64                   `yaml:"target_false_positive_rate,omitempty"`
	Thresholds            []SemanticThresholdRecord `yaml:"thresholds"`
}

func LoadSemanticThresholds(data []byte) (*SemanticThresholds, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var t SemanticThresholds
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("threshold policy parse error: %w", err)
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return &t, nil
}

func LoadSemanticThresholdsFile(path string) (*SemanticThresholds, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("threshold policy load: %w", err)
	}
	return LoadSemanticThresholds(data)
}

// Validate enforces syntax and legacy-compatible per-record sanity.
func (t *SemanticThresholds) Validate() error {
	if t.ID == "" {
		return errors.New("threshold policy: id is required")
	}
	if t.Version <= 0 {
		return errors.New("threshold policy: version must be positive")
	}
	if t.QuestionSchema == "" {
		return errors.New("threshold policy: question_schema is required")
	}
	if t.QuestionSchemaID == "" {
		t.QuestionSchemaID = t.QuestionSchema
	}
	for i, r := range t.Thresholds {
		if r.Question == "" {
			return fmt.Errorf("threshold policy: thresholds[%d].question is required", i)
		}
		if r.MinConfidence < 0 || r.MinConfidence > 1 || r.MinConfidence != r.MinConfidence {
			return fmt.Errorf("threshold policy: thresholds[%d] (%s): min_confidence must be within [0,1]", i, r.Question)
		}
		if r.Language != "" && r.Language != "*" && !validLanguage(r.Language) {
			return fmt.Errorf("threshold policy: thresholds[%d] (%s): unknown language %q", i, r.Question, r.Language)
		}
		if r.Risk != "" && !validRisk(r.Risk) {
			return fmt.Errorf("threshold policy: thresholds[%d] (%s): unknown risk %q", i, r.Question, r.Risk)
		}
	}
	return nil
}

var sha256Pattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

// ValidateForEnforcement applies the strict provenance, coverage, and
// promotion contract. questionIDs must come from the loaded schema.
func (t *SemanticThresholds) ValidateForEnforcement(schemaID string, schemaVersion int, questionIDs []string, provider string) error {
	if err := t.Validate(); err != nil {
		return err
	}
	if t.QuestionSchemaID == "" || t.QuestionSchemaVersion <= 0 || !sha256Pattern.MatchString(t.QuestionSchemaSHA256) {
		return errors.New("threshold policy: question schema id, positive version, and sha256 are required for enforcement")
	}
	if t.ArtifactVersion <= 0 {
		return errors.New("threshold policy: artifact_version must be positive")
	}
	if _, err := time.Parse("2006-01-02", t.EffectiveDate); err != nil {
		return errors.New("threshold policy: effective_date must be YYYY-MM-DD")
	}
	if t.QuestionSchemaID != schemaID || t.QuestionSchemaVersion != schemaVersion {
		return errors.New("threshold policy: question schema binding mismatch")
	}
	if t.DatasetID == "" || t.DatasetVersion == "" || !sha256Pattern.MatchString(t.DatasetSHA256) {
		return errors.New("threshold policy: dataset id, version, and sha256 are required for enforcement")
	}
	if strings.TrimSpace(t.Provider) == "" || strings.EqualFold(t.Provider, "noop") || !strings.EqualFold(t.Provider, provider) {
		return errors.New("threshold policy: provider must be a real provider matching the runtime provider")
	}
	if strings.TrimSpace(t.Checkpoint) == "" || strings.TrimSpace(t.ModelRevision) == "" {
		return errors.New("threshold policy: checkpoint and model_revision are required for enforcement")
	}
	if !validTimestamp(t.CalibrationTimestamp) || !validTimestamp(t.EvaluationTimestamp) {
		return errors.New("threshold policy: calibration and evaluation timestamps must be RFC3339")
	}
	if strings.TrimSpace(t.ToolVersion) == "" || strings.TrimSpace(t.CalibrationMethod) == "" {
		return errors.New("threshold policy: calibration method and tool version are required")
	}
	if !t.Evaluated || !t.Promoted || t.State != "promoted" {
		return errors.New("threshold policy: artifact must be explicitly evaluated and promoted")
	}
	if t.PromotionCriteria.MinSamples <= 0 || !rate(t.PromotionCriteria.MaxFPR) || !rate(t.PromotionCriteria.MaxFNR) || !rate(t.PromotionCriteria.MinPrecision) || !rate(t.PromotionCriteria.MinRecall) {
		return errors.New("threshold policy: invalid promotion criteria")
	}
	if len(t.SampleCounts) == 0 || len(t.Metrics) == 0 {
		return errors.New("threshold policy: sample_counts and metrics are required for enforcement")
	}

	seen := map[string]bool{}
	for i, r := range t.Thresholds {
		if r.Language == "" || r.Language == "*" {
			return fmt.Errorf("threshold policy: thresholds[%d] must name a language slice", i)
		}
		key := r.Question + "\x00" + r.Language
		if seen[key] {
			return fmt.Errorf("threshold policy: duplicate question/language slice %q", key)
		}
		seen[key] = true
		if !contains(questionIDs, r.Question) || !r.Evaluated || r.SampleCount < t.PromotionCriteria.MinSamples {
			return fmt.Errorf("threshold policy: incomplete evaluated slice for %s/%s", r.Question, r.Language)
		}
	}
	for _, id := range questionIDs {
		for _, language := range []string{"th", "en", "mixed"} {
			if !seen[id+"\x00"+language] {
				return fmt.Errorf("threshold policy: missing eligible slice for %s/%s", id, language)
			}
		}
	}
	sampleBySlice := map[string]bool{}
	for _, m := range t.SampleCounts {
		if m.Samples < t.PromotionCriteria.MinSamples || m.Positive < 0 || m.Negative < 0 || m.Positive+m.Negative != m.Samples || !rate(m.FalsePositive) || !rate(m.FalseNegative) || !rate(m.Precision) || !rate(m.Recall) {
			return errors.New("threshold policy: invalid sample counts or metrics")
		}
		if !validLanguage(m.Language) || !validRisk(m.Risk) || !contains(questionIDs, m.Question) {
			return errors.New("threshold policy: sample count or metric has an unknown slice")
		}
		key := m.Question + "\x00" + m.Language + "\x00" + m.Risk
		if sampleBySlice[key] {
			return fmt.Errorf("threshold policy: duplicate sample slice %q", key)
		}
		sampleBySlice[key] = true
	}
	for _, m := range t.Metrics {
		if m.Samples < t.PromotionCriteria.MinSamples || m.Positive < 0 || m.Negative < 0 || m.Positive+m.Negative != m.Samples || !rate(m.FalsePositive) || !rate(m.FalseNegative) || !rate(m.Precision) || !rate(m.Recall) {
			return errors.New("threshold policy: invalid sample counts or metrics")
		}
		if !validLanguage(m.Language) || !validRisk(m.Risk) || !contains(questionIDs, m.Question) {
			return errors.New("threshold policy: sample count or metric has an unknown slice")
		}
	}
	metricBySlice := map[string]SemanticSliceStats{}
	for _, m := range t.Metrics {
		key := m.Question + "\x00" + m.Language
		if _, exists := metricBySlice[key]; exists {
			return fmt.Errorf("threshold policy: duplicate metric slice %q", key)
		}
		metricBySlice[key] = m
	}
	for _, r := range t.Thresholds {
		m, ok := metricBySlice[r.Question+"\x00"+r.Language]
		if !ok || m.FalsePositive > t.PromotionCriteria.MaxFPR || m.FalseNegative > t.PromotionCriteria.MaxFNR || m.Precision < t.PromotionCriteria.MinPrecision || m.Recall < t.PromotionCriteria.MinRecall {
			return fmt.Errorf("threshold policy: promotion criteria failed for %s/%s", r.Question, r.Language)
		}
	}
	return nil
}

func validTimestamp(value string) bool { _, err := time.Parse(time.RFC3339, value); return err == nil }
func rate(value float64) bool          { return value >= 0 && value <= 1 && value == value }
func validLanguage(value string) bool  { return value == "th" || value == "en" || value == "mixed" }
func validRisk(value string) bool      { return value == "high" || value == "medium" || value == "low" }
func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// Match returns the most specific record governing a question and traffic
// slice. Absent dimensions default to any.
func (t *SemanticThresholds) Match(question, language, application, provider string) (SemanticThresholdRecord, bool) {
	best, bestScore := -1, -1
	for i, r := range t.Thresholds {
		if r.Question != question || !dimensionMatches(r.Language, language) || !dimensionMatches(r.Application, application) || !dimensionMatches(r.Provider, provider) {
			continue
		}
		score := 0
		if r.Language != "" && r.Language != "*" {
			score++
		}
		if r.Application != "" && r.Application != "*" {
			score++
		}
		if r.Provider != "" && r.Provider != "*" {
			score++
		}
		if score > bestScore {
			best, bestScore = i, score
		}
	}
	if best < 0 {
		return SemanticThresholdRecord{}, false
	}
	return t.Thresholds[best], true
}

func dimensionMatches(pattern, value string) bool {
	return pattern == "" || pattern == "*" || strings.EqualFold(pattern, value)
}

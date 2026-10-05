package policy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// SemanticThresholdRecord gates semantic enforcement for one calibrated
// slice (architecture §7.4). A question may only enforce on traffic matching
// the record's slices, with answer_confidence >= min_confidence, and only
// when the record is marked evaluated (INV-010, REQ-CONF-002/003).
type SemanticThresholdRecord struct {
	Question      string  `yaml:"question"`
	Language      string  `yaml:"language,omitempty"`    // th | en | mixed | * (default *)
	Application   string  `yaml:"application,omitempty"` // default: any
	Provider      string  `yaml:"provider,omitempty"`    // default: any
	MinConfidence float64 `yaml:"min_confidence"`
	Evaluated     bool    `yaml:"evaluated"`
}

// SemanticThresholds is the versioned threshold policy document. It is
// policy-as-code: id, version, owner, effective date, provenance (dataset
// hash, calibration method) and the fitted thresholds.
type SemanticThresholds struct {
	ID                 string                    `yaml:"id"`
	Version            int                       `yaml:"version"`
	Owner              string                    `yaml:"owner"`
	EffectiveDate      string                    `yaml:"effective_date"`
	QuestionSchema     string                    `yaml:"question_schema"`
	Checkpoint         string                    `yaml:"checkpoint,omitempty"`
	CheckpointRevision string                    `yaml:"checkpoint_revision,omitempty"`
	DatasetVersion     string                    `yaml:"dataset_version,omitempty"`
	DatasetSHA256      string                    `yaml:"dataset_sha256,omitempty"`
	CalibrationMethod  string                    `yaml:"calibration_method,omitempty"`
	TargetFPR          float64                   `yaml:"target_false_positive_rate,omitempty"`
	Thresholds         []SemanticThresholdRecord `yaml:"thresholds"`
}

// LoadSemanticThresholds parses and validates a threshold policy document.
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

// LoadSemanticThresholdsFile reads and validates from disk.
func LoadSemanticThresholdsFile(path string) (*SemanticThresholds, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("threshold policy load: %w", err)
	}
	return LoadSemanticThresholds(data)
}

// Validate enforces provenance and per-record sanity.
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
	for i, r := range t.Thresholds {
		if r.Question == "" {
			return fmt.Errorf("threshold policy: thresholds[%d].question is required", i)
		}
		if r.MinConfidence < 0 || r.MinConfidence > 1 {
			return fmt.Errorf("threshold policy: thresholds[%d] (%s): min_confidence must be within [0,1]", i, r.Question)
		}
	}
	return nil
}

// Match returns the record governing one question on one traffic slice.
// Absent dimensions default to "any". The most specific record wins.
func (t *SemanticThresholds) Match(question, language, application, provider string) (SemanticThresholdRecord, bool) {
	best := -1
	bestScore := -1
	for i, r := range t.Thresholds {
		if r.Question != question {
			continue
		}
		if !dimensionMatches(r.Language, language) {
			continue
		}
		if !dimensionMatches(r.Application, application) {
			continue
		}
		if !dimensionMatches(r.Provider, provider) {
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
	if pattern == "" || pattern == "*" {
		return true
	}
	return strings.EqualFold(pattern, value)
}

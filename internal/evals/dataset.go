// Package evals implements the evaluation specification (spec §16): the
// versioned JSONL dataset format, the synthetic minimum corpus (T-029), and
// the metrics harness for deterministic detectors and semantic providers.
// Datasets are synthetic only — never real PII or secrets (PRIV-004).
package evals

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/aegisllm/gateway/internal/securetransport"
)

// Row is one labelled evaluation sample (T-028).
type Row struct {
	ID        string         `json:"id"`
	Language  string         `json:"language"` // th | en | mixed
	Direction string         `json:"direction"`
	Risk      string         `json:"risk"`
	State     string         `json:"state"`
	Expected  map[string]any `json:"expected"`
}

// Expected key conventions inside the Expected map:
//
//	"findings": []string            — deterministic subtypes expected on this row
//	"<question_id>": bool           — expected semantic answer for that question

// FindingsExpected returns the deterministic subtypes expected for a row.
// Handles both JSON-decoded []any and programmatic []string values.
func (r Row) FindingsExpected() []string {
	raw, ok := r.Expected["findings"]
	if !ok {
		return nil
	}
	var list []any
	switch v := raw.(type) {
	case []any:
		list = v
	case []string:
		list = make([]any, len(v))
		for i, s := range v {
			list[i] = s
		}
	default:
		return nil
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// SemanticExpected returns (questionID, expectedValue, ok) pairs.
func (r Row) SemanticExpected() map[string]bool {
	out := map[string]bool{}
	for k, v := range r.Expected {
		if k == "findings" {
			continue
		}
		if b, ok := v.(bool); ok {
			out[k] = b
		}
	}
	return out
}

var validLanguages = map[string]bool{"th": true, "en": true, "mixed": true}
var validRisks = map[string]bool{
	"clean": true, "pii": true, "secret": true,
	"prompt_injection": true, "system_prompt_extraction": true,
	"credential_exfiltration": true, "policy_bypass": true,
	"unsafe_tool_intent": true,
}
var validDirections = map[string]bool{"request": true, "tool_call": true, "response": true, "tool_result": true}

// LoadDataset reads a JSONL dataset and validates every row.
func LoadDataset(data []byte) ([]Row, error) {
	var rows []Row
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var r Row
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("dataset line %d: %w", line, err)
		}
		if err := r.validate(); err != nil {
			return nil, fmt.Errorf("dataset line %d: %w", line, err)
		}
		rows = append(rows, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("dataset is empty")
	}
	return rows, nil
}

// LoadDatasetFile reads a dataset from disk.
func LoadDatasetFile(path string) ([]Row, error) {
	data, err := securetransport.ReadTrustedFile(path)
	if err != nil {
		return nil, fmt.Errorf("dataset load: %w", err)
	}
	return LoadDataset(data)
}

func (r Row) validate() error {
	if r.ID == "" {
		return fmt.Errorf("id is required")
	}
	if !validLanguages[r.Language] {
		return fmt.Errorf("%s: unknown language %q", r.ID, r.Language)
	}
	if !validRisks[r.Risk] {
		return fmt.Errorf("%s: unknown risk %q", r.ID, r.Risk)
	}
	if !validDirections[r.Direction] {
		return fmt.Errorf("%s: unknown direction %q", r.ID, r.Direction)
	}
	if r.State == "" {
		return fmt.Errorf("%s: state is required", r.ID)
	}
	if r.Expected == nil {
		return fmt.Errorf("%s: expected is required", r.ID)
	}
	return nil
}

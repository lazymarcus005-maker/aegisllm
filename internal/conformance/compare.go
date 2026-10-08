package conformance

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/aegisllm/gateway/internal/securetransport"
)

type CompareReport struct {
	SchemaVersion   string         `json:"schema_version"`
	BaselineTarget  string         `json:"baseline_target"`
	CandidateTarget string         `json:"candidate_target"`
	SemanticDiffs   []SemanticDiff `json:"semantic_diffs"`
	LatencyDeltaMS  int64          `json:"latency_delta_ms"`
}
type SemanticDiff struct {
	CaseID    string `json:"case_id"`
	Kind      string `json:"kind"`
	Baseline  string `json:"baseline,omitempty"`
	Candidate string `json:"candidate,omitempty"`
}

func LoadReport(path string) (Report, error) {
	b, err := securetransport.ReadTrustedFile(path)
	if err != nil {
		return Report{}, err
	}
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		return Report{}, errors.New("report JSON is malformed")
	}
	if err := r.Validate(); err != nil {
		return Report{}, err
	}
	return r, nil
}

func Compare(base, candidate Report) CompareReport {
	out := CompareReport{SchemaVersion: "aegisllm.conformance-compare/v1", BaselineTarget: base.Target.ID, CandidateTarget: candidate.Target.ID, LatencyDeltaMS: candidate.DurationMS - base.DurationMS}
	bm, cm := map[string]CaseResult{}, map[string]CaseResult{}
	for _, c := range base.Cases {
		bm[c.ID] = c
	}
	for _, c := range candidate.Cases {
		cm[c.ID] = c
	}
	ids := make([]string, 0, len(bm)+len(cm))
	seen := map[string]bool{}
	for id := range bm {
		seen[id] = true
		ids = append(ids, id)
	}
	for id := range cm {
		if !seen[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		b, bok := bm[id]
		c, cok := cm[id]
		if !bok || !cok {
			out.SemanticDiffs = append(out.SemanticDiffs, SemanticDiff{CaseID: id, Kind: "case_presence"})
			continue
		}
		if b.Status != c.Status {
			out.SemanticDiffs = append(out.SemanticDiffs, SemanticDiff{CaseID: id, Kind: "status", Baseline: b.Status, Candidate: c.Status})
		}
		if b.Response.Semantic != c.Response.Semantic {
			out.SemanticDiffs = append(out.SemanticDiffs, SemanticDiff{CaseID: id, Kind: "semantic_shape"})
		}
	}
	return out
}

func (c CompareReport) Validate() error {
	if c.SchemaVersion != "aegisllm.conformance-compare/v1" {
		return fmt.Errorf("unsupported compare schema")
	}
	return nil
}
func MarshalCompare(c CompareReport) ([]byte, error) { return json.MarshalIndent(c, "", "  ") }

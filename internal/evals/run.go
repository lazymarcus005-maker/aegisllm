package evals

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/decision"
	"github.com/aegisllm/gateway/internal/detectors"
)

// DeterministicMetrics aggregates detector performance over a dataset
// (spec §16: TP/FP/FN, throughput, matching latency).
type DeterministicMetrics struct {
	Rows           int     `json:"rows"`
	TruePositives  int     `json:"true_positives"`
	FalsePositives int     `json:"false_positives"`
	FalseNegatives int     `json:"false_negatives"`
	TrueNegatives  int     `json:"true_negatives"`
	ThroughputRPS  float64 `json:"throughput_rps"`
	P95LatencyMS   float64 `json:"p95_latency_ms"`
}

// SemanticMetrics aggregates one question's performance.
type SemanticMetrics struct {
	Question       string  `json:"question"`
	Rows           int     `json:"rows"`
	TruePositives  int     `json:"true_positives"`
	FalsePositives int     `json:"false_positives"`
	FalseNegatives int     `json:"false_negatives"`
	TrueNegatives  int     `json:"true_negatives"`
	Accuracy       float64 `json:"accuracy"`
	Precision      float64 `json:"precision"`
	Recall         float64 `json:"recall"`
	F1             float64 `json:"f1"`
	FalsePosRate   float64 `json:"false_positive_rate"`
	FalseNegRate   float64 `json:"false_negative_rate"`
	AvgLatencyMS   float64 `json:"avg_latency_ms"`
}

// Baseline is the versioned baseline artifact (T-030).
type Baseline struct {
	GeneratedAt        time.Time            `json:"generated_at"`
	Dataset            string               `json:"dataset"`
	DatasetSHA256      string               `json:"dataset_sha256"`
	QuestionSchema     string               `json:"question_schema"`
	QuestionSchemaSHA  string               `json:"question_schema_sha256"`
	Provider           string               `json:"provider"`
	Checkpoint         string               `json:"checkpoint,omitempty"`
	CheckpointRevision string               `json:"checkpoint_revision,omitempty"`
	ThresholdPolicy    string               `json:"threshold_policy"`
	Deterministic      DeterministicMetrics `json:"deterministic"`
	Semantic           []SemanticMetrics    `json:"semantic"`
}

// RunDeterministic scans every row through the registry and scores findings
// against the rows' expected subtype lists.
func RunDeterministic(rows []Row, registry *detectors.Registry) DeterministicMetrics {
	m := DeterministicMetrics{Rows: len(rows)}
	var latencies []time.Duration
	start := time.Now()
	for _, r := range rows {
		env := &core.InspectionEnvelope{
			RequestID: "eval-" + r.ID,
			Direction: core.DirectionRequest,
			Messages: []core.Message{{
				Role:  core.RoleUser,
				Parts: []core.ContentPart{{Type: core.PartText, Text: r.State}},
			}},
		}
		rowStart := time.Now()
		findings := registry.RunAll(env)
		latencies = append(latencies, time.Since(rowStart))

		got := map[string]bool{}
		for _, f := range findings {
			got[f.Subtype] = true
		}
		want := map[string]bool{}
		for _, s := range r.FindingsExpected() {
			want[s] = true
		}
		for s := range want {
			if got[s] {
				m.TruePositives++
			} else {
				m.FalseNegatives++
			}
		}
		for s := range got {
			if !want[s] {
				m.FalsePositives++
			}
		}
		if len(want) == 0 && len(got) == 0 {
			m.TrueNegatives++
		}
	}
	total := time.Since(start)
	if len(rows) > 0 {
		m.ThroughputRPS = float64(len(rows)) / total.Seconds()
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		m.P95LatencyMS = float64(latencies[(len(latencies)*95)/100].Milliseconds())
	}
	return m
}

// RunSemantic evaluates semantic rows through a provider and computes the
// spec §16 metric set per question.
func RunSemantic(rows []Row, provider decision.DecisionProvider, questionIDs []string) []SemanticMetrics {
	perQuestion := map[string]*SemanticMetrics{}
	for _, id := range questionIDs {
		perQuestion[id] = &SemanticMetrics{Question: id}
	}
	var totalLatency int64
	var totalRows int

	for _, r := range rows {
		expected := r.SemanticExpected()
		if len(expected) == 0 {
			continue
		}
		start := time.Now()
		ev, err := provider.Evaluate(context.Background(), decision.DecisionRequest{
			RequestID: "eval-" + r.ID,
			Direction: r.Direction,
			Role:      "user",
			Content:   r.State,
		}, keysOf(expected))
		latencyMS := time.Since(start).Milliseconds()
		if err != nil {
			// Provider failures are recorded as misses for every expected
			// question of the row — a failed evaluation must not look clean.
			for id := range expected {
				if expected[id] {
					perQuestion[id].FalseNegatives++
				} else {
					perQuestion[id].TrueNegatives++
				}
				perQuestion[id].Rows++
			}
			continue
		}
		totalLatency += latencyMS
		totalRows++
		for id, want := range expected {
			got := ev.Decisions[id].Value
			m := perQuestion[id]
			m.Rows++
			switch {
			case want && got:
				m.TruePositives++
			case want && !got:
				m.FalseNegatives++
			case !want && got:
				m.FalsePositives++
			default:
				m.TrueNegatives++
			}
		}
	}

	var out []SemanticMetrics
	for _, id := range questionIDs {
		m := perQuestion[id]
		if m.Rows == 0 {
			continue
		}
		m.Accuracy = ratio(m.TruePositives+m.TrueNegatives, m.Rows)
		m.Precision = ratio(m.TruePositives, m.TruePositives+m.FalsePositives)
		m.Recall = ratio(m.TruePositives, m.TruePositives+m.FalseNegatives)
		if m.Precision+m.Recall > 0 {
			m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
		}
		m.FalsePosRate = ratio(m.FalsePositives, m.FalsePositives+m.TrueNegatives)
		m.FalseNegRate = ratio(m.FalseNegatives, m.FalseNegatives+m.TruePositives)
		if totalRows > 0 {
			m.AvgLatencyMS = float64(totalLatency) / float64(totalRows)
		}
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Question < out[j].Question })
	return out
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

// SHA256Hex hashes data for dataset/question-schema provenance (T-030).
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// RenderMarkdown renders the baseline as a report (T-030).
func RenderMarkdown(b Baseline) string {
	var s string
	s += fmt.Sprintf("# security-v1 evaluation report\n\n")
	s += fmt.Sprintf("- Generated: %s\n", b.GeneratedAt.UTC().Format(time.RFC3339))
	s += fmt.Sprintf("- Dataset: %s (sha256 %s)\n", b.Dataset, b.DatasetSHA256[:16]+"…")
	s += fmt.Sprintf("- Question schema: %s (sha256 %s)\n", b.QuestionSchema, b.QuestionSchemaSHA[:16]+"…")
	s += fmt.Sprintf("- Provider: %s (checkpoint %q, revision %q)\n", b.Provider, b.Checkpoint, b.CheckpointRevision)
	s += fmt.Sprintf("- Threshold policy: %s\n", b.ThresholdPolicy)
	s += fmt.Sprintf("\n## Deterministic detectors\n\n")
	s += fmt.Sprintf("| rows | TP | FP | FN | throughput rps | p95 ms |\n|---|---|---|---|---|---|\n")
	s += fmt.Sprintf("| %d | %d | %d | %d | %.0f | %.1f |\n",
		b.Deterministic.Rows, b.Deterministic.TruePositives, b.Deterministic.FalsePositives,
		b.Deterministic.FalseNegatives, b.Deterministic.ThroughputRPS, b.Deterministic.P95LatencyMS)
	s += fmt.Sprintf("\n## Semantic questions\n\n")
	if len(b.Semantic) == 0 {
		s += "No semantic metrics recorded (provider absent or noop). Baseline pending a real laya-serve run.\n"
		return s
	}
	s += "| question | rows | acc | precision | recall | F1 | FPR | FNR | avg ms |\n|---|---|---|---|---|---|---|---|---|\n"
	for _, m := range b.Semantic {
		s += fmt.Sprintf("| %s | %d | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f | %.1f |\n",
			m.Question, m.Rows, m.Accuracy, m.Precision, m.Recall, m.F1, m.FalsePosRate, m.FalseNegRate, m.AvgLatencyMS)
	}
	return s
}

// MarshalBaseline serializes the baseline artifact as indented JSON.
func MarshalBaseline(b Baseline) ([]byte, error) {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// UnmarshalBaseline reads a baseline artifact from JSON.
func UnmarshalBaseline(data []byte) (*Baseline, error) {
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

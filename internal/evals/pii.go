package evals

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/aegisllm/gateway/internal/pii"
)

type LabeledSpan struct {
	Entity string `json:"entity"`
	Start  int    `json:"start"`
	End    int    `json:"end"`
}

type PIIExample struct {
	ID       string        `json:"id"`
	Language string        `json:"language"`
	Text     string        `json:"text"`
	Spans    []LabeledSpan `json:"spans"`
}

type PIISliceMetrics struct {
	Language         string  `json:"language"`
	Entity           string  `json:"entity"`
	Gold             int     `json:"gold"`
	Predicted        int     `json:"predicted"`
	ExactTP          int     `json:"exact_tp"`
	OverlapTP        int     `json:"overlap_tp"`
	ExactPrecision   float64 `json:"exact_precision"`
	ExactRecall      float64 `json:"exact_recall"`
	ExactFNR         float64 `json:"exact_fnr"`
	OverlapPrecision float64 `json:"overlap_precision"`
	OverlapRecall    float64 `json:"overlap_recall"`
	OverlapFNR       float64 `json:"overlap_fnr"`
}

type PIIReport struct {
	Schema                string            `json:"schema"`
	DatasetSHA256         string            `json:"dataset_sha256"`
	Provider              string            `json:"provider"`
	ProductionEligible    bool              `json:"production_eligible"`
	Examples              int               `json:"examples"`
	Slices                []PIISliceMetrics `json:"slices"`
	CalibrationCandidates []float64         `json:"calibration_candidates"`
}

type piiCounts struct{ gold, predicted, exact, overlap int }

func LoadPIIDataset(data []byte) ([]PIIExample, error) {
	var out []PIIExample
	s := bufio.NewScanner(bytes.NewReader(data))
	s.Buffer(make([]byte, 4096), 1<<20)
	for s.Scan() {
		if strings.TrimSpace(s.Text()) == "" {
			continue
		}
		var ex PIIExample
		if err := json.Unmarshal(s.Bytes(), &ex); err != nil {
			return nil, fmt.Errorf("PII dataset row is invalid")
		}
		if ex.ID == "" || ex.Language == "" || ex.Text == "" {
			return nil, fmt.Errorf("PII dataset row is incomplete")
		}
		out = append(out, ex)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func MarshalPIISynthetic(examples []PIIExample) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	for _, example := range examples {
		if err := enc.Encode(example); err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}

type PIIPredictor interface {
	Name() string
	SpansContext(context.Context, string) ([]pii.EntitySpan, error)
}

func EvaluatePII(ctx context.Context, examples []PIIExample, predictor PIIPredictor, productionEligible bool) (PIIReport, error) {
	if predictor == nil {
		return PIIReport{}, fmt.Errorf("PII predictor is required")
	}
	group := map[string]*piiCounts{}
	confidence := map[float64]bool{}
	for _, ex := range examples {
		predicted, err := predictor.SpansContext(ctx, ex.Text)
		if err != nil {
			return PIIReport{}, fmt.Errorf("PII provider evaluation failed")
		}
		for _, span := range predicted {
			confidence[roundConfidence(span.Confidence)] = true
		}
		for _, gold := range ex.Spans {
			key := ex.Language + "\x00" + gold.Entity
			if group[key] == nil {
				group[key] = &piiCounts{}
			}
			group[key].gold++
		}
		for _, span := range predicted {
			key := ex.Language + "\x00" + span.Label
			if group[key] == nil {
				group[key] = &piiCounts{}
			}
			group[key].predicted++
		}
		matchRows(ex, predicted, group)
	}
	var keys []string
	for key := range group {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	report := PIIReport{Schema: "aegisllm.pii-eval/v1", Provider: predictor.Name(), ProductionEligible: productionEligible, Examples: len(examples)}
	for _, key := range keys {
		parts := strings.SplitN(key, "\x00", 2)
		c := group[key]
		report.Slices = append(report.Slices, makeSlice(parts[0], parts[1], c))
	}
	for value := range confidence {
		report.CalibrationCandidates = append(report.CalibrationCandidates, value)
	}
	sort.Float64s(report.CalibrationCandidates)
	return report, nil
}

func matchRows(ex PIIExample, predicted []pii.EntitySpan, group map[string]*piiCounts) {
	usedExact := map[int]bool{}
	usedOverlap := map[int]bool{}
	for _, gold := range ex.Spans {
		for i, span := range predicted {
			if span.Label != gold.Entity || usedExact[i] {
				continue
			}
			if span.Start == gold.Start && span.End == gold.End {
				group[ex.Language+"\x00"+gold.Entity].exact++
				usedExact[i] = true
				break
			}
		}
		for i, span := range predicted {
			if span.Label != gold.Entity || usedOverlap[i] {
				continue
			}
			if span.Start < gold.End && gold.Start < span.End {
				group[ex.Language+"\x00"+gold.Entity].overlap++
				usedOverlap[i] = true
				break
			}
		}
	}
}

func makeSlice(language, entity string, c *piiCounts) PIISliceMetrics {
	return PIISliceMetrics{Language: language, Entity: entity, Gold: c.gold, Predicted: c.predicted, ExactTP: c.exact, OverlapTP: c.overlap, ExactPrecision: piiRatio(c.exact, c.predicted), ExactRecall: piiRatio(c.exact, c.gold), ExactFNR: piiRatio(c.gold-c.exact, c.gold), OverlapPrecision: piiRatio(c.overlap, c.predicted), OverlapRecall: piiRatio(c.overlap, c.gold), OverlapFNR: piiRatio(c.gold-c.overlap, c.gold)}
}
func piiRatio(num, den int) float64 {
	if den <= 0 {
		return 0
	}
	return float64(num) / float64(den)
}
func roundConfidence(v float64) float64 {
	switch {
	case v < .5:
		return .25
	case v < .75:
		return .5
	case v < .9:
		return .75
	default:
		return .9
	}
}

func MarshalPIIReport(r PIIReport) ([]byte, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
func RenderPIIMarkdown(r PIIReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# PII / NER span evaluation\n\n- Schema: %s\n- Dataset SHA-256: %s\n- Provider: %s\n- Production eligible: %t\n- Examples: %d\n\n", r.Schema, r.DatasetSHA256, r.Provider, r.ProductionEligible, r.Examples)
	b.WriteString("| language | entity | gold | predicted | exact P | exact R | exact FNR | overlap P | overlap R | overlap FNR |\n|---|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, s := range r.Slices {
		fmt.Fprintf(&b, "| %s | %s | %d | %d | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f |\n", s.Language, s.Entity, s.Gold, s.Predicted, s.ExactPrecision, s.ExactRecall, s.ExactFNR, s.OverlapPrecision, s.OverlapRecall, s.OverlapFNR)
	}
	fmt.Fprintf(&b, "\nCalibration candidates: %v\n", r.CalibrationCandidates)
	if !r.ProductionEligible {
		b.WriteString("\n> NON-PRODUCTION: synthetic/fake provider or dataset. Do not use this report for model promotion.\n")
	}
	return b.String()
}

func PIIProvenanceHash(data []byte) string { return SHA256Hex(data) }

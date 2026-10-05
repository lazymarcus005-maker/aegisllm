// Command evaltool generates the security-v1 dataset and runs evaluations,
// producing baseline artifacts under evals/ (T-028..T-030).
//
// Usage:
//
//	evaltool -generate                        # write evals/datasets/security-v1.jsonl
//	evaltool -provider noop                   # deterministic metrics only
//	evaltool -provider laya -url http://localhost:8300
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aegisllm/gateway/internal/decision"
	"github.com/aegisllm/gateway/internal/detectors"
	"github.com/aegisllm/gateway/internal/evals"
)

func main() {
	generate := flag.Bool("generate", false, "generate the minimum dataset and exit")
	datasetPath := flag.String("dataset", "evals/datasets/security-v1.jsonl", "dataset path")
	questionsPath := flag.String("questions", "questions/security-v1.yaml", "question schema path")
	providerName := flag.String("provider", "noop", "semantic provider: noop | laya")
	layaURL := flag.String("url", "http://localhost:8300", "laya-serve URL (provider=laya)")
	baselinePath := flag.String("baseline", "", "write baseline JSON here")
	reportPath := flag.String("report", "", "write markdown report here")
	calibrate := flag.Bool("calibrate", false, "fit thresholds against the dataset and print YAML records")
	comparePath := flag.String("compare", "", "compare the fresh run against this baseline (regression gate)")
	tolerance := flag.Float64("tolerance", 0.05, "regression tolerance fraction for -compare")
	targetFPR := flag.Float64("target-fpr", 0.05, "target false-positive rate for -calibrate")
	flag.Parse()

	if *generate {
		rows := evals.GenerateMinimumCorpus()
		data, err := evals.MarshalLines(rows)
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(*datasetPath, data, 0o644); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("wrote %d rows to %s\n", len(rows), *datasetPath)
		return
	}

	rows, err := evals.LoadDatasetFile(*datasetPath)
	if err != nil {
		log.Fatal(err)
	}
	datasetData, err := os.ReadFile(*datasetPath)
	if err != nil {
		log.Fatal(err)
	}
	questionsData, err := os.ReadFile(*questionsPath)
	if err != nil {
		log.Fatal(err)
	}
	qs, err := decision.LoadQuestions(questionsData)
	if err != nil {
		log.Fatal(err)
	}

	registry := detectors.NewRegistry(nil)
	for _, d := range detectors.SecretDetectors("eval-telemetry-key") {
		registry.Register(d)
	}
	for _, d := range detectors.PiiDetectors("eval-telemetry-key") {
		registry.Register(d)
	}

	provider := buildProvider(*providerName, *layaURL)

	baseline := evals.Baseline{
		GeneratedAt:       time.Now(),
		Dataset:           *datasetPath,
		DatasetSHA256:     evals.SHA256Hex(datasetData),
		QuestionSchema:    qs.Schema,
		QuestionSchemaSHA: evals.SHA256Hex(questionsData),
		Provider:          provider.Name(),
		ThresholdPolicy:   "none — semantic enforcement stays disabled until calibration (ticket 11)",
	}
	baseline.Deterministic = evals.RunDeterministic(rows, registry)
	baseline.Semantic = evals.RunSemantic(rows, provider, allQuestionIDs(qs))

	if *comparePath != "" {
		oldData, err := os.ReadFile(*comparePath)
		if err != nil {
			log.Fatal(err)
		}
		oldBase, err := evals.UnmarshalBaseline(oldData)
		if err != nil {
			log.Fatal(err)
		}
		violations := evals.CompareBaseline(*oldBase, baseline, *tolerance)
		if len(violations) > 0 {
			fmt.Fprintln(os.Stderr, "REGRESSIONS DETECTED:")
			for _, v := range violations {
				fmt.Fprintln(os.Stderr, "  -", v)
			}
			os.Exit(1)
		}
		fmt.Printf("no regressions vs %s (tolerance %.2f)\n", *comparePath, *tolerance)
	}

	if *calibrate {
		records, err := evals.Calibrate(rows, provider, allQuestionIDs(qs), *targetFPR)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("# fitted threshold records (review, set provenance, flip evaluated where justified)")
		for _, r := range records {
			fmt.Printf("  - question: %s\n    language: %s\n    min_confidence: %.3f\n    evaluated: %t\n",
				r.Question, r.Language, r.MinConfidence, r.Evaluated)
		}
		return
	}

	out, err := evals.MarshalBaseline(baseline)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(out))

	if *baselinePath != "" {
		if err := os.WriteFile(*baselinePath, out, 0o644); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("baseline written to %s\n", *baselinePath)
	}
	if *reportPath != "" {
		if err := os.WriteFile(*reportPath, []byte(evals.RenderMarkdown(baseline)), 0o644); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("report written to %s\n", *reportPath)
	}
}

func buildProvider(name, url string) decision.DecisionProvider {
	switch name {
	case "laya":
		return decision.NewLayaProvider(url, "/v1/evaluate", 10*time.Second)
	default:
		return decision.NoopProvider{}
	}
}

func allQuestionIDs(qs *decision.QuestionSchema) []string {
	var ids []string
	for _, q := range qs.Questions {
		ids = append(ids, q.ID)
	}
	return ids
}

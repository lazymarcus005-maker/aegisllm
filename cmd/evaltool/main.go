// Command evaltool evaluates held-out semantic data and manages reviewed
// calibration artifacts. It never enables gateway enforcement or writes to a
// repository automatically.
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
	"github.com/aegisllm/gateway/internal/policy"
	"gopkg.in/yaml.v3"
)

func main() {
	action := flag.String("action", "evaluate", "workflow action: evaluate | calibrate | verify | promote")
	generate := flag.Bool("generate", false, "generate the minimum dataset and exit")
	datasetPath := flag.String("dataset", "evals/datasets/security-v1.jsonl", "held-out dataset path")
	questionsPath := flag.String("questions", "questions/security-v1.yaml", "question schema path")
	providerName := flag.String("provider", "noop", "semantic provider: noop | fake | laya")
	layaURL := flag.String("url", "http://localhost:8300", "operator-provided Laya/fake HTTP provider URL")
	baselinePath := flag.String("baseline", "", "write baseline JSON here")
	reportPath := flag.String("report", "", "write markdown report here")
	artifactPath := flag.String("artifact", "", "calibration artifact to verify or promote")
	outputPath := flag.String("output", "", "output path for a calibrated/promoted artifact")
	calibrate := flag.Bool("calibrate", false, "compatibility alias for -action calibrate")
	comparePath := flag.String("compare", "", "compare the fresh run against this baseline")
	tolerance := flag.Float64("tolerance", 0.05, "regression tolerance fraction")
	targetFPR := flag.Float64("target-fpr", 0.05, "target false-positive rate")
	targetFNR := flag.Float64("target-fnr", 0.20, "maximum false-negative rate for promotion")
	minPrecision := flag.Float64("min-precision", 0.90, "minimum precision for promotion")
	minRecall := flag.Float64("min-recall", 0.90, "minimum recall for promotion")
	minSamples := flag.Int("min-samples", 30, "minimum samples per language/risk slice for promotion")
	flag.Parse()
	if *calibrate {
		*action = "calibrate"
	}

	if *generate {
		data, err := evals.MarshalLines(evals.GenerateMinimumCorpus())
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(*datasetPath, data, 0o644); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("wrote dataset to %s\n", *datasetPath)
		return
	}
	rows, datasetData, qs, questionsData := loadInputs(*datasetPath, *questionsPath)
	provider := buildProvider(*providerName, *layaURL)

	switch *action {
	case "calibrate":
		if provider.Name() == "noop" {
			log.Fatal("calibrate requires a real provider; noop artifacts are non-production")
		}
		criteria := policy.PromotionCriteria{MaxFPR: *targetFPR, MaxFNR: *targetFNR, MinPrecision: *minPrecision, MinRecall: *minRecall, MinSamples: *minSamples}
		artifact, err := evals.NewArtifactWithCriteria(rows, provider, questionsData, datasetData, qs, criteria, "evaltool-p0.5")
		if err != nil {
			log.Fatal(err)
		}
		data, err := yaml.Marshal(artifact)
		if err != nil {
			log.Fatal(err)
		}
		if *outputPath != "" {
			if err := os.WriteFile(*outputPath, data, 0o644); err != nil {
				log.Fatal(err)
			}
		}
		fmt.Print(string(data))
		return
	case "verify", "promote":
		if *artifactPath == "" {
			log.Fatal("-artifact is required")
		}
		artifactData, err := os.ReadFile(*artifactPath)
		if err != nil {
			log.Fatal(err)
		}
		artifact, err := policy.LoadSemanticThresholds(artifactData)
		if err != nil {
			log.Fatal(err)
		}
		if *providerName == "noop" {
			log.Fatal("verify/promote requires a real provider binding")
		}
		if *action == "promote" {
			artifact.Promoted, artifact.State = true, "promoted"
		}
		ids := allQuestionIDs(qs)
		if err := evals.VerifyArtifact(artifact, questionsData, datasetData, qs.Schema, qs.Version, ids, provider.Name()); err != nil {
			log.Fatal(err)
		}
		if *action == "promote" {
			out, err := yaml.Marshal(artifact)
			if err != nil {
				log.Fatal(err)
			}
			dest := *outputPath
			if dest == "" {
				dest = *artifactPath
			}
			if err := os.WriteFile(dest, out, 0o644); err != nil {
				log.Fatal(err)
			}
			fmt.Printf("promoted reviewed artifact written to %s\n", dest)
		} else {
			fmt.Println("artifact verification passed")
		}
		return
	case "evaluate":
		// Continue below for the existing baseline workflow. noop is permitted
		// here solely for the committed synthetic deterministic baseline.
	default:
		log.Fatalf("unknown action %q", *action)
	}

	registry := detectors.NewRegistry(nil)
	for _, d := range detectors.SecretDetectors("eval-telemetry-key") {
		registry.Register(d)
	}
	for _, d := range detectors.PiiDetectors("eval-telemetry-key") {
		registry.Register(d)
	}
	baseline := evals.Baseline{GeneratedAt: time.Now(), Dataset: *datasetPath, DatasetSHA256: evals.SHA256Hex(datasetData), QuestionSchema: qs.Schema, QuestionSchemaSHA: evals.SHA256Hex(questionsData), Provider: provider.Name(), ThresholdPolicy: "none — semantic enforcement stays disabled until a promoted real-provider artifact exists"}
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
		if violations := evals.CompareBaseline(*oldBase, baseline, *tolerance); len(violations) > 0 {
			for _, v := range violations {
				fmt.Fprintln(os.Stderr, v)
			}
			os.Exit(1)
		}
	}
	out, err := evals.MarshalBaseline(baseline)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(string(out))
	if *baselinePath != "" {
		if err := os.WriteFile(*baselinePath, out, 0o644); err != nil {
			log.Fatal(err)
		}
	}
	if *reportPath != "" {
		if err := os.WriteFile(*reportPath, []byte(evals.RenderMarkdown(baseline)), 0o644); err != nil {
			log.Fatal(err)
		}
	}
}

func loadInputs(datasetPath, questionsPath string) ([]evals.Row, []byte, *decision.QuestionSchema, []byte) {
	datasetData, err := os.ReadFile(datasetPath)
	if err != nil {
		log.Fatal(err)
	}
	rows, err := evals.LoadDataset(datasetData)
	if err != nil {
		log.Fatal(err)
	}
	questionsData, err := os.ReadFile(questionsPath)
	if err != nil {
		log.Fatal(err)
	}
	qs, err := decision.LoadQuestions(questionsData)
	if err != nil {
		log.Fatal(err)
	}
	return rows, datasetData, qs, questionsData
}

func buildProvider(name, url string) decision.DecisionProvider {
	switch name {
	case "laya":
		return decision.NewLayaProvider(url, "/v1/evaluate", 10*time.Second)
	case "fake":
		return &decision.FakeProvider{Answers: map[string]decision.Decision{}}
	default:
		return decision.NoopProvider{}
	}
}

func allQuestionIDs(qs *decision.QuestionSchema) []string {
	ids := make([]string, 0, len(qs.Questions))
	for _, q := range qs.Questions {
		ids = append(ids, q.ID)
	}
	return ids
}

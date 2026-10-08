// Command piieval evaluates labeled PII/NER spans. Reports contain only
// aggregate metrics and dataset provenance; synthetic/fake runs are marked
// non-production and cannot be used for model promotion.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/aegisllm/gateway/internal/evals"
	"github.com/aegisllm/gateway/internal/pii"
	"github.com/aegisllm/gateway/internal/securetransport"
)

func main() {
	datasetPath := flag.String("dataset", "evals/datasets/pii-ner-synthetic.jsonl", "labeled JSONL span dataset")
	providerName := flag.String("provider", "aegis", "provider: aegis | presidio | fake")
	providerURL := flag.String("url", "http://127.0.0.1:8400", "private provider URL")
	reportPath := flag.String("report", "", "write Markdown report")
	jsonPath := flag.String("json", "", "write JSON report")
	generate := flag.Bool("generate", false, "write the synthetic non-production dataset")
	flag.Parse()
	if *generate {
		data, err := evals.MarshalPIISynthetic(evals.GeneratePIISynthetic())
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(*datasetPath, data, 0o600); err != nil {
			log.Fatal(err)
		}
		fmt.Println("wrote synthetic non-production dataset to", *datasetPath)
		return
	}
	data, err := securetransport.ReadTrustedFile(*datasetPath)
	if err != nil {
		log.Fatal(err)
	}
	examples, err := evals.LoadPIIDataset(data)
	if err != nil {
		log.Fatal(err)
	}
	var predictor evals.PIIPredictor
	production := false
	switch *providerName {
	case "presidio":
		p, buildErr := pii.NewPresidioHTTPAdapter(pii.HTTPProviderConfig{ID: "presidio", URL: *providerURL, MaxChars: 4096, ChunkOverlap: 128, MaxConcurrent: 4, Breaker: 3, BreakerOpen: 15e9, Timeout: 2e9, FailBehavior: "strict"})
		if buildErr != nil {
			log.Fatal(buildErr)
		}
		predictor = p
		production = true
	case "aegis":
		p, buildErr := pii.NewAegisNERAdapter(pii.HTTPProviderConfig{ID: "aegis", URL: *providerURL, MaxChars: 4096, ChunkOverlap: 128, MaxConcurrent: 4, Breaker: 3, BreakerOpen: 15e9, Timeout: 2e9, FailBehavior: "strict"})
		if buildErr != nil {
			log.Fatal(buildErr)
		}
		predictor = p
		production = true
	case "fake":
		p, buildErr := pii.NewAegisNERAdapter(pii.HTTPProviderConfig{ID: "fake", URL: *providerURL, MaxChars: 4096, ChunkOverlap: 128, MaxConcurrent: 4, Breaker: 3, BreakerOpen: 15e9, Timeout: 2e9, FailBehavior: "deterministic_only"})
		if buildErr != nil {
			log.Fatal(buildErr)
		}
		predictor = p
	default:
		log.Fatal("unknown provider")
	}
	report, err := evals.EvaluatePII(context.Background(), examples, predictor, production)
	if err != nil {
		log.Fatal(err)
	}
	report.DatasetSHA256 = evals.PIIProvenanceHash(data)
	jsonData, err := evals.MarshalPIIReport(report)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(string(jsonData))
	if *jsonPath != "" {
		if err := os.WriteFile(*jsonPath, jsonData, 0o600); err != nil {
			log.Fatal(err)
		}
	}
	if *reportPath != "" {
		if err := os.WriteFile(*reportPath, []byte(evals.RenderPIIMarkdown(report)), 0o600); err != nil {
			log.Fatal(err)
		}
	}
}

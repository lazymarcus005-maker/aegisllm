// Command fakener is a CI-only deterministic HTTP NER contract fixture. It
// is synthetic plumbing coverage, not a model and not a quality benchmark.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"

	"github.com/aegisllm/gateway/internal/pii"
	"github.com/aegisllm/gateway/internal/securetransport"
)

type request struct {
	Text string `json:"text"`
}
type responseSpan struct {
	Entity     string  `json:"entity"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Confidence float64 `json:"confidence"`
	OffsetUnit string  `json:"offset_unit"`
}

func main() {
	http.HandleFunc("/", handle)
	log.Println("fake NER CI service listening on :8400")
	if err := securetransport.ServeHTTPServer(securetransport.NewHTTPServer(":8400", http.DefaultServeMux), "", ""); err != nil {
		log.Fatal(err)
	}
}
func handle(w http.ResponseWriter, r *http.Request) {
	var in request
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in) != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	var out []responseSpan
	for _, s := range pii.NewRegexSpanProvider().Spans(in.Text) {
		out = append(out, responseSpan{Entity: s.Label, Start: s.Start, End: s.End, Confidence: 0.6, OffsetUnit: "byte"})
	}
	for _, loc := range regexp.MustCompile(`\b\d+\s+[A-Za-z]+\s+(?:Road|Rd|Street|St)\.?`).FindAllStringIndex(in.Text, -1) {
		out = append(out, responseSpan{Entity: "ADDRESS", Start: loc[0], End: loc[1], Confidence: 0.6, OffsetUnit: "byte"})
	}
	for _, loc := range regexp.MustCompile(`[0-9]{10,16}`).FindAllStringIndex(in.Text, -1) {
		out = append(out, responseSpan{Entity: "BANK_ACCOUNT", Start: loc[0], End: loc[1], Confidence: 0.95, OffsetUnit: "byte"})
	}
	for _, loc := range regexp.MustCompile(`\bEMP-[0-9]{4,8}\b`).FindAllStringIndex(in.Text, -1) {
		out = append(out, responseSpan{Entity: "EMPLOYEE_ID", Start: loc[0], End: loc[1], Confidence: 0.99, OffsetUnit: "byte"})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"schema": pii.ProviderSchema, "version": 1, "spans": out})
}

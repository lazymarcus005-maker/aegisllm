// Command semanticctl is the offline/operator CLI for the signed semantic
// registry. It prints metadata projections only; model weights and dataset
// contents are never accepted or emitted.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	semantic "github.com/aegisllm/gateway/internal/semantic"
)

func main() {
	action := flag.String("action", "status", "status|list|validate|register|transition")
	artifactPath := flag.String("artifact", "", "signed semantic metadata JSON")
	statePath := flag.String("state", "", "registry state file")
	trustPath := flag.String("trust-store", "", "rotating trust store")
	to := flag.String("to", "", "target lifecycle state for transition")
	actor := flag.String("actor", "operator", "verified operator actor label")
	provenance := flag.String("provenance", "semanticctl", "bounded operator provenance")
	idempotency := flag.String("idempotency-key", "", "required mutation idempotency key")
	revision := flag.Uint64("expected-revision", 0, "optimistic registry revision")
	confirm := flag.Bool("confirm", false, "explicitly confirm broad lifecycle action")
	flag.Parse()

	if *trustPath == "" {
		fail("-trust-store is required")
	}
	m, err := semantic.NewManager(semantic.Config{StatePath: *statePath, TrustStorePath: *trustPath})
	if err != nil {
		fail(err.Error())
	}
	switch strings.ToLower(*action) {
	case "status":
		printJSON(m.Status())
	case "list":
		views := []semantic.RecordView{}
		for _, r := range m.List(0) {
			views = append(views, semantic.View(r))
		}
		printJSON(map[string]any{"revision": m.Revision(), "models": views})
	case "validate":
		a := readArtifact(*artifactPath)
		if err := m.ValidateArtifact(a); err != nil {
			fail("artifact rejected")
		}
		printJSON(map[string]string{"status": "validated"})
	case "register":
		a := readArtifact(*artifactPath)
		r, err := m.Register(semantic.Request{Artifact: a, Actor: *actor, Provenance: *provenance, IdempotencyKey: required(*idempotency, "-idempotency-key"), ExpectedRevision: *revision})
		if err != nil {
			fail("registration rejected")
		}
		printJSON(semantic.View(r))
	case "transition":
		if *artifactPath == "" || *to == "" {
			fail("-artifact and -to are required for transition")
		}
		a := readArtifact(*artifactPath)
		r, err := m.Transition(semantic.Request{Artifact: a, Actor: *actor, Provenance: *provenance, IdempotencyKey: required(*idempotency, "-idempotency-key"), ExpectedRevision: *revision, Confirm: *confirm}, semantic.State(*to))
		if err != nil {
			fail("transition rejected")
		}
		printJSON(semantic.View(r))
	default:
		fail("unknown action")
	}
}

func readArtifact(path string) semantic.Artifact {
	if path == "" {
		fail("-artifact is required")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- offline operator CLI intentionally reads the explicitly supplied artifact path.
	if err != nil {
		fail("artifact unavailable")
	}
	var a semantic.Artifact
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		fail("artifact malformed")
	}
	return a
}
func required(v, name string) string {
	if strings.TrimSpace(v) == "" {
		fail(name + " is required")
	}
	return v
}
func printJSON(v any) { data, _ := json.MarshalIndent(v, "", "  "); fmt.Println(string(data)) }
func fail(msg string) { fmt.Fprintln(os.Stderr, msg); os.Exit(2) }

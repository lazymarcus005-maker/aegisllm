// Command policytool validates and simulates the same policy contract used by
// the gateway runtime. Request bodies are read from files or stdin and are
// never echoed, logged, or included in output.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/gateway"
	"github.com/aegisllm/gateway/internal/policy"
)

type result struct {
	PolicyID        string                  `json:"policy_id"`
	PolicyVersion   int                     `json:"policy_version"`
	Rules           []policy.RuleSummary    `json:"rules,omitempty"`
	Findings        []policy.FindingSummary `json:"findings,omitempty"`
	MatchedRule     string                  `json:"matched_rule,omitempty"`
	PrecedenceStage string                  `json:"precedence_stage,omitempty"`
	FinalAction     core.Action             `json:"final_action,omitempty"`
	Code            string                  `json:"code,omitempty"`
	Reason          string                  `json:"reason,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		fail("command is required: validate, effective, or explain")
	}
	command := os.Args[1]
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	policyPath := fs.String("policy", "policies/enterprise-default.yaml", "policy YAML file")
	requestPath := fs.String("request", "", "request JSON file, or - for stdin")
	path := fs.String("path", "/v1/chat/completions", "wire endpoint when request is not a normalized envelope")
	provider := fs.String("provider", "", "provider metadata override")
	tenant := fs.String("tenant", "", "tenant metadata override")
	application := fs.String("application", "", "application metadata override")
	if err := fs.Parse(os.Args[2:]); err != nil {
		fail("invalid command arguments")
	}

	pol, err := policy.LoadFile(*policyPath)
	if err != nil {
		fail("invalid policy")
	}
	base := result{PolicyID: pol.ID, PolicyVersion: pol.Version}
	switch command {
	case "validate":
		base.Rules = pol.Summary()
		write(base)
	case "effective":
		base.Rules = pol.Summary()
		if *requestPath != "" {
			explainInto(&base, pol, *requestPath, *path, *provider, *tenant, *application)
		}
		write(base)
	case "explain":
		if *requestPath == "" {
			fail("request is required")
		}
		explainInto(&base, pol, *requestPath, *path, *provider, *tenant, *application)
		write(base)
	default:
		fail("unknown command")
	}
}

func explainInto(out *result, pol *policy.Policy, requestPath, endpoint, provider, tenant, application string) {
	raw, err := readInput(requestPath)
	if err != nil {
		fail("invalid request input")
	}
	env, err := requestEnvelope(raw, endpoint)
	if err != nil {
		fail("invalid request JSON")
	}
	if env.RequestID == "" {
		env.RequestID = "policytool"
	}
	if env.Direction == "" {
		env.Direction = core.DirectionRequest
	}
	if env.Target.Provider == "" {
		env.Target.Provider = provider
	}
	if tenant != "" {
		env.Tenant = tenant
	}
	if application != "" {
		env.Application = application
	}
	findings := gateway.ProductionFindings(env, "")
	explanation := policy.NewEngine(pol).Explain(policy.Context{Envelope: env, Findings: findings})
	out.Findings = explanation.Findings
	out.MatchedRule = explanation.Decision.MatchedRule
	out.PrecedenceStage = string(explanation.Decision.PrecedenceStage)
	out.FinalAction = explanation.Decision.Action
	out.Code = explanation.Decision.Code
	out.Reason = explanation.Decision.Reason
}

func requestEnvelope(raw []byte, endpoint string) (*core.InspectionEnvelope, error) {
	var env core.InspectionEnvelope
	if json.Unmarshal(raw, &env) == nil && len(env.Messages) > 0 {
		for _, message := range env.Messages {
			if len(message.Parts) > 0 {
				return &env, nil
			}
		}
	}
	n := gateway.NormalizerFor(endpoint)
	if n == nil {
		return nil, fmt.Errorf("unsupported endpoint")
	}
	return n.ParseRequest(raw)
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func write(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		os.Exit(1)
	}
}

func fail(message string) {
	// Keep failures machine-readable and content-free as well.
	write(map[string]string{"error": strings.TrimSpace(message)})
	os.Exit(2)
}

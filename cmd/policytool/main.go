// Command policytool validates and simulates the same policy contract used by
// the gateway runtime. Request bodies are read from files or stdin and are
// never echoed, logged, or included in output.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/gateway"
	"github.com/aegisllm/gateway/internal/policy"
	"github.com/aegisllm/gateway/internal/policydistribution"
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
	if command == "bundle" {
		bundleMain(os.Args[2:])
		return
	}
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

func bundleMain(args []string) {
	if len(args) == 0 {
		fail("bundle command is required: create, sign, verify, or inspect")
	}
	command := args[0]
	fs := flag.NewFlagSet("bundle "+command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	out := fs.String("out", "", "bundle directory")
	bundlePath := fs.String("bundle", "", "bundle directory")
	policyPath := fs.String("policy", "policies/enterprise-default.yaml", "policy YAML file")
	questionsPath := fs.String("questions", "", "question schema YAML file")
	thresholdsPath := fs.String("thresholds", "", "threshold YAML file")
	keyPath := fs.String("key", "", "Ed25519 private key file, or - for stdin")
	trustPath := fs.String("trust-store", "", "public trust store JSON/YAML")
	bundleID := fs.String("bundle-id", "", "bundle identifier")
	targetHash := fs.String("target-hash", "", "retained bundle hash for rollback authorization")
	sequence := fs.Uint64("sequence", 0, "monotonically increasing bundle sequence")
	issuer := fs.String("issuer", "", "issuer identifier")
	keyID := fs.String("key-id", "", "signing key identifier")
	role := fs.String("role", "aegis.operator", "operator role for rollback authorization")
	reason := fs.String("reason", "", "operator rollback reason")
	artifacts := fs.String("artifacts", "", "evaluation artifacts as name=path pairs separated by commas")
	created := fs.String("created", "", "RFC3339 creation timestamp")
	expires := fs.String("expires", "", "RFC3339 expiry timestamp")
	notBefore := fs.String("not-before", "", "RFC3339 not-before timestamp")
	minimum := fs.String("minimum-gateway-version", "", "minimum gateway version")
	environments := fs.String("environment", "", "comma-separated target environments")
	tenants := fs.String("tenant", "", "comma-separated target tenants")
	if err := fs.Parse(args[1:]); err != nil {
		fail("invalid bundle command arguments")
	}
	switch command {
	case "create":
		if *out == "" || *sequence == 0 || *issuer == "" || *keyID == "" {
			fail("create requires -out, -sequence, -issuer, and -key-id")
		}
		policyData, err := os.ReadFile(*policyPath)
		if err != nil {
			fail("policy artifact unavailable")
		}
		questionData := readOptional(*questionsPath)
		thresholdData := readOptional(*thresholdsPath)
		manifest := policydistribution.Manifest{BundleID: *bundleID, Sequence: *sequence, Issuer: *issuer, KeyID: *keyID,
			Created: *created, Expires: *expires, NotBefore: *notBefore, MinimumGatewayVersion: *minimum,
			TargetEnvironments: splitCSV(*environments), TargetTenants: splitCSV(*tenants)}
		bundle, err := policydistribution.Create(policyData, questionData, thresholdData, manifest)
		if err != nil {
			fail("bundle creation failed")
		}
		for _, item := range splitCSV(*artifacts) {
			parts := strings.SplitN(item, "=", 2)
			if len(parts) != 2 {
				fail("invalid evaluation artifact")
			}
			data, readErr := os.ReadFile(parts[1])
			if readErr != nil || policydistribution.AddFile(bundle, parts[0], data, true) != nil {
				fail("evaluation artifact unavailable")
			}
		}
		if err := policydistribution.WriteDirectory(*out, bundle); err != nil {
			fail("bundle write failed")
		}
	case "sign":
		if *bundlePath == "" || *keyPath == "" {
			fail("sign requires -bundle and -key")
		}
		bundle, err := policydistribution.ReadDirectory(*bundlePath)
		if err != nil {
			fail("bundle read failed")
		}
		keyData, err := readSecretInput(*keyPath)
		if err != nil {
			fail("private key unavailable")
		}
		privateKey, err := policydistribution.ParsePrivateKey(keyData)
		if err != nil || policydistribution.Sign(bundle, privateKey) != nil {
			fail("bundle signing failed")
		}
		destination := *out
		if destination == "" {
			destination = *bundlePath
		}
		if err := policydistribution.WriteDirectory(destination, bundle); err != nil {
			fail("signed bundle write failed")
		}
	case "verify":
		if *bundlePath == "" || *trustPath == "" {
			fail("verify requires -bundle and -trust-store")
		}
		bundle, err := policydistribution.ReadDirectory(*bundlePath)
		if err != nil {
			fail("bundle read failed")
		}
		trust := policydistribution.NewTrustStore(*trustPath)
		key, err := trust.Key(bundle.Manifest.KeyID, time.Now().UTC())
		if err != nil || bundle.Verify(key, time.Now().UTC()) != nil {
			fail("bundle verification failed")
		}
		snapshot, err := bundle.Snapshot()
		if err != nil {
			fail("bundle contract failed")
		}
		write(map[string]any{"valid": true, "bundle_id": bundle.Manifest.BundleID, "sequence": bundle.Manifest.Sequence, "bundle_hash": snapshot.BundleHash, "key_id": bundle.Manifest.KeyID})
	case "inspect":
		if *bundlePath == "" {
			fail("inspect requires -bundle")
		}
		bundle, err := policydistribution.ReadDirectory(*bundlePath)
		if err != nil {
			fail("bundle read failed")
		}
		write(map[string]any{"manifest": bundle.Manifest, "bundle_hash": bundle.Hash(), "files": bundle.SortedFileNames()})
	case "rollback":
		if *out == "" || *keyPath == "" || *keyID == "" || *sequence == 0 || (*targetHash == "" && *bundleID == "") {
			fail("rollback requires -out, -key, -key-id, -sequence, and -target-hash")
		}
		keyData, err := readSecretInput(*keyPath)
		if err != nil {
			fail("private key unavailable")
		}
		privateKey, err := policydistribution.ParsePrivateKey(keyData)
		if err != nil {
			fail("private key unavailable")
		}
		hash := *targetHash
		if hash == "" {
			hash = *bundleID
		}
		authz := policydistribution.Authorization{Version: 1, Action: "rollback", TargetSequence: *sequence, TargetHash: hash, Reason: *reason, Role: *role, Issuer: *issuer, KeyID: *keyID, Issued: time.Now().UTC().Format(time.RFC3339Nano)}
		if authz.Reason == "" {
			fail("rollback requires -reason")
		}
		if err := policydistribution.SignAuthorization(&authz, privateKey); err != nil {
			fail("rollback authorization failed")
		}
		payload := map[string]any{"version": authz.Version, "action": authz.Action, "target_sequence": authz.TargetSequence, "target_hash": authz.TargetHash, "reason": authz.Reason, "role": authz.Role, "issuer": authz.Issuer, "key_id": authz.KeyID, "issued": authz.Issued, "signature": base64.StdEncoding.EncodeToString(authz.Signature)}
		data, _ := json.Marshal(payload)
		data = append(data, '\n')
		if err := os.WriteFile(filepath.Clean(*out), data, 0600); err != nil {
			fail("rollback authorization write failed")
		}
	default:
		fail("unknown bundle command")
	}
}

func readSecretInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(filepath.Clean(path))
}

func readOptional(path string) []byte {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fail("optional artifact unavailable")
	}
	return data
}

func splitCSV(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
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

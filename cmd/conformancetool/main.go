// Command conformancetool runs the versioned, privacy-safe provider lab.
// It never accepts credential values on the command line.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/aegisllm/gateway/internal/conformance"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "conformancetool: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("command is required: run, list, validate-report, compare, or update-fixtures")
	}
	switch args[0] {
	case "run":
		return runCommand(args[1:])
	case "list":
		return listCommand(args[1:])
	case "validate-report":
		return validateCommand(args[1:])
	case "compare":
		return compareCommand(args[1:])
	case "update-fixtures":
		return updateFixturesCommand(args[1:])
	default:
		return errors.New("unknown command")
	}
}

func specFlag(fs *flag.FlagSet) *string {
	return fs.String("spec", "conformance/spec/v1.yaml", "versioned conformance specification")
}
func loadSpec(path string) (conformance.Specification, error) {
	if _, err := os.Stat(path); err != nil {
		return conformance.DefaultSpecification(), nil
	}
	return conformance.LoadSpecification(path)
}

func runCommand(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	target := fs.String("target", os.Getenv("CONFORMANCE_TARGET"), "gateway base URL")
	specPath := specFlag(fs)
	reportPath := fs.String("report", "conformance-report.json", "JSON report path")
	junitPath := fs.String("junit", "conformance-report.xml", "JUnit report path")
	authPath := fs.String("auth-file", os.Getenv("CONFORMANCE_AUTH_FILE"), "credential descriptor path (values remain in env/files)")
	profiles := fs.String("profiles", "", "comma-separated profile filter")
	timeout := fs.Duration("timeout", 15*time.Second, "per-request timeout")
	ca := fs.String("ca-file", "", "CA bundle path")
	cert := fs.String("client-cert", "", "mTLS client certificate path")
	key := fs.String("client-key", "", "mTLS client key path")
	serverName := fs.String("server-name", "", "TLS server name")
	gatewayCommit := fs.String("gateway-commit", os.Getenv("GATEWAY_COMMIT"), "sanitized gateway commit/version metadata")
	gatewayVersion := fs.String("gateway-version", os.Getenv("GATEWAY_VERSION"), "gateway version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" {
		return errors.New("--target or CONFORMANCE_TARGET is required")
	}
	spec, err := loadSpec(*specPath)
	if err != nil {
		return err
	}
	auth, err := conformance.LoadAuth(*authPath)
	if err != nil {
		return err
	}
	filter := parseFilter(*profiles)
	report, err := conformance.Run(context.Background(), spec, conformance.RunnerOptions{Target: *target, Timeout: *timeout, Auth: auth, CAFile: *ca, CertFile: *cert, KeyFile: *key, ServerName: *serverName, Gateway: conformance.GatewayInfo{Commit: sanitizeMetadata(*gatewayCommit), Version: sanitizeMetadata(*gatewayVersion)}}, filter)
	if err != nil {
		return err
	}
	data, err := conformance.MarshalDeterministic(report)
	if err != nil {
		return err
	}
	if err := conformance.WriteFile(*reportPath, append(data, '\n')); err != nil {
		return err
	}
	if err := conformance.WriteFile(*reportPath+".sha256", []byte(conformance.ArtifactSHA256(append(data, '\n'))+"\n")); err != nil {
		return err
	}
	if err := conformance.WriteFile(*junitPath, conformance.WriteJUnit(report)); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "conformance report=%s junit=%s required_pass=%d required_fail=%d required_skip=%d\n", safeName(*reportPath), safeName(*junitPath), report.Required.Passed, report.Required.Failed, report.Required.Skipped)
	if report.Required.Failed > 0 || report.Required.Skipped > 0 {
		return errors.New("required conformance cases did not pass")
	}
	return nil
}

func listCommand(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	sp := specFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	spec, err := loadSpec(*sp)
	if err != nil {
		return err
	}
	for _, p := range spec.Profiles {
		fmt.Printf("%s\tfamily=%s\tstream=%t\ttools=%t\trequired=%t\t%s\n", p.ID, p.Family, p.Streaming, p.Tools, p.Required, p.Description)
	}
	fmt.Println("unsupported fields:")
	for _, u := range spec.Unsupported {
		fmt.Printf("%s\t%s\t%s\n", u.Profile, u.Field, u.Behavior)
	}
	return nil
}

func validateCommand(args []string) error {
	fs := flag.NewFlagSet("validate-report", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	path := fs.String("report", "", "JSON report path")
	junit := fs.String("junit", "", "optional JUnit path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("--report is required")
	}
	r, err := conformance.LoadReport(*path)
	if err != nil {
		return err
	}
	if *junit != "" {
		if info, e := os.Stat(*junit); e != nil || info.Size() == 0 {
			return errors.New("JUnit report is missing or empty")
		}
	}
	if checksum, e := os.ReadFile(*path + ".sha256"); e == nil && strings.TrimSpace(string(checksum)) != conformance.ArtifactSHA256(mustRead(*path)) {
		return errors.New("report artifact hash does not match")
	}
	fmt.Printf("valid report schema=%s cases=%d\n", r.SchemaVersion, len(r.Cases))
	if r.Required.Failed > 0 || r.Required.Skipped > 0 {
		return errors.New("required failures or skips are not valid certification")
	}
	return nil
}

func mustRead(path string) []byte { data, _ := os.ReadFile(path); return data }

func compareCommand(args []string) error {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	base := fs.String("baseline", "", "baseline JSON report")
	candidate := fs.String("candidate", "", "candidate JSON report")
	outPath := fs.String("report", "conformance-compare.json", "comparison report")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *base == "" || *candidate == "" {
		return errors.New("--baseline and --candidate are required")
	}
	b, err := conformance.LoadReport(*base)
	if err != nil {
		return err
	}
	c, err := conformance.LoadReport(*candidate)
	if err != nil {
		return err
	}
	diff := conformance.Compare(b, c)
	data, err := conformance.MarshalCompare(diff)
	if err != nil {
		return err
	}
	if err := conformance.WriteFile(*outPath, append(data, '\n')); err != nil {
		return err
	}
	fmt.Printf("comparison report=%s semantic_diffs=%d latency_delta_ms=%d\n", safeName(*outPath), len(diff.SemanticDiffs), diff.LatencyDeltaMS)
	if len(diff.SemanticDiffs) > 0 {
		return errors.New("semantic regression detected")
	}
	return nil
}

func updateFixturesCommand(args []string) error {
	fs := flag.NewFlagSet("update-fixtures", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	report := fs.String("report", "", "validated report path")
	dir := fs.String("dir", "conformance/fixtures", "fixture directory")
	confirm := fs.Bool("confirm", false, "required explicit confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*confirm {
		return errors.New("fixture updates require --confirm and a reviewed report")
	}
	r, err := conformance.LoadReport(*report)
	if err != nil {
		return err
	}
	for _, c := range r.Cases {
		data, _ := json.MarshalIndent(c.Response.Semantic, "", "  ")
		if err := conformance.WriteFile(*dir+"/"+safeName(c.ID)+".json", append(data, '\n')); err != nil {
			return err
		}
	}
	fmt.Printf("updated fixtures dir=%s cases=%d\n", safeName(*dir), len(r.Cases))
	return nil
}

func parseFilter(value string) map[string]bool {
	out := map[string]bool{}
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out[item] = true
		}
	}
	return out
}
func sanitizeMetadata(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 64 {
		value = value[:64]
	}
	for i, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._-", r) {
			continue
		}
		value = value[:i] + "_" + value[i+len(string(r)):]
	}
	return value
}
func safeName(value string) string {
	value = strings.ReplaceAll(value, "\\", "/")
	if i := strings.LastIndex(value, "/"); i >= 0 {
		value = value[i+1:]
	}
	if value == "" {
		return "report"
	}
	return value
}

var _ = debug.ReadBuildInfo

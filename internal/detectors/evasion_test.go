package detectors

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aegisllm/gateway/internal/core"
)

func TestEvasionDetectsBoundedEncodingVariants(t *testing.T) {
	secret := "sk-abcdefghijklmnopqrstuvwxyz123456"
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	urlsafe := base64.RawURLEncoding.EncodeToString([]byte(secret))
	percent := strings.NewReplacer("s", "%73", "k", "%6b", "-", "%2d").Replace(secret)
	reg := NewRegistry(nil)
	for _, d := range SecretDetectors("") {
		reg.Register(d)
	}
	for _, input := range []string{encoded, urlsafe, percent} {
		findings := reg.RunAll(envelopeWith(input))
		found := false
		for _, f := range findings {
			if f.Category == core.CategorySecret && f.Subtype == SubtypeOpenAIAPIKey && f.Attributes["unsafe_span"] == "true" {
				found = true
				if f.Attributes["encoding_chain"] == "" {
					t.Fatal("encoded finding lacks bounded encoding metadata")
				}
			}
		}
		if !found {
			t.Fatalf("encoded secret was not detected: %q findings=%+v", input, findings)
		}
	}
}

func TestEvasionMapsUnicodeAndFailsClosedAcrossParts(t *testing.T) {
	secret := "sk-abcdefghijklmnopqrstuvwxyz123456"
	fullwidth := strings.NewReplacer("s", "ｓ", "k", "ｋ", "-", "－").Replace(secret)
	zeroWidth := strings.ReplaceAll(secret, "", "\u200b")
	zeroWidth = strings.Trim(zeroWidth, "\u200b")
	reg := NewRegistry(nil)
	for _, d := range SecretDetectors("") {
		reg.Register(d)
	}

	for _, input := range []string{fullwidth, zeroWidth} {
		findings := reg.RunAll(envelopeWith(input))
		var got *core.SecurityFinding
		for i := range findings {
			if findings[i].Subtype == SubtypeOpenAIAPIKey && findings[i].Attributes["unsafe_span"] != "true" {
				got = &findings[i]
				break
			}
		}
		if got == nil {
			t.Fatalf("normalized secret not found with safe span: %q findings=%+v", input, findings)
		}
		if got.Location.Start != 0 || got.Location.End != len(input) {
			t.Fatalf("span %v does not map to original bytes %d", got.Location, len(input))
		}
	}

	env := &core.InspectionEnvelope{RequestID: "split", Messages: []core.Message{{Parts: []core.ContentPart{{Type: core.PartText, Text: "sk-"}, {Type: core.PartText, Text: secret[3:]}}}}}
	findings := reg.RunAll(env)
	for _, f := range findings {
		if f.Subtype == SubtypeOpenAIAPIKey && f.Attributes["unsafe_span"] == "true" && f.Attributes["evasion_type"] == "cross_part" {
			return
		}
	}
	t.Fatal("cross-part secret was not marked unsafe")
}

func TestEvasionStructuredLimitsAndCancellation(t *testing.T) {
	reg := NewRegistry(nil)
	for _, d := range SecretDetectors("") {
		reg.Register(d)
	}
	json := `{"outer":{"inner":{"value":"\u0073\u006b\u002d\u0061\u0062\u0063\u0064\u0065\u0066\u0067\u0068\u0069\u006a\u006b\u006c\u006d\u006e\u006f\u0070\u0071\u0072\u0073\u0074\u0075\u0076\u0077\u0078\u0079\u007a\u0031\u0032\u0033\u0034\u0035\u0036"}}}`
	findings := reg.RunAll(envelopeWith(json))
	found := false
	for _, f := range findings {
		if f.Subtype == SubtypeOpenAIAPIKey && f.Attributes["evasion_type"] == "structured_json" {
			found = true
		}
	}
	if !found {
		t.Fatal("escaped JSON secret was not detected")
	}

	cfg := DefaultEvasionConfig()
	cfg.MaxJSONNodes = 1
	findings = reg.RunAllContext(context.Background(), envelopeWith(json), cfg)
	budget := false
	for _, f := range findings {
		if f.Attributes["evasion_type"] == "budget_exceeded" {
			budget = true
		}
	}
	if !budget {
		t.Fatal("JSON node budget rejection was not emitted")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := reg.RunAllContext(ctx, envelopeWith("sk-abcdefghijklmnopqrstuvwxyz123456"), DefaultEvasionConfig()); len(got) != 0 {
		t.Fatalf("canceled scan produced findings: %+v", got)
	}
}

func TestEvasionBenignCorpusDoesNotFlagNormalTextAndUUID(t *testing.T) {
	reg := NewRegistry(nil)
	for _, d := range SecretDetectors("") {
		reg.Register(d)
	}
	for _, input := range []string{
		"สวัสดีครับ นี่คือข้อความภาษาไทยปกติ",
		"Hello, this is ordinary English text.",
		"request id 550e8400-e29b-41d4-a716-446655440000",
		base64.StdEncoding.EncodeToString([]byte("a normal documentation example")),
	} {
		for _, f := range reg.RunAll(envelopeWith(input)) {
			if f.Category == core.CategorySecret {
				t.Fatalf("benign corpus secret finding for %q: %+v", input, f)
			}
		}
	}
}

func FuzzEvasionScannerNoPanic(f *testing.F) {
	f.Add("hello %73%6b-plain")
	f.Add("\u200bｓκ-encoded")
	f.Add("{\"nested\":\"\\u0073\\u006b\\u002dvalue\"}")
	reg := NewRegistry(nil)
	for _, d := range SecretDetectors("") {
		reg.Register(d)
	}
	f.Fuzz(func(t *testing.T, input string) {
		cfg := DefaultEvasionConfig()
		cfg.MaxDecodeWorkBytes = 4096
		cfg.MaxCandidateBytes = 1024
		_ = reg.RunAllContext(context.Background(), envelopeWith(input), cfg)
	})
}

func TestP14EvaluationCorpus(t *testing.T) {
	file, err := os.Open(filepath.Join("..", "..", "evals", "datasets", "evasion-p1.4.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reg := NewRegistry(nil)
	for _, d := range SecretDetectors("") {
		reg.Register(d)
	}
	scanner := bufio.NewScanner(file)
	line := 0
	for scanner.Scan() {
		line++
		var row struct{ ID, Text, Expected string }
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatalf("line %d: %v", line, err)
		}
		secret := false
		for _, finding := range reg.RunAll(envelopeWith(row.Text)) {
			if finding.Category == core.CategorySecret {
				secret = true
				break
			}
		}
		want := row.Expected == "SECRET"
		if secret != want {
			t.Errorf("%s: secret=%v want=%v", row.ID, secret, want)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

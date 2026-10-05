package detectors

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aegisllm/gateway/internal/core"
)

func envelopeWith(text string) *core.InspectionEnvelope {
	return &core.InspectionEnvelope{
		RequestID: "req-test",
		Direction: core.DirectionRequest,
		Messages: []core.Message{
			{Role: core.RoleUser, Parts: []core.ContentPart{{Type: core.PartText, Text: text}}},
		},
	}
}

func TestGitLabPATDetector(t *testing.T) {
	d := SecretDetectors("")[0]
	cases := []struct {
		text  string
		match bool
	}{
		{"use this token glpat-Abc123Xyz_-456DefGhi please", true},
		{"glpat-0123456789abcdefghij", true},
		{"glpat-short", false},
		{"glpat-", false},
		{"a gitlab pat looks like glpat followed by chars", false},
	}
	for _, tc := range cases {
		got := d.Detect(envelopeWith(tc.text))
		if (len(got) > 0) != tc.match {
			t.Errorf("text %q: matches=%d want match=%v", tc.text, len(got), tc.match)
		}
		if tc.match && got[0].Subtype != SubtypeGitLabPAT {
			t.Errorf("subtype: %s", got[0].Subtype)
		}
	}
}

func TestGitHubTokenDetector(t *testing.T) {
	d := SecretDetectors("")[1]
	cases := []struct {
		text  string
		match bool
	}{
		{"token ghp_0123456789abcdefghijklmnopqrstuv end", true},
		{"oauth gho_0123456789abcdefghijklmnopqrstuv", true},
		{"ghp_123 too short", false},
		{"github tokens are prefixed", false},
	}
	for _, tc := range cases {
		got := d.Detect(envelopeWith(tc.text))
		if (len(got) > 0) != tc.match {
			t.Errorf("text %q: matches=%d want match=%v", tc.text, len(got), tc.match)
		}
	}
}

func TestPEMPrivateKeyDetector(t *testing.T) {
	d := SecretDetectors("")[2]
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIB\nmore\nlines\n-----END RSA PRIVATE KEY-----"
	openssh := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END OPENSSH PRIVATE KEY-----"
	neg := "-----BEGIN CERTIFICATE-----\nnotakey\n-----END CERTIFICATE-----"
	for _, text := range []string{"key:\n" + pem, "prefix " + openssh + " suffix"} {
		got := d.Detect(envelopeWith(text))
		if len(got) != 1 {
			t.Errorf("expected match for %q", text[:40])
		}
	}
	if got := d.Detect(envelopeWith(neg)); len(got) != 0 {
		t.Errorf("certificate must not match private key: %d", len(got))
	}
	if got := d.Detect(envelopeWith(pem)); got[0].Location.End <= got[0].Location.Start {
		t.Error("span must cover the block")
	}
}

func TestJWTDetector(t *testing.T) {
	d := SecretDetectors("")[3]
	valid := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	if got := d.Detect(envelopeWith("auth " + valid + " end")); len(got) != 1 {
		t.Fatalf("expected jwt match, got %d", len(got))
	}
	for _, neg := range []string{"eyJabc.def", "not a jwt at all", "eyJhbGciOiJIUzI1NiJ9.two.segments"} {
		if got := d.Detect(envelopeWith(neg)); len(got) != 0 {
			t.Errorf("%q must not match", neg)
		}
	}
}

func TestBearerTokenDetector(t *testing.T) {
	d := SecretDetectors("")[4]
	if got := d.Detect(envelopeWith("Authorization: Bearer abcdefghijklmnop123456789")); len(got) != 1 {
		t.Fatalf("expected bearer match, got %d", len(got))
	}
	for _, neg := range []string{"bearer is just a word here", "Bearer tokens", "BEARER short"} {
		if got := d.Detect(envelopeWith(neg)); len(got) != 0 {
			t.Errorf("%q must not match", neg)
		}
	}
}

func TestFindingsNeverCarryRawValue(t *testing.T) {
	d := SecretDetectors("")[0]
	findings := d.Detect(envelopeWith("token glpat-Abc123Xyz_-456DefGhi here"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	b := mustFindingsJSON(t, findings)
	if strings.Contains(b, "glpat-Abc123Xyz") {
		t.Fatal("finding serialization leaked the raw secret")
	}
	if !strings.Contains(b, "GITLAB_PAT") {
		t.Fatal("finding must record the subtype")
	}
}

func TestHashValueStableAndKeyed(t *testing.T) {
	h1 := HashValue("telemetry-key", "glpat-value")
	h2 := HashValue("telemetry-key", "glpat-value")
	h3 := HashValue("other-key", "glpat-value")
	if h1 == "" || h1 != h2 {
		t.Fatal("hash must be deterministic under the same key")
	}
	if h1 == h3 {
		t.Fatal("hash must depend on the telemetry key")
	}
	if HashValue("", "glpat-value") != "" {
		t.Fatal("empty key disables hashing")
	}
}

func TestRegistryRunsInOrderTimesAndAssignsIDs(t *testing.T) {
	var order []string
	reg := NewRegistry(func(name string, d time.Duration) {
		order = append(order, name)
		if d < 0 {
			t.Error("negative duration")
		}
	})
	for _, d := range SecretDetectors("") {
		reg.Register(d)
	}
	env := envelopeWith("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c and glpat-0123456789abcdefghij")
	findings := reg.RunAll(env)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if len(order) != 8 {
		t.Fatalf("timing hook called %d times, want 8", len(order))
	}
	if findings[0].ID == "" || findings[0].ID == findings[1].ID {
		t.Fatalf("finding ids not assigned: %q %q", findings[0].ID, findings[1].ID)
	}
	if !strings.HasPrefix(findings[0].ID, "finding-req-test-") {
		t.Fatalf("id not request-scoped: %s", findings[0].ID)
	}
}

func mustFindingsJSON(t *testing.T, fs []core.SecurityFinding) string {
	t.Helper()
	b, err := json.Marshal(fs)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

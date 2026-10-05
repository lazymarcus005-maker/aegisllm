package detectors

import (
	"fmt"
	"sort"
	"testing"
	"time"
)

// Synthetic checksum-valid fixtures (T-007: never use real citizen IDs).
// "123456789012" + computed check digit 1 => "1234567890121"
// "111111111111" + computed check digit 9 => "1111111111119"
const (
	validCitizenIDPlain = "1234567890121"
	validCitizenIDOnes  = "1111111111119"
)

func TestThaiCitizenIDDetection(t *testing.T) {
	d := newThaiCitizenIDDetector("")
	cases := []struct {
		name string
		text string
		want bool
	}{
		{"plain", "id " + validCitizenIDPlain + " end", true},
		{"separated", "เลขบัตร 1-2345-67890-12-1 ค่ะ", true},
		{"second fixture", validCitizenIDOnes, true},
		{"bad checksum", "id 1234567890123 end", false},
		{"all nines", "9999999999999", false},
		{"too short", "123456789012", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := d.Detect(envelopeWith(tc.text))
			if (len(got) > 0) != tc.want {
				t.Fatalf("text %q: findings=%d want=%v", tc.text, len(got), tc.want)
			}
			if tc.want && got[0].Subtype != SubtypeThaiCitizenID {
				t.Fatalf("subtype: %s", got[0].Subtype)
			}
		})
	}
}

func TestThaiCitizenIDChecksumFunction(t *testing.T) {
	if !ThaiCitizenIDValid(validCitizenIDPlain) || !ThaiCitizenIDValid(validCitizenIDOnes) {
		t.Fatal("fixtures must be checksum-valid")
	}
	if ThaiCitizenIDValid("1234567890123") || ThaiCitizenIDValid("12345") {
		t.Fatal("invalid values accepted")
	}
}

func TestPhoneDetection(t *testing.T) {
	ds := PiiDetectors("")
	d := ds[1]
	cases := []struct {
		text  string
		match bool
	}{
		{"โทร 0812345678 ค่ะ", true},
		{"081-234-5678", true},
		{"+66 81 234 5678", true},
		{"office 0223456789", true},
		{"1234567890", false},
		{"no phone here", false},
	}
	for _, tc := range cases {
		got := d.Detect(envelopeWith(tc.text))
		if (len(got) > 0) != tc.match {
			t.Errorf("text %q: findings=%d want=%v", tc.text, len(got), tc.match)
			continue
		}
		if tc.match && got[0].Subtype != SubtypePhoneNumber {
			t.Errorf("subtype: %s", got[0].Subtype)
		}
	}
}

func TestEmailDetection(t *testing.T) {
	d := PiiDetectors("")[2]
	if got := d.Detect(envelopeWith("mail somchai.jaidee@example.co.th end")); len(got) != 1 {
		t.Fatalf("expected email finding, got %d", len(got))
	}
	if got := d.Detect(envelopeWith("not an email address")); len(got) != 0 {
		t.Fatalf("false positive: %+v", got)
	}
}

func TestCreditCardDetection(t *testing.T) {
	d := newCreditCardDetector("")
	// 4111 1111 1111 1111 is the canonical synthetic Visa test number.
	if got := d.Detect(envelopeWith("card 4111 1111 1111 1111 end")); len(got) != 1 {
		t.Fatalf("expected card finding, got %d", len(got))
	}
	negatives := []string{
		"4111111111111112",  // Luhn fail
		validCitizenIDPlain, // valid citizen ID must not double-report
		"1234567890123",     // 13 digits, fails both checksums
		"just some digits 123456",
	}
	for _, neg := range negatives {
		if got := d.Detect(envelopeWith(neg)); len(got) != 0 {
			t.Errorf("%q must not match", neg)
		}
	}
}

func TestIPDetection(t *testing.T) {
	d := newIPDetector("")
	if got := d.Detect(envelopeWith("server 192.168.1.1 and 2001:0db8:85a3:0000:0000:8a2e:0370:7334")); len(got) != 2 {
		t.Fatalf("expected 2 ip findings, got %d", len(got))
	}
	for _, neg := range []string{"999.999.999.999", "version 1.2.3 note", "no ip"} {
		if got := d.Detect(envelopeWith(neg)); len(got) != 0 {
			t.Errorf("%q must not match", neg)
		}
	}
	got := d.Detect(envelopeWith("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
	if got[0].Attributes["ip_version"] != "6" {
		t.Fatalf("ip version attribute: %+v", got[0].Attributes)
	}
}

func TestAWSAccessKeyDetection(t *testing.T) {
	d := SecretDetectors("")[5]
	if got := d.Detect(envelopeWith("key AKIAIOSFODNN7EXAMPLE end")); len(got) != 1 {
		t.Fatalf("expected aws key finding, got %d", len(got))
	}
	if got := d.Detect(envelopeWith("AKIA123 short")); len(got) != 0 {
		t.Fatalf("false positive: %+v", got)
	}
}

func TestConnectionStringDetection(t *testing.T) {
	d := SecretDetectors("")[6]
	positives := []string{
		"postgres://admin:s3cret@db.internal:5432/app",
		"mysql://root:hunter2@localhost/db",
		"mongodb+srv://user:pass@cluster.example.net/db",
		"rediss://:pass@cache.internal:6379/0",
	}
	for _, p := range positives {
		if got := d.Detect(envelopeWith("conn " + p + " end")); len(got) != 1 {
			t.Errorf("%q must match", p)
		}
	}
	negatives := []string{
		"postgres://db.internal:5432/app", // no password
		"https://user:pass@example.com",   // not a data-store scheme
		"see https://example.com/docs",
	}
	for _, n := range negatives {
		if got := d.Detect(envelopeWith(n)); len(got) != 0 {
			t.Errorf("%q must not match", n)
		}
	}
}

func TestHighEntropySecretWithAndWithoutContext(t *testing.T) {
	d := SecretDetectors("")[7]
	token := "xK9mQ2vN8pLwR3zT6uY1aB4cD7eF0gH"
	if got := d.Detect(envelopeWith("password: " + token + " (rotate soon)")); len(got) != 1 {
		t.Fatalf("expected high-entropy finding near context, got %d", len(got))
	}
	negatives := []string{
		token, // no context keyword
		"password aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // low entropy
		"password: short", // too short
	}
	for _, neg := range negatives {
		if got := d.Detect(envelopeWith(neg)); len(got) != 0 {
			t.Errorf("%q must not match", neg)
		}
	}
}

// NFR-PERF-001: deterministic scanning target p95 <= 10 ms for typical text
// payloads, measured in the test harness. "Typical" here: ~2 KB of mixed
// prose containing several candidates, full detector set.
func TestDeterministicScanLatencyTarget(t *testing.T) {
	registry := NewRegistry(nil)
	for _, d := range SecretDetectors("") {
		registry.Register(d)
	}
	for _, d := range PiiDetectors("") {
		registry.Register(d)
	}
	text := "Customer somchai.jaidee@example.co.th called from 081-234-5678 about server 10.0.0.7. " +
		"His card 4111 1111 1111 1111 was declined; citizen id 1-2345-67890-12-1 verified. " +
		"The db password xK9mQ2vN8pLwR3zT6uY1aB4cD7eF0gH must be rotated. " +
		"Please check the postgres://admin:s3cret@db.internal:5432/app connection and the bearer ABCDEFGHIJKLMNOP123456 token. "
	payload := make([]byte, 0, 2048)
	for len(payload) < 2048 {
		payload = append(payload, text...)
	}
	env := envelopeWith(string(payload))

	var durations []time.Duration
	for i := 0; i < 30; i++ {
		start := time.Now()
		findings := registry.RunAll(env)
		d := time.Since(start)
		durations = append(durations, d)
		if i == 0 && len(findings) < 5 {
			t.Fatalf("payload should produce findings, got %d", len(findings))
		}
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p95 := durations[(len(durations)*95)/100]
	if p95 > 10*time.Millisecond {
		t.Fatalf("p95 scan latency %v exceeds 10ms target", p95)
	}
	t.Logf(fmt.Sprintf("p95 deterministic scan: %v", p95))
}

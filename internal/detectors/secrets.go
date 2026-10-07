package detectors

import (
	"math"
	"regexp"
	"strings"

	"github.com/aegisllm/gateway/internal/core"
)

// Secret subtypes (FR-004).
const (
	SubtypeGitLabPAT         = "GITLAB_PAT"
	SubtypeGitHubToken       = "GITHUB_TOKEN"
	SubtypePEMPrivateKey     = "PEM_PRIVATE_KEY"
	SubtypeJWT               = "JWT"
	SubtypeBearerToken       = "BEARER_TOKEN"
	SubtypeAWSAccessKey      = "AWS_ACCESS_KEY"
	SubtypeAWSSecret         = "AWS_SECRET_ACCESS_KEY"
	SubtypeOpenAIAPIKey      = "OPENAI_API_KEY"
	SubtypeAnthropicAPIKey   = "ANTHROPIC_API_KEY"
	SubtypeSlackToken        = "SLACK_TOKEN"
	SubtypeGoogleAPIKey      = "GOOGLE_API_KEY"
	SubtypeGenericAPIKey     = "GENERIC_API_KEY"
	SubtypeConnectionString  = "CONNECTION_STRING"
	SubtypeHighEntropySecret = "HIGH_ENTROPY_SECRET"
)

// PII subtypes (FR-005).
const (
	SubtypeThaiCitizenID = "TH_CITIZEN_ID"
	SubtypePhoneNumber   = "PHONE_NUMBER"
	SubtypeEmail         = "EMAIL"
	SubtypeCreditCard    = "CREDIT_CARD"
	SubtypeIPAddress     = "IP_ADDRESS"
)

// SecretDetectors returns the full ticket-02/04 secret detector set.
// telemetryKey is the dedicated HMAC key for finding correlation (may be empty).
func SecretDetectors(telemetryKey string) []Detector {
	mkp := func(name, subtype string, conf float64, patterns ...string) Detector {
		return &patternDetector{
			name: name, subtype: subtype, category: core.CategorySecret,
			res: compile(patterns...), confidence: conf, telemetryHMAC: telemetryKey,
		}
	}
	return []Detector{
		mkp("gitlab-pat", SubtypeGitLabPAT, 1.0, `(?i)\bglpat-[0-9a-z_-]{20,}\b`),
		mkp("github-token", SubtypeGitHubToken, 1.0, `(?i)\bgh[pousr]_[0-9a-z]{20,}\b`),
		mkp("pem-private-key", SubtypePEMPrivateKey, 1.0,
			`(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----.*?-----END [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----`),
		mkp("jwt", SubtypeJWT, 1.0, `\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b`),
		mkp("bearer-token", SubtypeBearerToken, 0.95, `(?i)\bbearer\s+[A-Za-z0-9._+=/-]{16,}`),
		mkp("aws-access-key", SubtypeAWSAccessKey, 1.0, `\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`),
		mkp("connection-string", SubtypeConnectionString, 0.95,
			`(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|mssql|oracle):\/\/[^\s:@\/]*:[^\s@]+@[^\s]+`),
		newContextEntropyDetector(telemetryKey),
		mkp("openai-api-key", SubtypeOpenAIAPIKey, 1.0, `(?i)\bsk-[a-z0-9]{20,}\b`, `(?i)\bsk-proj-[a-z0-9_-]{20,}\b`),
		mkp("anthropic-api-key", SubtypeAnthropicAPIKey, 1.0, `(?i)\bsk-ant-[a-z0-9_-]{20,}\b`),
		mkp("aws-secret-access-key", SubtypeAWSSecret, 1.0,
			`(?i)\bAWS_SECRET_ACCESS_KEY\b\s*[:=]\s*["']?[A-Za-z0-9/+=]{32,64}["']?`),
		mkp("slack-token", SubtypeSlackToken, 1.0, `(?i)\bxox(?:b|p|a|r|s)-[0-9a-z-]{10,}\b`),
		mkp("google-api-key", SubtypeGoogleAPIKey, 1.0, `\bAIza[A-Za-z0-9_-]{20,}\b`),
		mkp("generic-api-key", SubtypeGenericAPIKey, 0.95,
			`(?i)\b(?:api[_-]?key|x-api-key|client[_-]?secret)\b\s*[:=]\s*["']?[A-Za-z0-9._~+/=-]{20,}["']?`),
	}
}

// contextEntropyDetector flags long high-entropy candidate tokens that appear
// near credential-ish context keywords (T-006 "generic high-entropy secret
// with context"). Confidence is intentionally moderate; policy decides.
type contextEntropyDetector struct {
	telemetryHMAC string
	tokenRe       *regexp.Regexp
	contextRe     *regexp.Regexp
	window        int
	minEntropy    float64
}

var structuredSecretValueRe = regexp.MustCompile(`(?i)(?:aws_secret_access_key|api[_-]?key|x-api-key|client[_-]?secret)\s*[:=]\s*["']?$`)

func newContextEntropyDetector(telemetryKey string) *contextEntropyDetector {
	return &contextEntropyDetector{
		telemetryHMAC: telemetryKey,
		tokenRe:       regexp.MustCompile(`[A-Za-z0-9+/_-]{20,}`),
		contextRe:     regexp.MustCompile(`(?i)(password|passwd|secret|token|api[-_]?key|apikey|credential|private[-_]?key|access[-_]?key|auth)`),
		window:        60,
		minEntropy:    4.5,
	}
}

func (d *contextEntropyDetector) Name() string { return "high-entropy-secret" }

func (d *contextEntropyDetector) Detect(env *core.InspectionEnvelope) []core.SecurityFinding {
	var out []core.SecurityFinding
	for _, lt := range env.TextParts() {
		contexts := d.contextRe.FindAllStringIndex(lt.Text, -1)
		if len(contexts) == 0 {
			continue
		}
		for _, loc := range d.tokenRe.FindAllStringIndex(lt.Text, -1) {
			if !nearContext(loc[0], contexts, d.window) {
				continue
			}
			if structuredSecretValue(lt.Text, loc[0]) {
				continue // a structured detector owns this value
			}
			value := lt.Text[loc[0]:loc[1]]
			if hasSpecificSecretPrefix(value) {
				continue // a specific detector owns this span; avoid double reporting
			}
			if isEntropyAllowlisted(value) || !hasMixedCharset(value) || shannonEntropy(value) <= d.minEntropy {
				continue
			}
			f := (&patternDetector{
				subtype: SubtypeHighEntropySecret, category: core.CategorySecret, confidence: 0.7,
				telemetryHMAC: d.telemetryHMAC,
			}).finding(lt, loc, value)
			out = append(out, f)
		}
	}
	return out
}

func structuredSecretValue(text string, start int) bool {
	from := start - 96
	if from < 0 {
		from = 0
	}
	prefix := text[from:start]
	return structuredSecretValueRe.MatchString(prefix)
}

// hasSpecificSecretPrefix reports tokens already owned by a specific
// detector family so the generic entropy detector does not double-report.
func hasSpecificSecretPrefix(value string) bool {
	for _, p := range []string{"eyJ", "glpat-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "AKIA", "ASIA", "ABIA", "ACCA", "sk-", "sk-ant-", "xox", "AIza"} {
		if strings.HasPrefix(strings.ToLower(value), strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func hasMixedCharset(value string) bool {
	var lower, upper, digit, symbol bool
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			symbol = true
		}
	}
	classes := 0
	for _, present := range []bool{lower, upper, digit, symbol} {
		if present {
			classes++
		}
	}
	return classes >= 3
}

func isEntropyAllowlisted(value string) bool {
	switch strings.ToLower(value) {
	case "hello", "hello-world", "example-secret", "test-secret":
		return true
	}
	if len(value) == 36 && value[8] == '-' && value[13] == '-' && value[18] == '-' && value[23] == '-' {
		for i, r := range value {
			if i == 8 || i == 13 || i == 18 || i == 23 {
				continue
			}
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
				return false
			}
		}
		return true
	}
	return false
}

func nearContext(tokenStart int, contexts [][]int, window int) bool {
	for _, c := range contexts {
		// context before or overlapping the token within the window
		if tokenStart >= c[0]-window && tokenStart <= c[1]+window {
			return true
		}
	}
	return false
}

// shannonEntropy computes bits of entropy per character.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	var sum float64
	n := float64(len([]rune(s)))
	for _, c := range counts {
		p := float64(c) / n
		sum -= p * math.Log2(p)
	}
	return sum
}

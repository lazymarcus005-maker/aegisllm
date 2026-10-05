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

// patternDetector finds matches for compiled rules across all text parts.
// It is the shared engine for the secret and PII pattern families.
type patternDetector struct {
	name          string
	subtype       string
	category      core.FindingCategory
	res           []*regexp.Regexp
	confidence    float64
	telemetryHMAC string
}

func (p *patternDetector) Name() string { return p.name }

func (p *patternDetector) Detect(env *core.InspectionEnvelope) []core.SecurityFinding {
	var out []core.SecurityFinding
	for _, lt := range env.TextParts() {
		for _, re := range p.res {
			for _, loc := range re.FindAllStringIndex(lt.Text, -1) {
				value := lt.Text[loc[0]:loc[1]]
				out = append(out, p.finding(lt, loc, value))
			}
		}
	}
	return out
}

func (p *patternDetector) finding(lt core.LocatedText, loc []int, value string) core.SecurityFinding {
	return core.SecurityFinding{
		Category:   p.category,
		Subtype:    p.subtype,
		Detector:   "pattern",
		Confidence: p.confidence,
		Location: core.Span{
			MessageIndex: lt.MessageIndex,
			PartIndex:    lt.PartIndex,
			Start:        loc[0],
			End:          loc[1],
		},
		ValueHash: HashValue(p.telemetryHMAC, value),
	}
}

func compile(patterns ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, regexp.MustCompile(p))
	}
	return out
}

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
		mkp("gitlab-pat", SubtypeGitLabPAT, 1.0, `glpat-[0-9A-Za-z_-]{20,}`),
		mkp("github-token", SubtypeGitHubToken, 1.0, `\bgh[pousr]_[0-9A-Za-z]{20,}\b`),
		mkp("pem-private-key", SubtypePEMPrivateKey, 1.0,
			`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----.*?-----END [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----`),
		mkp("jwt", SubtypeJWT, 1.0, `\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b`),
		mkp("bearer-token", SubtypeBearerToken, 0.85, `(?i)\bbearer\s+[A-Za-z0-9._+=/-]{16,}`),
		mkp("aws-access-key", SubtypeAWSAccessKey, 1.0, `\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`),
		mkp("connection-string", SubtypeConnectionString, 0.95,
			`(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|mssql|oracle):\/\/[^\s:@\/]*:[^\s@]+@[^\s]+`),
		newContextEntropyDetector(telemetryKey),
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

func newContextEntropyDetector(telemetryKey string) *contextEntropyDetector {
	return &contextEntropyDetector{
		telemetryHMAC: telemetryKey,
		tokenRe:       regexp.MustCompile(`[A-Za-z0-9+/_-]{28,}`),
		contextRe:     regexp.MustCompile(`(?i)(password|passwd|secret|token|api[-_]?key|apikey|credential|private[-_]?key|access[-_]?key|auth)`),
		window:        60,
		minEntropy:    3.5,
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
			value := lt.Text[loc[0]:loc[1]]
			if strings.HasPrefix(value, "eyJ") {
				continue // JWT detector owns these; avoid double reporting
			}
			if shannonEntropy(value) < d.minEntropy {
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

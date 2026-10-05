package detectors

import (
	"regexp"

	"github.com/aegisllm/gateway/internal/core"
)

// Secret subtypes (FR-004; ticket 02 ships the first five).
const (
	SubtypeGitLabPAT     = "GITLAB_PAT"
	SubtypeGitHubToken   = "GITHUB_TOKEN"
	SubtypePEMPrivateKey = "PEM_PRIVATE_KEY"
	SubtypeJWT           = "JWT"
	SubtypeBearerToken   = "BEARER_TOKEN"
)

// patternDetector finds matches for one compiled rule across all text parts.
type patternDetector struct {
	name          string
	subtype       string
	re            *regexp.Regexp
	confidence    float64
	telemetryHMAC string
}

func (p *patternDetector) Name() string { return p.name }

func (p *patternDetector) Detect(env *core.InspectionEnvelope) []core.SecurityFinding {
	var out []core.SecurityFinding
	for _, lt := range env.TextParts() {
		for _, loc := range p.re.FindAllStringIndex(lt.Text, -1) {
			value := lt.Text[loc[0]:loc[1]]
			out = append(out, core.SecurityFinding{
				Category:   core.CategorySecret,
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
			})
		}
	}
	return out
}

// SecretDetectors returns the ticket-02 secret detector set. telemetryKey is
// the dedicated HMAC key for finding correlation (may be empty).
func SecretDetectors(telemetryKey string) []Detector {
	mk := func(name, subtype, pattern string, conf float64) Detector {
		return &patternDetector{
			name:          name,
			subtype:       subtype,
			re:            regexp.MustCompile(pattern),
			confidence:    conf,
			telemetryHMAC: telemetryKey,
		}
	}
	return []Detector{
		mk("gitlab-pat", SubtypeGitLabPAT, `glpat-[0-9A-Za-z_-]{20,}`, 1.0),
		mk("github-token", SubtypeGitHubToken, `\bgh[pousr]_[0-9A-Za-z]{20,}\b`, 1.0),
		mk("pem-private-key", SubtypePEMPrivateKey,
			`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----.*?-----END [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----`, 1.0),
		mk("jwt", SubtypeJWT, `\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b`, 1.0),
		mk("bearer-token", SubtypeBearerToken, `(?i)\bbearer\s+[A-Za-z0-9._+=/-]{16,}`, 0.85),
	}
}

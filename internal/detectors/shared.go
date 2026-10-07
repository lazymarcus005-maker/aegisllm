package detectors

import (
	"regexp"

	"github.com/aegisllm/gateway/internal/core"
)

// patternDetector is shared by secret and structured-PII rules. Keeping the
// span projection and keyed hashing in one helper prevents detector families
// from drifting on offsets or telemetry behavior.
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
				out = append(out, p.finding(lt, loc, lt.Text[loc[0]:loc[1]]))
			}
		}
	}
	return out
}

func (p *patternDetector) finding(lt core.LocatedText, loc []int, value string) core.SecurityFinding {
	return core.SecurityFinding{
		Category: p.category, Subtype: p.subtype, Detector: "pattern", Confidence: p.confidence,
		Location:  core.Span{MessageIndex: lt.MessageIndex, PartIndex: lt.PartIndex, Start: loc[0], End: loc[1]},
		ValueHash: HashValue(p.telemetryHMAC, value),
	}
}

func compile(patterns ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		out = append(out, regexp.MustCompile(pattern))
	}
	return out
}

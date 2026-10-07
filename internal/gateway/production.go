package gateway

import (
	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/detectors"
	"github.com/aegisllm/gateway/internal/pii"
)

// ProductionFindings runs the same deterministic and span-oriented detector
// families used by the gateway, for offline policy simulation. It returns
// evidence only; enforcement remains in policy.Engine.
func ProductionFindings(env *core.InspectionEnvelope, telemetryKey string) []core.SecurityFinding {
	findings := detectors.ProductionRegistry(telemetryKey, nil).RunAll(env)
	spans := pii.NewCompositeSpanProvider(pii.NewRegexSpanProvider())
	for _, text := range env.TextParts() {
		for _, entity := range spans.Spans(text.Text) {
			findings = append(findings, core.SecurityFinding{
				Category: core.CategoryPII, Subtype: entity.Label, Detector: spans.Name(), Confidence: entity.Confidence,
				Location: core.Span{MessageIndex: text.MessageIndex, PartIndex: text.PartIndex, Start: entity.Start, End: entity.End},
			})
		}
	}
	return findings
}

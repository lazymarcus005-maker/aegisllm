// Package pii holds span-oriented PII detection (FR-006) and the
// transformation planner. Span providers return exact spans so the gateway
// can redact/tokenize content; Laya is deliberately excluded from this
// interface — it supplies semantic evidence, not spans.
package pii

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/aegisllm/gateway/internal/core"
)

// EntitySpan is one recognized entity inside a text part.
type EntitySpan struct {
	Label      string // e.g. PERSON, ADDRESS, or an org-specific label
	Start      int    // byte offsets into the scanned text
	End        int
	Confidence float64
}

// SpanProvider recognizes entity spans regex/NER-style. Implementations must
// be replaceable (FR-006); a Presidio/NER adapter can slot in later.
type SpanProvider interface {
	Name() string
	Spans(text string) []EntitySpan
}

// RegexSpanProvider recognizes Thai/English honorific person names and Thai
// address lead-ins with deterministic patterns. Heuristic by design: spans
// feed policy-driven transformations, never direct enforcement.
type RegexSpanProvider struct {
	res []compiledRecognizer
}

type compiledRecognizer struct {
	label string
	re    *regexp.Regexp
	conf  float64
}

// NewRegexSpanProvider returns the MVP recognizer set. Byte offsets are used
// throughout, consistent with detector findings.
func NewRegexSpanProvider() *RegexSpanProvider {
	return &RegexSpanProvider{
		res: []compiledRecognizer{
			// Thai honorific + given name, optionally one following word
			// (surname): นายสมชาย ใจดี, คุณมานะ
			{label: "PERSON", conf: 0.6, re: regexp.MustCompile(
				`(?:นาย|นาง|นางสาว|คุณ|เด็กชาย|เด็กหญิง)[\x{0E00}-\x{0E7F}]+(?:\s[\x{0E00}-\x{0E7F}]+)?`)},
			// English honorific names: Mr. Somchai Jaidee
			{label: "PERSON", conf: 0.6, re: regexp.MustCompile(
				`\b(?:Mr|Mrs|Ms|Dr)\.\s?[A-Z][a-z]+(?:\s[A-Z][a-z]+)?`)},
			// Thai address lead-ins: ที่อยู่ ..., บ้านเลขที่ ...
			{label: "ADDRESS", conf: 0.5, re: regexp.MustCompile(
				`(?:ที่อยู่|บ้านเลขที่)\s?[^\n]{6,100}`)},
		},
	}
}

func (p *RegexSpanProvider) Name() string { return "regex-span" }

func (p *RegexSpanProvider) Spans(text string) []EntitySpan {
	var out []EntitySpan
	for _, r := range p.res {
		for _, loc := range r.re.FindAllStringIndex(text, -1) {
			out = append(out, EntitySpan{Label: r.label, Start: loc[0], End: loc[1], Confidence: r.conf})
		}
	}
	return out
}

// CompositeSpanProvider aggregates providers in registration order.
type CompositeSpanProvider struct {
	providers []SpanProvider
}

func NewCompositeSpanProvider(providers ...SpanProvider) *CompositeSpanProvider {
	return &CompositeSpanProvider{providers: providers}
}

func (c *CompositeSpanProvider) Name() string { return "composite-span" }

func (c *CompositeSpanProvider) Spans(text string) []EntitySpan {
	var out []EntitySpan
	for _, p := range c.providers {
		out = append(out, p.Spans(text)...)
	}
	return out
}

// Transformation is one planned replacement inside a message part.
type Transformation struct {
	MessageIndex int
	PartIndex    int
	Start        int
	End          int
	Subtype      string
	Priority     int
	Replacement  string
}

// Namer builds the replacement text for a subtype; ordinal is the 1-based
// occurrence of that subtype within the request (used by tokenization).
type Namer func(subtype string, ordinal int) string

// RedactNamer produces [REDACTED:SUBTYPE] replacements (ticket 05).
func RedactNamer(subtype string, _ int) string { return "[REDACTED:" + subtype + "]" }

// TokenNamer produces the spec FR-013 placeholder form: <TH_CITIZEN_ID_001>.
func TokenNamer(subtype string, ordinal int) string {
	return "<" + subtype + "_" + fmt.Sprintf("%03d", ordinal) + ">"
}

// priorityRank implements the deterministic precedence from T-018:
// secret > specific validated PII detector > generic entity span.
func priorityRank(f core.SecurityFinding) int {
	switch f.Category {
	case core.CategorySecret:
		return 3
	case core.CategoryPII:
		if f.Detector == "pattern" || f.Detector == "thai-citizen-id" || f.Detector == "credit-card" {
			return 2
		}
		return 1 // span-provider entities
	}
	return 0
}

// Plan converts findings (which always carry exact spans) into a
// non-overlapping, deterministically ordered transformation set:
//
//	more specific detector > generic span provider
//	longer validated span > shorter ambiguous span
//	secret > PII
//
// Overlapping lower-priority spans are dropped; equal priorities keep the
// longest. Ordinals for the namer are assigned per subtype in location order.
func Plan(findings []core.SecurityFinding, namer Namer) []Transformation {
	type cand struct {
		f    core.SecurityFinding
		prio int
	}
	cands := make([]cand, 0, len(findings))
	for _, f := range findings {
		if f.Location.End <= f.Location.Start {
			continue
		}
		cands = append(cands, cand{f: f, prio: priorityRank(f)})
	}
	sort.Slice(cands, func(i, j int) bool {
		a, b := cands[i].f.Location, cands[j].f.Location
		if a.MessageIndex != b.MessageIndex {
			return a.MessageIndex < b.MessageIndex
		}
		if a.PartIndex != b.PartIndex {
			return a.PartIndex < b.PartIndex
		}
		if a.Start != b.Start {
			return a.Start < b.Start
		}
		if a.End != b.End {
			return a.End > b.End // longer span first at equal start
		}
		return cands[i].prio > cands[j].prio
	})

	accepted := make([]cand, 0, len(cands))
	for _, c := range cands {
		conflict := false
		higher := true
		for _, a := range accepted {
			if !overlaps(a.f.Location, c.f.Location) {
				continue
			}
			conflict = true
			if c.prio <= a.prio {
				higher = false
				break
			}
		}
		if conflict && !higher {
			continue
		}
		if conflict && higher {
			// drop every accepted span this one outranks
			kept := accepted[:0]
			for _, a := range accepted {
				if !overlaps(a.f.Location, c.f.Location) {
					kept = append(kept, a)
				}
			}
			accepted = kept
		}
		accepted = append(accepted, c)
	}

	sort.Slice(accepted, func(i, j int) bool {
		a, b := accepted[i].f.Location, accepted[j].f.Location
		if a.MessageIndex != b.MessageIndex {
			return a.MessageIndex < b.MessageIndex
		}
		if a.PartIndex != b.PartIndex {
			return a.PartIndex < b.PartIndex
		}
		return a.Start < b.Start
	})

	// Numbering: identical values (same HMAC under the telemetry key) share
	// one ordinal per subtype within the request scope; distinct values
	// number sequentially in first-appearance order. Without a telemetry key
	// every occurrence numbers separately (values are indistinguishable).
	ordinals := map[string]int{}
	nextPerSubtype := map[string]int{}
	out := make([]Transformation, 0, len(accepted))
	for _, a := range accepted {
		loc := a.f.Location
		var ordinal int
		if a.f.ValueHash != "" {
			key := a.f.Subtype + "\x00" + a.f.ValueHash
			if _, seen := ordinals[key]; !seen {
				nextPerSubtype[a.f.Subtype]++
				ordinals[key] = nextPerSubtype[a.f.Subtype]
			}
			ordinal = ordinals[key]
		} else {
			nextPerSubtype[a.f.Subtype]++
			ordinal = nextPerSubtype[a.f.Subtype]
		}
		out = append(out, Transformation{
			MessageIndex: loc.MessageIndex,
			PartIndex:    loc.PartIndex,
			Start:        loc.Start,
			End:          loc.End,
			Subtype:      a.f.Subtype,
			Priority:     a.prio,
			Replacement:  namer(a.f.Subtype, ordinal),
		})
	}
	return out
}

func overlaps(a, b core.Span) bool {
	return a.MessageIndex == b.MessageIndex && a.PartIndex == b.PartIndex &&
		a.Start < b.End && b.Start < a.End
}

// ApplyToText applies one part's transformations, replacing from the end
// backwards so byte offsets stay valid. Transformations must belong to the
// same message part and must not overlap each other.
func ApplyToText(text string, ts []Transformation) string {
	ordered := make([]Transformation, len(ts))
	copy(ordered, ts)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Start > ordered[j].Start })
	for _, t := range ordered {
		if t.Start < 0 || t.End > len(text) || t.Start >= t.End {
			continue
		}
		text = text[:t.Start] + t.Replacement + text[t.End:]
	}
	return text
}

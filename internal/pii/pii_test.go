package pii

import (
	"strings"
	"testing"

	"github.com/aegisllm/gateway/internal/core"
)

func TestRegexSpanProviderThaiPerson(t *testing.T) {
	p := NewRegexSpanProvider()
	spans := p.Spans("ลูกค้าชื่อ นายสมชาย ใจดี โทรเข้ามา")
	if len(spans) == 0 {
		t.Fatal("expected PERSON span for Thai honorific name")
	}
	span := spans[0]
	if span.Label != "PERSON" {
		t.Fatalf("label: %s", span.Label)
	}
	got := "ลูกค้าชื่อ นายสมชาย ใจดี โทรเข้ามา"[span.Start:span.End]
	if got != "นายสมชาย ใจดี" {
		t.Fatalf("span text: %q", got)
	}
}

func TestRegexSpanProviderEnglishPerson(t *testing.T) {
	p := NewRegexSpanProvider()
	spans := p.Spans("Contact Mr. Somchai Jaidee tomorrow.")
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if spans[0].Label != "PERSON" {
		t.Fatalf("label: %s", spans[0].Label)
	}
}

func TestRegexSpanProviderAddress(t *testing.T) {
	p := NewRegexSpanProvider()
	spans := p.Spans("ที่อยู่ 123/45 ถนนสุขุมวิท กรุงเทพฯ")
	if len(spans) != 1 || spans[0].Label != "ADDRESS" {
		t.Fatalf("address span: %+v", spans)
	}
}

func TestCompositeSpanProviderAggregates(t *testing.T) {
	c := NewCompositeSpanProvider(NewRegexSpanProvider(), NewRegexSpanProvider())
	spans := c.Spans("นายสมชาย")
	if len(spans) != 2 {
		t.Fatalf("composite should aggregate duplicates, got %d", len(spans))
	}
	if c.Name() != "composite-span" {
		t.Fatalf("name: %s", c.Name())
	}
}

func finding(cat core.FindingCategory, subtype, detector string, msg, part, start, end int) core.SecurityFinding {
	return core.SecurityFinding{
		Category: cat, Subtype: subtype, Detector: detector, Confidence: 1.0,
		Location: core.Span{MessageIndex: msg, PartIndex: part, Start: start, End: end},
	}
}

func TestPlanSecretBeatsOverlappingPII(t *testing.T) {
	// A secret span overlapping a PII span: secret wins (secret > PII).
	findings := []core.SecurityFinding{
		finding(core.CategoryPII, "HIGH_ENTROPY_SECRET", "pattern", 0, 0, 10, 50),
		finding(core.CategorySecret, "JWT", "pattern", 0, 0, 12, 48),
	}
	plan := Plan(findings, RedactNamer)
	if len(plan) != 1 {
		t.Fatalf("expected 1 transformation, got %d", len(plan))
	}
	if plan[0].Subtype != "JWT" || plan[0].Replacement != "[REDACTED:JWT]" {
		t.Fatalf("secret must win: %+v", plan[0])
	}
}

func TestPlanLongerSpanWinsAtEqualPriority(t *testing.T) {
	findings := []core.SecurityFinding{
		finding(core.CategoryPII, "PHONE_NUMBER", "pattern", 0, 0, 5, 15),
		finding(core.CategoryPII, "PHONE_NUMBER", "pattern", 0, 0, 5, 12),
	}
	plan := Plan(findings, RedactNamer)
	if len(plan) != 1 || plan[0].End != 15 {
		t.Fatalf("longer span must win: %+v", plan)
	}
}

func TestPlanSpecificDetectorBeatsGenericEntity(t *testing.T) {
	// A validated detector span (detectors report detector="pattern", spec
	// §10) overlaps a generic PERSON entity span.
	findings := []core.SecurityFinding{
		finding(core.CategoryPII, "PERSON", "regex-span", 0, 0, 0, 20),
		finding(core.CategoryPII, "TH_CITIZEN_ID", "pattern", 0, 0, 6, 19),
	}
	plan := Plan(findings, RedactNamer)
	if len(plan) != 1 || plan[0].Subtype != "TH_CITIZEN_ID" {
		t.Fatalf("specific detector must win: %+v", plan)
	}
}

func TestPlanKeepsDisjointSpansWithOrdinals(t *testing.T) {
	findings := []core.SecurityFinding{
		finding(core.CategoryPII, "PHONE_NUMBER", "pattern", 0, 0, 0, 10),
		finding(core.CategoryPII, "PHONE_NUMBER", "pattern", 0, 0, 30, 40),
		finding(core.CategoryPII, "EMAIL", "pattern", 1, 0, 2, 22),
	}
	plan := Plan(findings, func(subtype string, ordinal int) string {
		return "<" + subtype + "_" + pad(ordinal) + ">"
	})
	if len(plan) != 3 {
		t.Fatalf("expected 3 transformations, got %d", len(plan))
	}
	if plan[0].Replacement != "<PHONE_NUMBER_001>" || plan[1].Replacement != "<PHONE_NUMBER_002>" {
		t.Fatalf("ordinals wrong: %+v", plan)
	}
	if plan[2].MessageIndex != 1 {
		t.Fatalf("message index wrong: %+v", plan[2])
	}
}

func TestApplyToTextReplacesDescending(t *testing.T) {
	text := "call 0812345678 or 0898765432 today"
	ts := []Transformation{
		{Start: 5, End: 15, Replacement: "[REDACTED:PHONE_NUMBER]"},
		{Start: 19, End: 29, Replacement: "[REDACTED:PHONE_NUMBER]"},
	}
	got := ApplyToText(text, ts)
	want := "call [REDACTED:PHONE_NUMBER] or [REDACTED:PHONE_NUMBER] today"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestApplyToTextThaiByteOffsets(t *testing.T) {
	// Thai text: byte offsets must cut on UTF-8 boundaries.
	text := "ลูกค้าชื่อ นายสมชาย ใจดี โทร 0812345678"
	start := strings.Index(text, "นายสมชาย ใจดี")
	end := start + len("นายสมชาย ใจดี")
	got := ApplyToText(text, []Transformation{{Start: start, End: end, Replacement: "[REDACTED:PERSON]"}})
	if strings.Contains(got, "สมชาย") {
		t.Fatalf("name not redacted: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:PERSON]") {
		t.Fatalf("replacement missing: %q", got)
	}
}

func pad(n int) string {
	s := "00" + string(rune('0'+n%10))
	return s[len(s)-3:]
}

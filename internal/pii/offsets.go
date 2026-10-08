package pii

import (
	"errors"
	"math"
	"sort"
	"unicode/utf8"
)

// OffsetUnit is the contract used by a provider for start/end offsets.
// Transformers always consume UTF-8 byte offsets.
type OffsetUnit string

const (
	OffsetBytes      OffsetUnit = "byte"
	OffsetCodepoints OffsetUnit = "codepoint"
	OffsetUTF16      OffsetUnit = "utf16"
)

// RawSpan is a provider response before offset normalization.
type RawSpan struct {
	Label      string
	Start      int
	End        int
	Confidence float64
	Unit       OffsetUnit
}

// NormalizeSpans converts a provider response to valid, non-overlapping
// UTF-8 byte spans. A malformed response is rejected as a whole: accepting a
// partial response can produce an unsafe transformation boundary.
func NormalizeSpans(text string, raw []RawSpan) ([]EntitySpan, error) {
	if !utf8.ValidString(text) {
		return nil, errors.New("text is not valid UTF-8")
	}
	spans := make([]EntitySpan, 0, len(raw))
	for _, in := range raw {
		if in.Label == "" || in.Start < 0 || in.End <= in.Start || math.IsNaN(in.Confidence) || math.IsInf(in.Confidence, 0) || in.Confidence < 0 || in.Confidence > 1 {
			return nil, errors.New("invalid provider span")
		}
		start, end, ok := normalizeOffsets(text, in.Start, in.End, in.Unit)
		if !ok || start < 0 || end > len(text) || start >= end || !utf8.ValidString(text[start:end]) {
			return nil, errors.New("provider span is out of range or not on a UTF-8 boundary")
		}
		spans = append(spans, EntitySpan{Label: in.Label, Start: start, End: end, Confidence: in.Confidence, OffsetUnit: OffsetBytes})
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].Start != spans[j].Start {
			return spans[i].Start < spans[j].Start
		}
		if spans[i].End != spans[j].End {
			return spans[i].End < spans[j].End
		}
		return spans[i].Label < spans[j].Label
	})
	for i := 1; i < len(spans); i++ {
		if spans[i].Start < spans[i-1].End {
			return nil, errors.New("provider spans overlap")
		}
	}
	return spans, nil
}

func normalizeOffsets(text string, start, end int, unit OffsetUnit) (int, int, bool) {
	if unit == "" {
		unit = OffsetBytes
	}
	switch unit {
	case OffsetBytes:
		if start > len(text) || end > len(text) || !utf8.ValidString(text) {
			return 0, 0, false
		}
		if !utf8Boundary(text, start) || !utf8Boundary(text, end) {
			return 0, 0, false
		}
		return start, end, true
	case OffsetCodepoints:
		bounds := runeBoundaries(text)
		if start >= len(bounds) || end >= len(bounds) {
			return 0, 0, false
		}
		return bounds[start], bounds[end], true
	case OffsetUTF16:
		units := []int{0}
		for pos, r := range text {
			_ = pos
			units = append(units, units[len(units)-1]+utf16Width(r))
		}
		// The list above is per rune, not per UTF-8 byte; map only exact rune
		// boundaries so a provider cannot split a surrogate pair.
		if start < 0 || end <= start {
			return 0, 0, false
		}
		startByte, endByte := -1, -1
		for i, n := range units {
			if n == start {
				startByte = runeBoundaries(text)[i]
			}
			if n == end {
				endByte = runeBoundaries(text)[i]
			}
		}
		return startByte, endByte, startByte >= 0 && endByte >= 0
	case "utf-16", "utf_16":
		return normalizeOffsets(text, start, end, OffsetUTF16)
	case "bytes":
		return normalizeOffsets(text, start, end, OffsetBytes)
	case "codepoints", "code_points":
		return normalizeOffsets(text, start, end, OffsetCodepoints)
	default:
		return 0, 0, false
	}
}

func utf8Boundary(text string, pos int) bool {
	return pos == 0 || pos == len(text) || (pos >= 0 && pos < len(text) && utf8.RuneStart(text[pos]))
}

func runeBoundaries(text string) []int {
	out := make([]int, 0, utf8.RuneCountInString(text)+1)
	out = append(out, 0)
	for pos := range text {
		if pos > 0 {
			out = append(out, pos)
		}
	}
	if out[len(out)-1] != len(text) {
		out = append(out, len(text))
	}
	return out
}

func utf16Width(r rune) int {
	if r > 0xFFFF {
		return 2
	}
	return 1
}

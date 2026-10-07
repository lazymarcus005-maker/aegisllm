package detectors

// This file contains the bounded evasion-resistant projection used before
// deterministic detectors. It intentionally emits evidence only: policy owns
// the action, and unsafe decoded/cross-part evidence is never a rewrite plan.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aegisllm/gateway/internal/core"
	"golang.org/x/text/unicode/norm"
)

// EvasionConfig is deliberately small and bounded. Values <= 0 select safe
// defaults, which keeps programmatic callers fail-closed without configuration.
type EvasionConfig struct {
	Enabled            bool
	Transforms         []string
	MaxDecodeDepth     int
	MaxDecodeWorkBytes int
	MaxExpansionRatio  int
	MaxJSONDepth       int
	MaxJSONNodes       int
	MaxJSONStringBytes int
	MaxCandidateBytes  int
	EnableHex          bool
	BudgetAction       core.Action
	Allowlist          map[string]bool
}

const (
	transformNFKC       = "nfkc"
	transformControls   = "controls"
	transformConfusable = "confusable_skeleton"
	transformBase64     = "base64"
	transformPercent    = "percent"
	transformJSON       = "json_unicode"
	transformHex        = "hex"
)

func DefaultEvasionConfig() EvasionConfig {
	return EvasionConfig{
		Enabled:        true,
		Transforms:     []string{transformNFKC, transformControls, transformConfusable, transformBase64, transformPercent, transformJSON},
		MaxDecodeDepth: 1, MaxDecodeWorkBytes: 256 << 10, MaxExpansionRatio: 8,
		MaxJSONDepth: 8, MaxJSONNodes: 512, MaxJSONStringBytes: 16 << 10,
		MaxCandidateBytes: 32 << 10, BudgetAction: core.ActionBlock,
		Allowlist: map[string]bool{},
	}
}

func (c EvasionConfig) withDefaults() EvasionConfig {
	d := DefaultEvasionConfig()
	if c.MaxDecodeDepth <= 0 {
		c.MaxDecodeDepth = d.MaxDecodeDepth
	}
	if c.MaxDecodeWorkBytes <= 0 {
		c.MaxDecodeWorkBytes = d.MaxDecodeWorkBytes
	}
	if c.MaxExpansionRatio <= 0 {
		c.MaxExpansionRatio = d.MaxExpansionRatio
	}
	if c.MaxJSONDepth <= 0 {
		c.MaxJSONDepth = d.MaxJSONDepth
	}
	if c.MaxJSONNodes <= 0 {
		c.MaxJSONNodes = d.MaxJSONNodes
	}
	if c.MaxJSONStringBytes <= 0 {
		c.MaxJSONStringBytes = d.MaxJSONStringBytes
	}
	if c.MaxCandidateBytes <= 0 {
		c.MaxCandidateBytes = d.MaxCandidateBytes
	}
	if c.BudgetAction == "" {
		c.BudgetAction = d.BudgetAction
	}
	if len(c.Transforms) == 0 {
		c.Transforms = d.Transforms
	}
	if c.Allowlist == nil {
		c.Allowlist = map[string]bool{}
	}
	return c
}

type sourceSpan struct{ message, part, start, end int }

type projection struct {
	text     string
	byByte   []sourceSpan
	parts    []sourceSpan
	controls []sourceSpan
}

type evasionScanner struct {
	ctx       context.Context
	cfg       EvasionConfig
	detectors []Detector
	timing    TimingHook
	work      int
	budget    bool
	seen      map[string]bool
	out       []core.SecurityFinding
}

func (r *Registry) RunAllContext(ctx context.Context, env *core.InspectionEnvelope, cfg EvasionConfig) []core.SecurityFinding {
	if !cfg.Enabled {
		return r.assignIDs(env, r.runDetectors(env))
	}
	s := &evasionScanner{ctx: ctx, cfg: cfg.withDefaults(), detectors: r.detectors, timing: r.timing, seen: map[string]bool{}}
	s.scan(env)
	return r.assignIDs(env, s.out)
}

func (r *Registry) runDetectors(env *core.InspectionEnvelope) []core.SecurityFinding {
	var out []core.SecurityFinding
	for _, d := range r.detectors {
		start := time.Now()
		findings := d.Detect(env)
		if r.timing != nil {
			r.timing(d.Name(), time.Since(start))
		}
		out = append(out, findings...)
	}
	return out
}

func (r *Registry) assignIDs(env *core.InspectionEnvelope, findings []core.SecurityFinding) []core.SecurityFinding {
	for i := range findings {
		findings[i].ID = "finding-" + env.RequestID + "-" + strconv.Itoa(i)
	}
	return findings
}

func (s *evasionScanner) scan(env *core.InspectionEnvelope) {
	if env == nil || s.ctx.Err() != nil {
		return
	}
	parts := make([]projection, 0, len(env.TextParts()))
	canonical := cloneEnvelope(env)
	located := env.TextParts()
	canonicalLocated := canonical.TextParts()
	for i, lt := range located {
		p := makeProjection(lt.Text, lt.MessageIndex, lt.PartIndex, s.cfg)
		parts = append(parts, p)
		if len(p.controls) > 0 && !s.cfg.Allowlist["zero_width_control"] {
			for _, control := range p.controls {
				s.out = append(s.out, core.SecurityFinding{Category: core.CategoryPolicy, Subtype: "ZERO_WIDTH_OR_BIDI_CONTROL", Detector: "evasion", Confidence: 1,
					Location:   core.Span{MessageIndex: control.message, PartIndex: control.part, Start: control.start, End: control.end},
					Attributes: map[string]string{"evasion_type": "zero_width_control"}})
			}
		}
		if i < len(canonicalLocated) {
			canonical.Messages[lt.MessageIndex].Parts[lt.PartIndex].Text = p.text
		}
	}
	for _, f := range s.runTimed(canonical) {
		if s.ctx.Err() != nil {
			return
		}
		s.addMapped(f, parts, false, "")
	}

	// A single rolling canonical projection catches credentials split across
	// message parts/tool fields. Mapping is unsafe when it crosses a boundary.
	// A one-part envelope needs no second detector pass.
	combined := combine(parts)
	if len(parts) > 1 && combined.text != "" {
		virtual := cloneEnvelope(env)
		virtual.Messages = []core.Message{{Role: core.RoleUser, Parts: []core.ContentPart{{Type: core.PartText, Text: combined.text}}}}
		for _, f := range s.run(virtual) {
			s.addMapped(f, parts, true, "cross_part")
		}
	}

	for i, p := range parts {
		if s.ctx.Err() != nil {
			return
		}
		s.scanStructured(env, located[i], p)
		s.scanEncodings(located[i], p, 0, "")
	}
	if s.budget && !s.cfg.Allowlist["budget_exceeded"] {
		s.out = append(s.out, core.SecurityFinding{Category: core.CategoryPolicy, Subtype: "EVASION_BUDGET_EXCEEDED", Detector: "evasion", Confidence: 1,
			Attributes: map[string]string{"evasion_type": "budget_exceeded", "reason": "bounded_work_limit"}})
	}
}

func cloneEnvelope(env *core.InspectionEnvelope) *core.InspectionEnvelope {
	out := *env
	out.Messages = make([]core.Message, len(env.Messages))
	for i, m := range env.Messages {
		out.Messages[i] = m
		out.Messages[i].Parts = append([]core.ContentPart(nil), m.Parts...)
	}
	return &out
}

func (s *evasionScanner) run(env *core.InspectionEnvelope) []core.SecurityFinding {
	var out []core.SecurityFinding
	for _, d := range s.detectors {
		if s.ctx.Err() != nil {
			return out
		}
		out = append(out, d.Detect(env)...)
	}
	return out
}

func (s *evasionScanner) runTimed(env *core.InspectionEnvelope) []core.SecurityFinding {
	var out []core.SecurityFinding
	for _, d := range s.detectors {
		if s.ctx.Err() != nil {
			return out
		}
		start := time.Now()
		out = append(out, d.Detect(env)...)
		// The registry hook is intentionally reserved for the primary canonical
		// pass; decoded/virtual views are bounded evidence, not new detector
		// families and must not distort detector latency dashboards.
		if s.timing != nil {
			s.timing(d.Name(), time.Since(start))
		}
	}
	return out
}

func makeProjection(text string, message, part int, cfg EvasionConfig) projection {
	var b strings.Builder
	b.Grow(len(text))
	by := make([]sourceSpan, 0, len(text))
	var controls []sourceSpan
	useNFKC := containsTransform(cfg.Transforms, transformNFKC)
	useConfusable := containsTransform(cfg.Transforms, transformConfusable)
	for start := 0; start < len(text); {
		r, size := utf8.DecodeRuneInString(text[start:])
		if r == utf8.RuneError && size == 1 {
			r = unicode.ReplacementChar
		}
		if isEvasionControl(r) && containsTransform(cfg.Transforms, transformControls) {
			controls = append(controls, sourceSpan{message: message, part: part, start: start, end: start + size})
			start += size
			continue
		}
		piece := string(r)
		if useNFKC && r > unicode.MaxASCII {
			piece = norm.NFKC.String(piece)
		}
		if useConfusable && r > unicode.MaxASCII {
			piece = confusable(piece)
		}
		b.WriteString(piece)
		for n := 0; n < len(piece); n++ {
			by = append(by, sourceSpan{message: message, part: part, start: start, end: start + size})
		}
		start += size
	}
	return projection{text: b.String(), byByte: by, controls: controls}
}

func isEvasionControl(r rune) bool {
	return r == '\u200b' || r == '\u200c' || r == '\u200d' || r == '\ufeff' ||
		r == '\u200e' || r == '\u200f' || (r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069')
}

// confusable is intentionally targeted. It covers credential prefixes and
// high-signal keyword characters, not general transliteration of user text.
func confusable(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case 'а', 'А':
			b.WriteRune(mapRune(r, 'a', 'A'))
		case 'с':
			b.WriteRune('c')
		case 'С':
			b.WriteRune('C')
		case 'е':
			b.WriteRune('e')
		case 'Е':
			b.WriteRune('E')
		case 'о':
			b.WriteRune('o')
		case 'О':
			b.WriteRune('O')
		case 'р':
			b.WriteRune('p')
		case 'Р':
			b.WriteRune('P')
		case 'х':
			b.WriteRune('x')
		case 'Х':
			b.WriteRune('X')
		case 'ѕ':
			b.WriteRune('s')
		case 'Ѕ':
			b.WriteRune('S')
		case 'і':
			b.WriteRune('i')
		case 'І':
			b.WriteRune('I')
		case 'κ':
			b.WriteRune('k')
		case 'Κ':
			b.WriteRune('K')
		case 'ο':
			b.WriteRune('o')
		case 'Ο':
			b.WriteRune('O')
		case 'ρ':
			b.WriteRune('p')
		case 'Ρ':
			b.WriteRune('P')
		case 'υ':
			b.WriteRune('y')
		case 'Υ':
			b.WriteRune('Y')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func mapRune(r, lower, upper rune) rune {
	if unicode.IsUpper(r) {
		return upper
	}
	return lower
}
func containsTransform(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

func combine(parts []projection) projection {
	var b strings.Builder
	var by []sourceSpan
	for _, p := range parts {
		b.WriteString(p.text)
		by = append(by, p.byByte...)
	}
	return projection{text: b.String(), byByte: by}
}

func (s *evasionScanner) addMapped(f core.SecurityFinding, parts []projection, unsafe bool, typ string) {
	if f.Location.MessageIndex < 0 {
		return
	}
	// Virtual findings use the combined projection and are mapped below by byte
	// index. Ordinary findings use canonical part-local coordinates.
	idx := f.Location.PartIndex
	if unsafe {
		start, end := f.Location.Start, f.Location.End
		combined := combine(parts)
		if start < 0 || end <= start || end > len(combined.byByte) {
			return
		}
		first, last := combined.byByte[start], combined.byByte[end-1]
		f.Location = core.Span{MessageIndex: first.message, PartIndex: first.part, Start: first.start, End: last.end}
		f.Attributes = addAttrs(f.Attributes, map[string]string{"unsafe_span": "true", "evasion_type": typ})
	} else {
		if idx >= len(parts) || f.Location.Start < 0 || f.Location.End <= f.Location.Start || f.Location.End > len(parts[idx].byByte) {
			return
		}
		first, last := parts[idx].byByte[f.Location.Start], parts[idx].byByte[f.Location.End-1]
		f.Location = core.Span{MessageIndex: first.message, PartIndex: first.part, Start: first.start, End: last.end}
	}
	key := string(f.Category) + "/" + f.Subtype + "/" + strconv.Itoa(f.Location.MessageIndex) + "/" + strconv.Itoa(f.Location.PartIndex) + "/" + strconv.Itoa(f.Location.Start) + "/" + strconv.Itoa(f.Location.End) + "/" + f.Attributes["encoding_chain"]
	if s.seen[key] {
		return
	}
	s.seen[key] = true
	s.out = append(s.out, f)
}

func addAttrs(base map[string]string, extra map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		if v != "" {
			out[k] = v
		}
	}
	return out
}

var base64Candidate = regexp.MustCompile(`[A-Za-z0-9+/_=-]{16,}`)
var percentCandidate = regexp.MustCompile(`(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9._~+/-]){8,}`)
var jsonUnicodeCandidate = regexp.MustCompile(`(?:\\u[0-9A-Fa-f]{4}){2,}`)
var hexCandidate = regexp.MustCompile(`(?i)(?:[0-9a-f]{2}){8,}`)

func (s *evasionScanner) scanEncodings(lt core.LocatedText, p projection, depth int, chain string) {
	if depth >= s.cfg.MaxDecodeDepth || !s.consume(len(p.text)) {
		return
	}
	if containsTransform(s.cfg.Transforms, transformBase64) {
		for _, loc := range base64Candidate.FindAllStringIndex(p.text, -1) {
			s.decodeCandidate(lt, p, loc, p.text[loc[0]:loc[1]], "base64", depth, chain)
		}
	}
	if containsTransform(s.cfg.Transforms, transformPercent) {
		for _, loc := range percentCandidate.FindAllStringIndex(p.text, -1) {
			if strings.Count(p.text[loc[0]:loc[1]], "%") < 2 {
				continue
			}
			s.decodeCandidate(lt, p, loc, p.text[loc[0]:loc[1]], "percent", depth, chain)
		}
	}
	if containsTransform(s.cfg.Transforms, transformJSON) {
		for _, loc := range jsonUnicodeCandidate.FindAllStringIndex(p.text, -1) {
			s.decodeCandidate(lt, p, loc, p.text[loc[0]:loc[1]], "json_unicode", depth, chain)
		}
	}
	if s.cfg.EnableHex && containsTransform(s.cfg.Transforms, transformHex) {
		for _, loc := range hexCandidate.FindAllStringIndex(p.text, -1) {
			s.decodeCandidate(lt, p, loc, p.text[loc[0]:loc[1]], "hex", depth, chain)
		}
	}
}

func (s *evasionScanner) decodeCandidate(lt core.LocatedText, p projection, loc []int, candidate, kind string, depth int, chain string) {
	if len(candidate) > s.cfg.MaxCandidateBytes || s.ctx.Err() != nil {
		return
	}
	if kind == "base64" && shannonEntropy(candidate) < 3.25 {
		return
	}
	decoded, ok := decode(kind, candidate)
	if !ok || !decodedText(decoded, candidate, s.cfg.MaxExpansionRatio) {
		return
	}
	if !s.consume(len(decoded)) {
		s.budget = true
		return
	}
	view := &core.InspectionEnvelope{RequestID: "decoded", Messages: []core.Message{{Parts: []core.ContentPart{{Type: core.PartText, Text: string(decoded)}}}}}
	nextChain := kind
	if chain != "" {
		nextChain = chain + ">" + kind
	}
	for _, f := range s.run(view) {
		f.Attributes = addAttrs(f.Attributes, map[string]string{"unsafe_span": "true", "evasion_type": "encoded", "encoding_chain": boundedChain(nextChain)})
		f.Location = core.Span{MessageIndex: lt.MessageIndex, PartIndex: lt.PartIndex, Start: loc[0], End: loc[1]}
		key := string(f.Category) + "/" + f.Subtype + "/" + strconv.Itoa(lt.MessageIndex) + "/" + strconv.Itoa(lt.PartIndex) + "/" + strconv.Itoa(loc[0]) + "/" + strconv.Itoa(loc[1]) + "/" + nextChain
		if !s.seen[key] {
			s.seen[key] = true
			s.out = append(s.out, f)
		}
	}
	if depth+1 < s.cfg.MaxDecodeDepth {
		s.scanEncodings(core.LocatedText{MessageIndex: lt.MessageIndex, PartIndex: lt.PartIndex, Text: string(decoded)}, makeProjection(string(decoded), lt.MessageIndex, lt.PartIndex, s.cfg), depth+1, nextChain)
	}
}

func decode(kind, candidate string) ([]byte, bool) {
	switch kind {
	case "base64":
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if out, err := enc.DecodeString(candidate); err == nil {
				return out, true
			}
		}
	case "percent":
		out, err := url.PathUnescape(candidate)
		return []byte(out), err == nil
	case "json_unicode":
		out, err := strconv.Unquote(`"` + candidate + `"`)
		return []byte(out), err == nil
	case "hex":
		out, err := hex.DecodeString(candidate)
		return out, err == nil
	}
	return nil, false
}

func decodedText(data []byte, source string, ratio int) bool {
	if len(data) < 6 || len(data) > (len(source)*ratio+1) || !utf8.Valid(data) {
		return false
	}
	printable := 0
	for _, r := range string(data) {
		if unicode.IsPrint(r) || unicode.IsSpace(r) {
			printable++
		}
	}
	if printable*100 < utf8.RuneCount(data)*82 {
		return false
	}
	return shannonEntropy(string(data)) >= 2.0 || strings.Contains(string(data), "sk-") || strings.Contains(string(data), "eyJ")
}

func boundedChain(chain string) string {
	if len(chain) > 64 {
		return chain[:64]
	}
	return chain
}
func (s *evasionScanner) consume(n int) bool {
	if n < 0 || s.work > s.cfg.MaxDecodeWorkBytes-n {
		s.budget = true
		return false
	}
	s.work += n
	return true
}

func (s *evasionScanner) scanStructured(env *core.InspectionEnvelope, lt core.LocatedText, p projection) {
	if !containsTransform(s.cfg.Transforms, transformJSON) || len(lt.Text) > s.cfg.MaxCandidateBytes {
		return
	}
	var value any
	dec := json.NewDecoder(strings.NewReader(lt.Text))
	dec.UseNumber()
	if dec.Decode(&value) != nil {
		return
	}
	nodes := 0
	var walk func(any, string, int)
	walk = func(v any, key string, depth int) {
		if s.ctx.Err() != nil || depth > s.cfg.MaxJSONDepth || nodes >= s.cfg.MaxJSONNodes {
			if depth > s.cfg.MaxJSONDepth || nodes >= s.cfg.MaxJSONNodes {
				s.budget = true
			}
			return
		}
		nodes++
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				walk(child, k, depth+1)
			}
		case []any:
			for _, child := range x {
				walk(child, key, depth+1)
			}
		case string:
			if len(x) > s.cfg.MaxJSONStringBytes || !likelyTextValue(x, key) {
				return
			}
			viewText := key + "=" + x
			view := &core.InspectionEnvelope{RequestID: "json", Messages: []core.Message{{Parts: []core.ContentPart{{Type: core.PartText, Text: viewText}}}}}
			for _, f := range s.run(view) {
				if s.hasTypePart(f.Category, f.Subtype, lt.MessageIndex, lt.PartIndex) {
					continue
				}
				f.Attributes = addAttrs(f.Attributes, map[string]string{"unsafe_span": "true", "evasion_type": "structured_json"})
				f.Location = core.Span{MessageIndex: lt.MessageIndex, PartIndex: lt.PartIndex, Start: 0, End: len(lt.Text)}
				keyID := string(f.Category) + "/" + f.Subtype + "/json/" + strconv.Itoa(lt.MessageIndex) + "/" + strconv.Itoa(lt.PartIndex)
				if !s.seen[keyID] {
					s.seen[keyID] = true
					s.out = append(s.out, f)
				}
			}
		}
	}
	walk(value, "", 0)
	_ = p
}

func (s *evasionScanner) hasTypePart(category core.FindingCategory, subtype string, message, part int) bool {
	for _, f := range s.out {
		if f.Category == category && f.Subtype == subtype && f.Location.MessageIndex == message && f.Location.PartIndex == part {
			return true
		}
	}
	return false
}

func likelyTextValue(value, key string) bool {
	if strings.Contains(strings.ToLower(key), "blob") || strings.Contains(strings.ToLower(key), "binary") || strings.Contains(strings.ToLower(key), "image") {
		return false
	}
	if strings.ContainsAny(value, "\x00\x01\x02\x03\x04\x05\x06\x07") {
		return false
	}
	runes := []rune(value)
	if len(runes) > 0 {
		printable := 0
		for _, r := range runes {
			if unicode.IsPrint(r) || unicode.IsSpace(r) {
				printable++
			}
		}
		if printable*100 < len(runes)*80 {
			return false
		}
	}
	return key != "" || strings.TrimSpace(value) != ""
}

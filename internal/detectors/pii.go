package detectors

import (
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/aegisllm/gateway/internal/core"
)

// PiiDetectors returns the ticket-04 Thai/structured PII detector set (FR-005).
// Organization-specific IDs remain pluggable: register additional
// patternDetectors on the Registry as rules become configured.
func PiiDetectors(telemetryKey string) []Detector {
	mk := func(name, subtype string, conf float64, patterns ...string) Detector {
		return &patternDetector{
			name: name, subtype: subtype, category: core.CategoryPII,
			res: compile(patterns...), confidence: conf, telemetryHMAC: telemetryKey,
		}
	}
	return []Detector{
		newThaiCitizenIDDetector(telemetryKey),
		mk("phone-number", SubtypePhoneNumber, 0.9,
			`\+66[-\s]?(?:6|8|9)\d{1}[-\s]?\d{3}[-\s]?\d{4}\b`,
			`\b0(?:6|8|9)\d{1}[-\s]?\d{3}[-\s]?\d{4}\b`,
			`\b0[2-7]\d[-\s]?\d{3}[-\s]?\d{4}\b`),
		newEmailDetector(telemetryKey),
		newCreditCardDetector(telemetryKey),
		newIPDetector(telemetryKey),
	}
}

type emailDetector struct {
	telemetryHMAC string
	candidate     *regexp.Regexp
}

func newEmailDetector(telemetryKey string) *emailDetector {
	return &emailDetector{
		telemetryHMAC: telemetryKey,
		candidate: regexp.MustCompile(
			`[A-Za-z0-9!#$%&'*+/=?^_{}|~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_{}|~-]+)*@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+`),
	}
}

func (d *emailDetector) Name() string { return "email" }

func (d *emailDetector) Detect(env *core.InspectionEnvelope) []core.SecurityFinding {
	var out []core.SecurityFinding
	for _, lt := range env.TextParts() {
		for _, loc := range d.candidate.FindAllStringIndex(lt.Text, -1) {
			if loc[0] > 0 && emailBoundaryForbidden(rune(lt.Text[loc[0]-1])) {
				continue
			}
			if loc[1] < len(lt.Text) && emailBoundaryForbidden(rune(lt.Text[loc[1]])) {
				continue
			}
			raw := lt.Text[loc[0]:loc[1]]
			parts := strings.Split(raw, "@")
			if len(parts) != 2 || strings.Contains(parts[0], "..") || strings.Contains(parts[1], "..") {
				continue
			}
			f := (&patternDetector{subtype: SubtypeEmail, category: core.CategoryPII, confidence: 1.0, telemetryHMAC: d.telemetryHMAC}).finding(lt, loc, raw)
			out = append(out, f)
		}
	}
	return out
}

func emailBoundaryForbidden(r rune) bool {
	return r == '.' || r == '_' || r == '+' || r == '-' ||
		(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// thaiCitizenIDDetector matches 13-digit candidates (with or without the
// X-XXXX-XXXXX-XX-X separators) and validates the official checksum. A random
// 13-digit number that fails the checksum is not a citizen ID (T-007).
type thaiCitizenIDDetector struct {
	telemetryHMAC string
	candidate     []*regexp.Regexp
}

func newThaiCitizenIDDetector(telemetryKey string) *thaiCitizenIDDetector {
	return &thaiCitizenIDDetector{
		telemetryHMAC: telemetryKey,
		candidate:     compile(`\b\d[-\s]?\d{4}[-\s]?\d{5}[-\s]?\d{2}[-\s]?\d\b`),
	}
}

func (d *thaiCitizenIDDetector) Name() string { return "thai-citizen-id" }

func (d *thaiCitizenIDDetector) Detect(env *core.InspectionEnvelope) []core.SecurityFinding {
	var out []core.SecurityFinding
	for _, lt := range env.TextParts() {
		for _, re := range d.candidate {
			for _, loc := range re.FindAllStringIndex(lt.Text, -1) {
				raw := lt.Text[loc[0]:loc[1]]
				if !ThaiCitizenIDValid(stripSeparators(raw)) {
					continue
				}
				f := (&patternDetector{
					subtype: SubtypeThaiCitizenID, category: core.CategoryPII, confidence: 1.0,
					telemetryHMAC: d.telemetryHMAC,
				}).finding(lt, loc, raw)
				out = append(out, f)
			}
		}
	}
	return out
}

// ThaiCitizenIDValid validates the 13-digit Thai citizen ID checksum: the sum
// of digit[i] * (13 - i) for i in 0..11, check digit = (11 - sum % 11) % 10.
func ThaiCitizenIDValid(digits string) bool {
	if len(digits) != 13 {
		return false
	}
	sum := 0
	for i := 0; i < 12; i++ {
		d, err := strconv.Atoi(string(digits[i]))
		if err != nil {
			return false
		}
		sum += d * (13 - i)
	}
	last, err := strconv.Atoi(string(digits[12]))
	if err != nil {
		return false
	}
	return last == (11-sum%11)%10
}

// creditCardDetector finds 13-19 digit candidates and validates with Luhn.
// Candidates that are checksum-valid Thai citizen IDs are skipped so the two
// detectors do not double-report the same 13-digit span.
type creditCardDetector struct {
	telemetryHMAC string
	candidate     []*regexp.Regexp
}

func newCreditCardDetector(telemetryKey string) *creditCardDetector {
	return &creditCardDetector{
		telemetryHMAC: telemetryKey,
		candidate:     compile(`\b(?:\d[ -]?){12,18}\d\b`),
	}
}

func (d *creditCardDetector) Name() string { return "credit-card" }

func (d *creditCardDetector) Detect(env *core.InspectionEnvelope) []core.SecurityFinding {
	var out []core.SecurityFinding
	for _, lt := range env.TextParts() {
		for _, re := range d.candidate {
			for _, loc := range re.FindAllStringIndex(lt.Text, -1) {
				raw := lt.Text[loc[0]:loc[1]]
				digits := stripSeparators(raw)
				if len(digits) < 13 || len(digits) > 19 {
					continue
				}
				if len(digits) == 13 && ThaiCitizenIDValid(digits) {
					continue // citizen ID detector owns this span
				}
				if !LuhnValid(digits) {
					continue
				}
				f := (&patternDetector{
					subtype: SubtypeCreditCard, category: core.CategoryPII, confidence: 1.0,
					telemetryHMAC: d.telemetryHMAC,
				}).finding(lt, loc, raw)
				out = append(out, f)
			}
		}
	}
	return out
}

// LuhnValid validates the Luhn checksum used by payment card numbers.
func LuhnValid(digits string) bool {
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d, err := strconv.Atoi(string(digits[i]))
		if err != nil {
			return false
		}
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// ipDetector matches IPv4/IPv6 candidates and validates their structure, so
// "999.1.1.1" is not reported.
type ipDetector struct {
	telemetryHMAC string
	ipv4          []*regexp.Regexp
	ipv6          []*regexp.Regexp
}

func newIPDetector(telemetryKey string) *ipDetector {
	return &ipDetector{
		telemetryHMAC: telemetryKey,
		ipv4:          compile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
		ipv6:          compile(`(?i)[0-9a-f:]{2,39}`),
	}
}

func (d *ipDetector) Name() string { return "ip-address" }

func (d *ipDetector) Detect(env *core.InspectionEnvelope) []core.SecurityFinding {
	var out []core.SecurityFinding
	for _, lt := range env.TextParts() {
		out = append(out, d.scan(lt, d.ipv4, "4")...)
		out = append(out, d.scan(lt, d.ipv6, "6")...)
	}
	return out
}

func (d *ipDetector) scan(lt core.LocatedText, res []*regexp.Regexp, version string) []core.SecurityFinding {
	var out []core.SecurityFinding
	for _, re := range res {
		for _, loc := range re.FindAllStringIndex(lt.Text, -1) {
			value := lt.Text[loc[0]:loc[1]]
			if net.ParseIP(value) == nil {
				continue
			}
			f := (&patternDetector{
				subtype: SubtypeIPAddress, category: core.CategoryPII, confidence: 0.9,
				telemetryHMAC: d.telemetryHMAC,
			}).finding(lt, loc, value)
			if f.Attributes == nil {
				f.Attributes = map[string]string{}
			}
			f.Attributes["ip_version"] = version
			if ip := net.ParseIP(value); ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
				f.Attributes["ip_scope"] = "private"
			} else {
				f.Attributes["ip_scope"] = "public"
			}
			out = append(out, f)
		}
	}
	return out
}

func stripSeparators(s string) string {
	return strings.NewReplacer("-", "", " ", "").Replace(s)
}

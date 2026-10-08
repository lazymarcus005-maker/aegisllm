package conformance

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aegisllm/gateway/internal/securetransport"
)

var allowedReasonIDs = map[string]bool{
	"ok": true, "http_status": true, "transport": true, "timeout": true, "cancelled": true, "malformed_json": true,
	"malformed_sse": true, "oversize": true, "unexpected_shape": true, "auth": true, "required_skip": true, "capability": true,
}

type AuthDescriptor struct {
	SchemaVersion string             `json:"schema_version"`
	BearerEnv     string             `json:"bearer_env,omitempty"`
	BearerFile    string             `json:"bearer_file,omitempty"`
	Headers       []HeaderDescriptor `json:"headers,omitempty"`
}
type HeaderDescriptor struct {
	Name      string `json:"name"`
	ValueEnv  string `json:"value_env,omitempty"`
	ValueFile string `json:"value_file,omitempty"`
}

func LoadAuth(path string) (http.Header, error) {
	if path == "" {
		return make(http.Header), nil
	}
	b, err := securetransport.ReadTrustedFile(path)
	if err != nil {
		return nil, errors.New("auth descriptor unavailable")
	}
	var d AuthDescriptor
	if err := json.Unmarshal(b, &d); err != nil || d.SchemaVersion != "aegisllm.conformance.auth/v1" {
		return nil, errors.New("auth descriptor is malformed")
	}
	h := make(http.Header)
	if d.BearerEnv != "" && d.BearerFile != "" {
		return nil, errors.New("bearer env and file are mutually exclusive")
	}
	if d.BearerEnv != "" {
		if value := os.Getenv(d.BearerEnv); value != "" {
			h.Set("Authorization", "Bearer "+value)
		}
	}
	if d.BearerFile != "" {
		value, e := securetransport.ReadTrustedFile(d.BearerFile)
		if e != nil {
			return nil, errors.New("bearer file unavailable")
		}
		h.Set("Authorization", "Bearer "+strings.TrimSpace(string(value)))
	}
	for _, item := range d.Headers {
		if item.Name == "" || (item.ValueEnv != "" && item.ValueFile != "") || (item.ValueEnv == "" && item.ValueFile == "") {
			return nil, errors.New("auth header descriptor is malformed")
		}
		var value string
		if item.ValueEnv != "" {
			value = os.Getenv(item.ValueEnv)
		} else {
			raw, e := securetransport.ReadTrustedFile(item.ValueFile)
			if e != nil {
				return nil, errors.New("auth header file unavailable")
			}
			value = strings.TrimSpace(string(raw))
		}
		if value != "" {
			h.Set(item.Name, value)
		}
	}
	return h, nil
}

type RunnerOptions struct {
	Target     string
	Timeout    time.Duration
	Auth       http.Header
	CAFile     string
	CertFile   string
	KeyFile    string
	ServerName string
	Gateway    GatewayInfo
}

func (o RunnerOptions) Client() (*http.Client, error) {
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: o.ServerName}}
	if o.CAFile != "" {
		pem, err := securetransport.ReadTrustedFile(o.CAFile)
		if err != nil {
			return nil, errors.New("CA file unavailable")
		}
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA file is invalid")
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	if o.CertFile != "" || o.KeyFile != "" {
		if o.CertFile == "" || o.KeyFile == "" {
			return nil, errors.New("mTLS requires certificate and key files")
		}
		cert, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
		if err != nil {
			return nil, errors.New("mTLS certificate unavailable")
		}
		tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &http.Client{Transport: tr, Timeout: timeout}, nil
}

func Run(ctx context.Context, spec Specification, opts RunnerOptions, filter map[string]bool) (Report, error) {
	if err := spec.Validate(); err != nil {
		return Report{}, err
	}
	if opts.Target == "" {
		return Report{}, errors.New("target is required")
	}
	targetURL, err := url.Parse(opts.Target)
	if err != nil || targetURL.Scheme == "" || targetURL.Host == "" || targetURL.User != nil || targetURL.RawQuery != "" || targetURL.Fragment != "" || (targetURL.Scheme != "http" && targetURL.Scheme != "https") {
		return Report{}, errors.New("target URL must be http/https without userinfo, query, or fragment")
	}
	client, err := opts.Client()
	if err != nil {
		return Report{}, err
	}
	cases := Cases(spec, filter)
	started := time.Now().UTC()
	report := Report{SchemaVersion: SchemaVersion, SpecVersion: 1, Gateway: opts.Gateway, Target: TargetInfo{ID: sanitizeTarget(opts.Target), BaseURL: sanitizeBaseURL(opts.Target)}, StartedAt: started}
	for _, tc := range cases {
		result := runCase(ctx, client, opts, tc)
		report.Cases = append(report.Cases, result)
		if tc.Required {
			report.Required.Total++
		} else {
			report.Optional.Total++
		}
		if result.Status == "pass" {
			if tc.Required {
				report.Required.Passed++
			} else {
				report.Optional.Passed++
			}
		}
		if result.Status == "fail" {
			if tc.Required {
				report.Required.Failed++
			} else {
				report.Optional.Failed++
			}
		}
		if result.Status == "skip" {
			if tc.Required {
				report.Required.Skipped++
			} else {
				report.Optional.Skipped++
			}
		}
	}
	report.DurationMS = time.Since(started).Milliseconds()
	report.Normalize()
	return report, nil
}

func runCase(ctx context.Context, client *http.Client, opts RunnerOptions, tc Case) CaseResult {
	started := time.Now()
	r := CaseResult{ID: tc.ID, Profile: tc.Profile, Required: tc.Required, Status: "fail"}
	var body []byte
	var err error
	if tc.RawBody != "" {
		body = []byte(tc.RawBody)
	} else {
		body, err = json.Marshal(tc.Body)
	}
	if err != nil {
		r.ReasonID = "unexpected_shape"
		return finish(r, started)
	}
	r.Request = RequestShape{Bytes: len(body), SHA256: HashBytes(body), Fields: topFields(tc.Body)}
	req, err := http.NewRequestWithContext(ctx, tc.Method, strings.TrimRight(opts.Target, "/")+tc.Path, strings.NewReader(string(body)))
	if err != nil {
		r.ReasonID = "transport"
		return finish(r, started)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Conformance-Case", tc.ID)
	// Keep the lab's bounded identities isolated so a rapid full matrix does
	// not accidentally test the gateway's production rate bucket.
	req.Header.Set("X-Application-Id", "conformance-"+safeToken(tc.Profile))
	req.Header.Set("X-Tenant-Id", "conformance-lab")
	if tc.Stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	for key, values := range opts.Auth {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		r.ReasonID = reasonForError(err)
		return finish(r, started)
	}
	defer resp.Body.Close()
	r.HTTPStatus = resp.StatusCode
	r.Response.ContentType = safeContentType(resp.Header.Get("Content-Type"))
	r.Response.Headers = safeHeaders(resp.Header)
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20+1))
	r.Response.Bytes = len(data)
	r.Response.SHA256 = HashBytes(data)
	if readErr != nil {
		r.ReasonID = "transport"
		return finish(r, started)
	}
	if len(data) > 8<<20 {
		r.ReasonID = "oversize"
		return finish(r, started)
	}
	if !containsInt(tc.Expected.Statuses, resp.StatusCode) {
		r.ReasonID = "http_status"
		return finish(r, started)
	}
	if tc.Expected.Shape == "stream" {
		r.Response.Semantic, err = NormalizeSSE(data, tc.Profile)
		if err != nil {
			r.ReasonID = "malformed_sse"
			return finish(r, started)
		}
	} else {
		r.Response.Semantic, err = NormalizeJSON(data, tc.Profile)
		if err != nil {
			r.ReasonID = "malformed_json"
			return finish(r, started)
		}
	}
	if r.Response.Semantic.Kind == "" {
		r.ReasonID = "unexpected_shape"
		return finish(r, started)
	}
	r.Status = "pass"
	r.ReasonID = "ok"
	return finish(r, started)
}

func finish(r CaseResult, started time.Time) CaseResult {
	if !allowedReasonIDs[r.ReasonID] {
		r.ReasonID = "unexpected_shape"
	}
	r.DurationMS = time.Since(started).Milliseconds()
	return r
}
func reasonForError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(strings.ToLower(err.Error()), "timeout") {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	return "transport"
}
func containsInt(values []int, value int) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func topFields(body any) []string {
	m, ok := body.(map[string]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func safeContentType(value string) string {
	value = strings.ToLower(strings.TrimSpace(strings.Split(value, ";")[0]))
	if value == "application/json" || value == "text/event-stream" {
		return value
	}
	return "other"
}
func safeHeaders(h http.Header) []string {
	out := []string{}
	for k := range h {
		k = strings.ToLower(k)
		if k == "content-type" || k == "retry-after" || k == "x-request-id" || k == "x-fake-auth-seen" {
			out = append(out, k)
		}
	}
	return out
}

func safeToken(value string) string {
	value = strings.ToLower(value)
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
func sanitizeTarget(raw string) string {
	raw = strings.ToLower(raw)
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "https://")
	if i := strings.IndexAny(raw, "/?:#"); i >= 0 {
		raw = raw[:i]
	}
	if raw == "" {
		return "unknown"
	}
	return raw
}
func sanitizeBaseURL(raw string) string {
	if strings.HasPrefix(raw, "https://") {
		return "https://" + sanitizeTarget(raw)
	}
	return "http://" + sanitizeTarget(raw)
}

func NormalizeJSON(data []byte, profile string) (SemanticShape, error) {
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return SemanticShape{}, err
	}
	m, ok := root.(map[string]any)
	if !ok {
		return SemanticShape{}, errors.New("response is not an object")
	}
	s := SemanticShape{Kind: "json", Object: stringValue(m["object"]), Model: stringValue(m["model"]), Usage: m["usage"] != nil}
	contentLen := 0
	if choices, ok := m["choices"].([]any); ok {
		s.Choices = len(choices)
		for _, item := range choices {
			if cm, ok := item.(map[string]any); ok {
				s.Finish = stringValue(cm["finish_reason"])
				if msg, ok := cm["message"].(map[string]any); ok {
					s.TextBytes += len([]byte(stringValue(msg["content"])))
					s.ToolCalls += arrayLen(msg["tool_calls"])
				}
			}
		}
	}
	if content, ok := m["content"].([]any); ok {
		contentLen = len(content)
		for _, item := range content {
			if cm, ok := item.(map[string]any); ok {
				s.TextBytes += len([]byte(stringValue(cm["text"])))
				if stringValue(cm["type"]) == "tool_use" {
					s.ToolCalls++
				}
			}
		}
	}
	s.Stop = stringValue(m["stop_reason"])
	if s.Object == "" && (s.Choices > 0 || contentLen > 0 || profile == "generic-alias") {
		s.Object = "provider-response"
	}
	return s, nil
}

func NormalizeSSE(data []byte, profile string) (SemanticShape, error) {
	s := SemanticShape{Kind: "sse"}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 1024), 256<<10)
	var event strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if event.Len() > 0 {
				piece, err := normalizeEvent(event.String(), profile)
				if err != nil {
					return SemanticShape{}, err
				}
				mergeShape(&s, piece)
				event.Reset()
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			if event.Len() > 0 {
				event.WriteByte('\n')
			}
			event.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	if event.Len() > 0 {
		piece, err := normalizeEvent(event.String(), profile)
		if err != nil {
			return SemanticShape{}, err
		}
		mergeShape(&s, piece)
	}
	if err := scanner.Err(); err != nil {
		return SemanticShape{}, err
	}
	if s.Events == 0 {
		return SemanticShape{}, errors.New("no SSE events")
	}
	s.Done = strings.Contains(string(data), "[DONE]") || s.Stop != ""
	return s, nil
}
func normalizeEvent(data, profile string) (SemanticShape, error) {
	if strings.TrimSpace(data) == "[DONE]" {
		return SemanticShape{Kind: "sse", Done: true}, nil
	}
	s, err := NormalizeJSON([]byte(data), profile)
	if err != nil {
		return SemanticShape{}, err
	}
	s.Kind = "sse"
	s.Events = 1
	return s, nil
}
func mergeShape(dst *SemanticShape, src SemanticShape) {
	dst.Events += src.Events
	dst.TextBytes += src.TextBytes
	dst.Choices += src.Choices
	dst.ToolCalls += src.ToolCalls
	if src.Model != "" {
		dst.Model = src.Model
	}
	if src.Finish != "" {
		dst.Finish = src.Finish
	}
	if src.Stop != "" {
		dst.Stop = src.Stop
	}
	dst.Usage = dst.Usage || src.Usage
	dst.Done = dst.Done || src.Done
}
func stringValue(v any) string { s, _ := v.(string); return s }
func arrayLen(v any) int       { a, _ := v.([]any); return len(a) }

// WriteJUnit emits only bounded identifiers, statuses, and reason IDs.
func WriteJUnit(r Report) []byte {
	var b strings.Builder
	total := len(r.Cases)
	failures := r.Required.Failed + r.Optional.Failed
	skipped := r.Required.Skipped + r.Optional.Skipped
	fmt.Fprintf(&b, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuite name=\"aegisllm-conformance\" tests=\"%d\" failures=\"%d\" skipped=\"%d\">\n", total, failures, skipped)
	for _, c := range r.Cases {
		fmt.Fprintf(&b, "  <testcase name=\"%s\" classname=\"%s\" time=\"%.3f\">", xmlEscape(c.ID), xmlEscape(c.Profile), float64(c.DurationMS)/1000)
		if c.Status == "fail" {
			fmt.Fprintf(&b, "<failure type=\"%s\" message=\"%s\"/>", xmlEscape(c.ReasonID), xmlEscape(c.ReasonID))
		}
		if c.Status == "skip" {
			fmt.Fprintf(&b, "<skipped message=\"%s\"/>", xmlEscape(c.ReasonID))
		}
		b.WriteString("</testcase>\n")
	}
	b.WriteString("</testsuite>\n")
	return []byte(b.String())
}
func xmlEscape(v string) string {
	v = strings.ReplaceAll(v, "&", "&amp;")
	v = strings.ReplaceAll(v, "<", "&lt;")
	v = strings.ReplaceAll(v, ">", "&gt;")
	v = strings.ReplaceAll(v, "\"", "&quot;")
	return v
}

func WriteFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

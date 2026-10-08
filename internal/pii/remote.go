package pii

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aegisllm/gateway/internal/securetransport"
	"github.com/aegisllm/gateway/internal/trace"
)

const (
	ProviderSchema  = "aegisllm.ner/v1"
	MaxProviderBody = 1 << 20
)

// HTTPProviderConfig is shared by the Presidio and Aegis NER adapters. Auth
// is intentionally a file reference; inline bearer values are not accepted.
type HTTPProviderConfig struct {
	ID                      string
	Priority                int
	FailBehavior            string
	URL                     string
	Languages               []string
	EntityMappings          map[string]string
	MinConfidence           map[string]float64
	MinConfidenceByLanguage map[string]map[string]float64
	Timeout                 time.Duration
	MaxChars                int
	ChunkOverlap            int
	MaxConcurrent           int
	Breaker                 int
	BreakerOpen             time.Duration
	AuthFile                string
	TLS                     securetransport.ClientTLSOptions
	Transport               http.RoundTripper
	Metrics                 ProviderMetrics
}

// ProviderMetrics is intentionally tiny and content-free. Implementations
// must use only bounded provider/entity/language/confidence labels.
type ProviderMetrics interface {
	ObserveNER(provider, entity, language, confidenceBucket string, latencyMS float64, failed, fallback bool)
}

// ProviderStatus is safe for readiness and operator status. It contains no
// endpoint, credentials, content, or provider payload.
type ProviderStatus struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Languages   []string  `json:"languages,omitempty"`
	Entities    []string  `json:"entities,omitempty"`
	Available   bool      `json:"available"`
	Breaker     string    `json:"breaker"`
	InFlight    int       `json:"in_flight"`
	LastError   string    `json:"last_error,omitempty"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	TotalCalls  uint64    `json:"total_calls"`
	TotalErrors uint64    `json:"total_errors"`
}

type remoteSpanProvider struct {
	cfg       HTTPProviderConfig
	typeName  string
	client    *http.Client
	auth      *securetransport.File[string]
	certFiles []*securetransport.File[tls.Certificate]
	sem       chan struct{}
	breaker   *providerBreaker
	statusMu  sync.RWMutex
	status    ProviderStatus
	calls     atomic.Uint64
	errors    atomic.Uint64
	inFlight  atomic.Int64
	sequence  atomic.Uint64
}

// NewPresidioHTTPAdapter creates an adapter for the Presidio /analyze
// contract. Presidio response offsets are codepoints by default.
func NewPresidioHTTPAdapter(cfg HTTPProviderConfig) (*remoteSpanProvider, error) {
	return newRemoteProvider(cfg, "presidio", "/analyze")
}

// NewAegisNERAdapter creates an adapter for the versioned Aegis NER contract.
func NewAegisNERAdapter(cfg HTTPProviderConfig) (*remoteSpanProvider, error) {
	return newRemoteProvider(cfg, "aegis-ner", "")
}

// PresidioHTTPAdapter is an explicit public alias for integrations that want
// to name the concrete adapter type in configuration or tests.
type PresidioHTTPAdapter = remoteSpanProvider

// AegisNERAdapter is an explicit public alias for the generic contract.
type AegisNERAdapter = remoteSpanProvider

func newRemoteProvider(cfg HTTPProviderConfig, typeName, suffix string) (*remoteSpanProvider, error) {
	if strings.TrimSpace(cfg.ID) == "" {
		cfg.ID = typeName
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" {
		return nil, errors.New("NER provider URL is invalid")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.MaxChars <= 0 {
		cfg.MaxChars = 4096
	}
	if cfg.ChunkOverlap < 0 || cfg.ChunkOverlap >= cfg.MaxChars {
		return nil, errors.New("NER chunk overlap is invalid")
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 4
	}
	if cfg.Breaker <= 0 {
		cfg.Breaker = 3
	}
	if cfg.BreakerOpen <= 0 {
		cfg.BreakerOpen = 15 * time.Second
	}
	var authFile *securetransport.File[string]
	if cfg.AuthFile != "" {
		authFile, err = securetransport.SecretFile(cfg.AuthFile, securetransport.DefaultPollInterval, nil)
		if err != nil {
			return nil, errors.New("NER auth file is invalid")
		}
	}
	var certFiles []*securetransport.File[tls.Certificate]
	if cfg.Transport == nil {
		tlsCfg, loadedCertFiles, tlsErr := cfg.TLS.TLSConfig()
		if tlsErr != nil {
			if authFile != nil {
				authFile.Close()
			}
			return nil, errors.New("NER TLS configuration is invalid")
		}
		tr := &http.Transport{TLSClientConfig: tlsCfg, MaxIdleConns: cfg.MaxConcurrent, MaxIdleConnsPerHost: cfg.MaxConcurrent, ResponseHeaderTimeout: cfg.Timeout}
		cfg.Transport = tr
		// Retain the reload handles so Close can stop their bounded pollers.
		certFiles = loadedCertFiles
	}
	p := &remoteSpanProvider{cfg: cfg, typeName: typeName, client: &http.Client{Transport: cfg.Transport, Timeout: cfg.Timeout}, auth: authFile, certFiles: certFiles, sem: make(chan struct{}, cfg.MaxConcurrent), breaker: newProviderBreaker(cfg.Breaker, cfg.BreakerOpen), status: ProviderStatus{ID: cfg.ID, Type: typeName, Languages: append([]string(nil), cfg.Languages...), Entities: mappingValues(cfg.EntityMappings), Available: true, Breaker: "closed"}}
	_ = suffix
	return p, nil
}

func (p *remoteSpanProvider) Name() string { return p.cfg.ID }

func (p *remoteSpanProvider) SetMetrics(metrics ProviderMetrics) { p.cfg.Metrics = metrics }

func (p *remoteSpanProvider) ObserveFallback() {
	if p.cfg.FailBehavior == "deterministic_only" && p.cfg.Metrics != nil {
		p.cfg.Metrics.ObserveNER(p.cfg.ID, "none", "none", "none", 0, true, true)
	}
}

func (p *remoteSpanProvider) Spans(text string) []EntitySpan {
	spans, _ := p.SpansContext(context.Background(), text)
	return spans
}

func (p *remoteSpanProvider) SpansContext(ctx context.Context, text string) ([]EntitySpan, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(text) == 0 {
		return nil, nil
	}
	lang := DetectLanguage(text)
	if !p.supportsLanguage(lang) {
		return nil, nil
	}
	chunks := splitChunks(text, p.cfg.MaxChars, p.cfg.ChunkOverlap)
	var out []EntitySpan
	for _, chunk := range chunks {
		spans, err := p.call(ctx, chunk.text, lang)
		if err != nil {
			return nil, err
		}
		for _, span := range spans {
			span.Start += chunk.startByte
			span.End += chunk.startByte
			span.Provider = p.cfg.ID
			out = append(out, span)
		}
	}
	// Chunk overlap intentionally causes duplicate detections at the seam.
	return deduplicateSpans(out), nil
}

func (p *remoteSpanProvider) supportsLanguage(language string) bool {
	if len(p.cfg.Languages) == 0 {
		return true
	}
	for _, supported := range p.cfg.Languages {
		if strings.EqualFold(supported, language) || strings.EqualFold(supported, "mixed") || strings.EqualFold(supported, "*") {
			return true
		}
		if language == "mixed" && (strings.EqualFold(supported, "th") || strings.EqualFold(supported, "en")) {
			return true
		}
	}
	return false
}

func (p *remoteSpanProvider) call(ctx context.Context, text, language string) ([]EntitySpan, error) {
	started := time.Now()
	if !p.breaker.allow() {
		p.record(false, "breaker_open", language, nil, time.Since(started))
		return nil, errors.New("NER provider unavailable")
	}
	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
	case <-ctx.Done():
		p.record(false, "cancelled", language, nil, time.Since(started))
		return nil, ctx.Err()
	}
	p.inFlight.Add(1)
	defer p.inFlight.Add(-1)
	p.calls.Add(1)
	callCtx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	body, err := p.requestBody(text, language)
	if err != nil {
		p.record(false, "request", language, nil, time.Since(started))
		return nil, errors.New("NER provider request failed")
	}
	path := ""
	endpoint := strings.TrimRight(p.cfg.URL, "/")
	if p.typeName == "presidio" && !strings.HasSuffix(endpoint, "/analyze") {
		path = "/analyze"
		endpoint += path
	}
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		p.record(false, "request", language, nil, time.Since(started))
		return nil, errors.New("NER provider request failed")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Aegis-Correlation-ID", p.correlationID())
	if tc, ok := trace.From(callCtx); ok {
		trace.Inject(req, trace.Child(tc))
	}
	if p.auth != nil {
		secret, getErr := p.auth.Get()
		if getErr != nil {
			p.record(false, "auth", language, nil, time.Since(started))
			return nil, errors.New("NER provider auth unavailable")
		}
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		p.record(false, "transport", language, nil, time.Since(started))
		return nil, errors.New("NER provider request failed")
	}
	defer resp.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, MaxProviderBody+1))
	if readErr != nil || len(data) > MaxProviderBody || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		p.record(false, "response", language, nil, time.Since(started))
		return nil, errors.New("NER provider response invalid")
	}
	spans, parseErr := p.parse(text, data, language)
	if parseErr != nil {
		p.record(false, "payload", language, nil, time.Since(started))
		return nil, parseErr
	}
	p.record(true, "", language, spans, time.Since(started))
	return spans, nil
}

func (p *remoteSpanProvider) requestBody(text, language string) ([]byte, error) {
	if p.typeName == "presidio" {
		return json.Marshal(struct {
			Text     string `json:"text"`
			Language string `json:"language"`
		}{text, language})
	}
	return json.Marshal(struct {
		Schema        string `json:"schema"`
		Version       int    `json:"version"`
		Text          string `json:"text"`
		Language      string `json:"language"`
		CorrelationID string `json:"correlation_id"`
	}{ProviderSchema, 1, text, language, p.correlationID()})
}

func (p *remoteSpanProvider) parse(text string, data []byte, language string) ([]EntitySpan, error) {
	var raw []RawSpan
	if p.typeName == "presidio" {
		var response []struct {
			Entity string  `json:"entity"`
			Start  int     `json:"start"`
			End    int     `json:"end"`
			Score  float64 `json:"score"`
			Offset string  `json:"offset_unit"`
		}
		if err := json.Unmarshal(data, &response); err != nil {
			return nil, errors.New("NER provider response invalid")
		}
		for _, s := range response {
			label := s.Entity
			if mapped, ok := p.cfg.EntityMappings[label]; ok {
				label = mapped
			}
			unit := OffsetCodepoints
			if s.Offset != "" {
				unit = OffsetUnit(strings.ToLower(s.Offset))
			}
			raw = append(raw, RawSpan{Label: label, Start: s.Start, End: s.End, Confidence: s.Score, Unit: unit})
		}
	} else {
		var response struct {
			Schema  string `json:"schema"`
			Version int    `json:"version"`
			Spans   []struct {
				Entity     string  `json:"entity"`
				Label      string  `json:"label"`
				Start      int     `json:"start"`
				End        int     `json:"end"`
				Confidence float64 `json:"confidence"`
				OffsetUnit string  `json:"offset_unit"`
			} `json:"spans"`
		}
		if err := json.Unmarshal(data, &response); err != nil || response.Schema != ProviderSchema || response.Version != 1 {
			return nil, errors.New("NER provider response invalid")
		}
		for _, s := range response.Spans {
			label := s.Entity
			if label == "" {
				label = s.Label
			}
			if mapped, ok := p.cfg.EntityMappings[label]; ok {
				label = mapped
			}
			unit := OffsetUnit(strings.ToLower(s.OffsetUnit))
			if unit == "" {
				unit = OffsetCodepoints
			}
			raw = append(raw, RawSpan{Label: label, Start: s.Start, End: s.End, Confidence: s.Confidence, Unit: unit})
		}
	}
	for _, span := range raw {
		if min, ok := p.cfg.MinConfidence[span.Label]; ok && span.Confidence < min {
			span.Confidence = -1
		}
		if byLanguage, ok := p.cfg.MinConfidenceByLanguage[language]; ok {
			if min, ok := byLanguage[span.Label]; ok && span.Confidence < min {
				span.Confidence = -1
			}
		}
	}
	filtered := raw[:0]
	for _, span := range raw {
		if span.Confidence >= 0 {
			filtered = append(filtered, span)
		}
	}
	return NormalizeSpans(text, filtered)
}

func (p *remoteSpanProvider) correlationID() string { return fmt.Sprintf("ner-%x", p.sequence.Add(1)) }

func (p *remoteSpanProvider) record(success bool, reason, language string, spans []EntitySpan, latency time.Duration) {
	if !success {
		p.errors.Add(1)
		p.breaker.record(false)
	} else {
		p.breaker.record(true)
	}
	p.statusMu.Lock()
	defer p.statusMu.Unlock()
	p.status.Available = success
	p.status.Breaker = p.breaker.state()
	p.status.InFlight = int(p.inFlight.Load())
	p.status.TotalCalls = p.calls.Load()
	p.status.TotalErrors = p.errors.Load()
	if success {
		p.status.LastSuccess = time.Now().UTC()
		p.status.LastError = ""
	} else {
		p.status.LastError = boundedProviderReason(reason)
	}
	if p.cfg.Metrics != nil {
		if len(spans) == 0 {
			p.cfg.Metrics.ObserveNER(p.cfg.ID, "none", language, "none", float64(latency.Microseconds())/1000, !success, false)
		}
		for _, span := range spans {
			p.cfg.Metrics.ObserveNER(p.cfg.ID, span.Label, language, confidenceBucket(span.Confidence), float64(latency.Microseconds())/1000, !success, false)
		}
	}
}

func (p *remoteSpanProvider) Status() ProviderStatus {
	p.statusMu.RLock()
	defer p.statusMu.RUnlock()
	out := p.status
	out.Languages = append([]string(nil), out.Languages...)
	out.Entities = append([]string(nil), out.Entities...)
	return out
}
func (p *remoteSpanProvider) Close() {
	if p.auth != nil {
		p.auth.Close()
	}
	for _, file := range p.certFiles {
		file.Close()
	}
}

func confidenceBucket(v float64) string {
	switch {
	case v < .5:
		return "0-.49"
	case v < .75:
		return ".5-.74"
	case v < .9:
		return ".75-.89"
	default:
		return ".9-1"
	}
}

type providerBreaker struct {
	mu                  sync.Mutex
	failures, threshold int
	openUntil           time.Time
	cooldown            time.Duration
}

func newProviderBreaker(threshold int, cooldown time.Duration) *providerBreaker {
	return &providerBreaker{threshold: threshold, cooldown: cooldown}
}
func (b *providerBreaker) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failures < b.threshold || time.Now().After(b.openUntil)
}
func (b *providerBreaker) record(success bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if success {
		b.failures = 0
		b.openUntil = time.Time{}
		return
	}
	b.failures++
	if b.failures >= b.threshold {
		b.openUntil = time.Now().Add(b.cooldown)
	}
}
func (b *providerBreaker) state() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failures < b.threshold {
		return "closed"
	}
	if time.Now().Before(b.openUntil) {
		return "open"
	}
	return "half_open"
}

func boundedProviderReason(reason string) string {
	switch reason {
	case "breaker_open", "cancelled", "request", "auth", "transport", "response", "payload":
		return reason
	default:
		return "provider"
	}
}

type textChunk struct {
	text      string
	startByte int
}

func splitChunks(text string, maxChars, overlap int) []textChunk {
	runes := []rune(text)
	if maxChars <= 0 || len(runes) <= maxChars {
		return []textChunk{{text: text, startByte: 0}}
	}
	var out []textChunk
	start := 0
	for start < len(runes) {
		end := start + maxChars
		if end > len(runes) {
			end = len(runes)
		}
		part := string(runes[start:end])
		startByte := len(string(runes[:start]))
		out = append(out, textChunk{part, startByte})
		if end == len(runes) {
			break
		}
		next := end - overlap
		if next <= start {
			next = end
		}
		start = next
	}
	return out
}

func deduplicateSpans(spans []EntitySpan) []EntitySpan {
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].Start != spans[j].Start {
			return spans[i].Start < spans[j].Start
		}
		if spans[i].End != spans[j].End {
			return spans[i].End < spans[j].End
		}
		return spans[i].Label < spans[j].Label
	})
	out := spans[:0]
	for _, s := range spans {
		if len(out) > 0 && out[len(out)-1].Start == s.Start && out[len(out)-1].End == s.End && out[len(out)-1].Label == s.Label {
			if s.Confidence > out[len(out)-1].Confidence {
				out[len(out)-1] = s
			}
			continue
		}
		out = append(out, s)
	}
	return out
}

func mappingValues(m map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range m {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// DetectLanguage is deliberately bounded and explainable. It routes provider
// calls; it is not a quality claim about language identification.
func DetectLanguage(text string) string {
	var th, en bool
	for _, r := range text {
		switch {
		case r >= 0x0E00 && r <= 0x0E7F:
			th = true
		case r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z':
			en = true
		}
	}
	if th && en {
		return "mixed"
	}
	if th {
		return "th"
	}
	return "en"
}

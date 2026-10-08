// Package attachment implements the bounded, fail-closed multimodal boundary.
// It deliberately contains no protocol-specific JSON rewriting: normalizers
// provide references and this package validates, fetches, and extracts them
// before the ordinary detector/PII/policy path runs.
package attachment

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/securetransport"
)

const (
	DefaultMaxEncodedBytes = 8 << 20
	DefaultMaxDecodedBytes = 6 << 20
	DefaultMaxTextBytes    = 1 << 20
	DefaultMaxAttachments  = 8
	DefaultMaxPages        = 32
	DefaultTimeout         = 5 * time.Second
)

var DefaultAllowedMIMEs = []string{"image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf", "text/plain", "application/json", "application/zip", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}

// Error is safe to expose as a stable policy code. Details never include a
// URL, filename, payload, or extractor response.
type Error struct {
	Code  string
	cause error
}

func (e *Error) Error() string            { return e.Code }
func (e *Error) Unwrap() error            { return e.cause }
func fail(code string, cause error) error { return &Error{Code: code, cause: cause} }

type Config struct {
	Enabled           bool
	Production        bool
	Adapter           string // disabled | builtin | http
	EndpointURL       string
	AllowedHosts      []string
	AllowPrivateHosts bool
	MaxEncodedBytes   int64
	MaxDecodedBytes   int64
	MaxTextBytes      int
	MaxAttachments    int
	MaxPages          int
	MaxExpansionRatio int64
	Timeout           time.Duration
	MaxRedirects      int
	AllowedMIMEs      []string
	TLS               securetransport.ClientTLSOptions
}

type ExtractionRequest struct {
	MIMEType string
	Kind     string
	Name     string
	Bytes    []byte
	Hash     string
}
type ExtractionResult struct {
	Text     string
	Pages    int
	Metadata map[string]string
}
type Extractor interface {
	Extract(context.Context, ExtractionRequest) (ExtractionResult, error)
}
type Status struct {
	Enabled bool
	Adapter string
	Ready   bool
}

type Inspector struct {
	cfg       Config
	extractor Extractor
	client    *http.Client
	materials []interface{ Close() }
}

func New(cfg Config, extractor Extractor) (*Inspector, error) {
	cfg = withDefaults(cfg)
	if !cfg.Enabled {
		return &Inspector{cfg: cfg}, nil
	}
	if cfg.Adapter == "" {
		cfg.Adapter = "builtin"
	}
	if cfg.Production && cfg.Adapter != "http" {
		return nil, errors.New("production attachment extraction requires private HTTP adapter")
	}
	if cfg.Adapter == "http" && extractor == nil {
		if strings.TrimSpace(cfg.EndpointURL) == "" {
			return nil, errors.New("attachment extractor endpoint is required")
		}
		u, err := url.Parse(cfg.EndpointURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" {
			return nil, errors.New("attachment extractor endpoint must be verified HTTPS without credentials or query data")
		}
		tlsConfig, materials, err := cfg.TLS.TLSConfig()
		if err != nil {
			return nil, errors.New("attachment extractor TLS configuration is invalid")
		}
		transport := &http.Transport{TLSClientConfig: tlsConfig, Proxy: nil, DialContext: (&net.Dialer{Timeout: cfg.Timeout}).DialContext, MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second}
		adapterClient := &http.Client{Transport: transport, Timeout: cfg.Timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > cfg.MaxRedirects {
				return errors.New("redirect limit")
			}
			if err := validateRemoteURL(req.URL, cfg); err != nil {
				return err
			}
			req.Header = make(http.Header)
			return nil
		}}
		extractor = &HTTPExtractor{endpoint: strings.TrimRight(cfg.EndpointURL, "/"), client: adapterClient}
		// Media URLs use a separate TLS client without the extractor mTLS
		// certificate. Caller credentials never cross the URL-fetch boundary.
		fetchTLS := cfg.TLS
		fetchTLS.CertificateFile, fetchTLS.KeyFile = "", ""
		fetchTLS.ServerName = ""
		fetchConfig, _, fetchErr := fetchTLS.TLSConfig()
		if fetchErr != nil {
			return nil, errors.New("attachment URL TLS configuration is invalid")
		}
		fetchTransport := &http.Transport{TLSClientConfig: fetchConfig, Proxy: nil, DialContext: safeDialContext(cfg, &net.Dialer{Timeout: cfg.Timeout}), MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second}
		fetchClient := &http.Client{Transport: fetchTransport, Timeout: cfg.Timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > cfg.MaxRedirects {
				return errors.New("redirect limit")
			}
			if err := validateRemoteURL(req.URL, cfg); err != nil {
				return err
			}
			req.Header = make(http.Header)
			return nil
		}}
		owned := make([]interface{ Close() }, len(materials))
		for n, material := range materials {
			owned[n] = material
		}
		return &Inspector{cfg: cfg, extractor: extractor, client: fetchClient, materials: owned}, nil
	}
	if cfg.Adapter != "builtin" {
		return nil, errors.New("unknown attachment extractor adapter")
	}
	if extractor == nil {
		extractor = BuiltinExtractor{}
	}
	return &Inspector{cfg: cfg, extractor: extractor}, nil
}

func withDefaults(c Config) Config {
	if c.MaxEncodedBytes <= 0 {
		c.MaxEncodedBytes = DefaultMaxEncodedBytes
	}
	if c.MaxDecodedBytes <= 0 {
		c.MaxDecodedBytes = DefaultMaxDecodedBytes
	}
	if c.MaxTextBytes <= 0 {
		c.MaxTextBytes = DefaultMaxTextBytes
	}
	if c.MaxAttachments <= 0 {
		c.MaxAttachments = DefaultMaxAttachments
	}
	if c.MaxPages <= 0 {
		c.MaxPages = DefaultMaxPages
	}
	if c.MaxExpansionRatio <= 0 {
		c.MaxExpansionRatio = 20
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.MaxRedirects < 0 {
		c.MaxRedirects = 0
	}
	if len(c.AllowedMIMEs) == 0 {
		c.AllowedMIMEs = append([]string(nil), DefaultAllowedMIMEs...)
	}
	return c
}

func (i *Inspector) Status() Status {
	if i == nil {
		return Status{}
	}
	return Status{Enabled: i.cfg.Enabled, Adapter: i.cfg.Adapter, Ready: !i.cfg.Enabled || i.extractor != nil}
}
func (i *Inspector) MaterialStatuses() []func() securetransport.Status {
	var out []func() securetransport.Status
	for _, material := range i.materials {
		if status, ok := material.(interface{ Status() securetransport.Status }); ok {
			out = append(out, status.Status)
		}
	}
	return out
}
func (i *Inspector) Close() {
	if i == nil {
		return
	}
	for _, material := range i.materials {
		material.Close()
	}
}

// Inspect mutates only normalized attachment metadata and extracted text. It
// never mutates the wire body, which remains the forwarding source of truth.
func (i *Inspector) Inspect(ctx context.Context, env *core.InspectionEnvelope) error {
	if i == nil || !i.cfg.Enabled {
		for _, m := range env.Messages {
			for _, p := range m.Parts {
				if p.Attachment != nil {
					if i != nil && i.cfg.Production {
						return fail("ATTACHMENT_INSPECTION_UNAVAILABLE", nil)
					}
				}
			}
		}
		return nil
	}
	count := 0
	for mi := range env.Messages {
		for pi := range env.Messages[mi].Parts {
			part := &env.Messages[mi].Parts[pi]
			if part.Attachment == nil {
				continue
			}
			count++
			if count > i.cfg.MaxAttachments {
				return fail("ATTACHMENT_COUNT_EXCEEDED", nil)
			}
			if err := i.inspectPart(ctx, part); err != nil {
				return err
			}
		}
	}
	return nil
}

func (i *Inspector) inspectPart(ctx context.Context, part *core.ContentPart) error {
	ref := part.Attachment
	data, mimeType, err := i.load(ctx, ref)
	if err != nil {
		return err
	}
	declared := normalizeMIME(ref.MIMEType)
	if declared != "" && mimeType != "" && declared != mimeType {
		return fail("ATTACHMENT_MIME_MISMATCH", nil)
	}
	if len(data) > int(i.cfg.MaxDecodedBytes) {
		return fail("ATTACHMENT_DECODED_BYTES_EXCEEDED", nil)
	}
	if mimeType == "" {
		mimeType = normalizeMIME(ref.MIMEType)
	}
	if !allowedMIME(mimeType, i.cfg.AllowedMIMEs) {
		return fail("ATTACHMENT_MIME_NOT_ALLOWED", nil)
	}
	if !magicMatches(mimeType, data) {
		return fail("ATTACHMENT_MIME_MISMATCH", nil)
	}
	if err := checkExpansion(mimeType, data, i.cfg); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	extractCtx, cancel := context.WithTimeout(ctx, i.cfg.Timeout)
	defer cancel()
	result, err := i.extractor.Extract(extractCtx, ExtractionRequest{MIMEType: mimeType, Kind: ref.Kind, Name: ref.Name, Bytes: data, Hash: hex.EncodeToString(sum[:])})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return fail("ATTACHMENT_CANCELED", err)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return fail("ATTACHMENT_EXTRACT_TIMEOUT", err)
		}
		return fail("ATTACHMENT_EXTRACT_FAILED", err)
	}
	if result.Pages > i.cfg.MaxPages {
		return fail("ATTACHMENT_PAGE_LIMIT_EXCEEDED", nil)
	}
	if len(result.Text) > i.cfg.MaxTextBytes {
		return fail("ATTACHMENT_TEXT_BYTES_EXCEEDED", nil)
	}
	if !utf8.ValidString(result.Text) {
		return fail("ATTACHMENT_TEXT_INVALID", nil)
	}
	ref.MIMEType, ref.Hash, ref.Pages = mimeType, hex.EncodeToString(sum[:8]), result.Pages
	ref.Metadata = boundedMetadata(result.Metadata)
	ref.TextBytes = len(result.Text)
	part.Type = core.PartAttachment
	part.Text = result.Text
	return nil
}

func (i *Inspector) load(ctx context.Context, ref *core.AttachmentRef) ([]byte, string, error) {
	if ref.InlineData != "" {
		data, mimeType, err := decodeInline(ref.InlineData, i.cfg.MaxEncodedBytes, i.cfg.MaxDecodedBytes)
		return data, mimeType, err
	}
	if ref.URL == "" {
		return nil, "", fail("ATTACHMENT_SOURCE_INVALID", nil)
	}
	u, err := url.Parse(ref.URL)
	if err != nil {
		return nil, "", fail("ATTACHMENT_URL_REJECTED", nil)
	}
	if err := validateRemoteURL(u, i.cfg); err != nil {
		return nil, "", fail("ATTACHMENT_URL_REJECTED", nil)
	}
	if u.Scheme != "https" {
		return nil, "", fail("ATTACHMENT_HTTPS_REQUIRED", nil)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", fail("ATTACHMENT_URL_REJECTED", nil)
	}
	request.Header = make(http.Header) // never forward caller headers or credentials
	client := i.client
	if client == nil {
		client = &http.Client{Timeout: i.cfg.Timeout, Transport: &http.Transport{Proxy: nil, DialContext: safeDialContext(i.cfg, &net.Dialer{Timeout: i.cfg.Timeout}), MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second}, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= i.cfg.MaxRedirects {
				return errors.New("redirect limit")
			}
			return validateRemoteURL(req.URL, i.cfg)
		}}
	}
	resp, err := client.Do(request)
	if err != nil {
		return nil, "", fail("ATTACHMENT_FETCH_FAILED", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", fail("ATTACHMENT_FETCH_FAILED", nil)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, i.cfg.MaxDecodedBytes+1))
	if err != nil {
		return nil, "", fail("ATTACHMENT_FETCH_FAILED", err)
	}
	if int64(len(data)) > i.cfg.MaxDecodedBytes {
		return nil, "", fail("ATTACHMENT_DECODED_BYTES_EXCEEDED", nil)
	}
	contentType := normalizeMIME(resp.Header.Get("Content-Type"))
	if contentType == "" {
		return nil, "", fail("ATTACHMENT_CONTENT_TYPE_INVALID", nil)
	}
	return data, contentType, nil
}

func decodeInline(raw string, maxEncoded, maxDecoded int64) ([]byte, string, error) {
	if int64(len(raw)) > maxEncoded {
		return nil, "", fail("ATTACHMENT_ENCODED_BYTES_EXCEEDED", nil)
	}
	mimeType, payload := "", raw
	if strings.HasPrefix(strings.ToLower(raw), "data:") {
		comma := strings.IndexByte(raw, ',')
		if comma < 0 {
			return nil, "", fail("ATTACHMENT_BASE64_INVALID", nil)
		}
		header := raw[5:comma]
		payload = raw[comma+1:]
		parts := strings.Split(header, ";")
		if len(parts) > 0 {
			mimeType = normalizeMIME(parts[0])
		}
		isBase64 := false
		for _, p := range parts[1:] {
			if strings.EqualFold(p, "base64") {
				isBase64 = true
			}
		}
		if !isBase64 {
			return nil, "", fail("ATTACHMENT_BASE64_INVALID", nil)
		}
	}
	var data []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		data, err = enc.DecodeString(payload)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, "", fail("ATTACHMENT_BASE64_INVALID", nil)
	}
	if int64(len(data)) > maxDecoded {
		return nil, "", fail("ATTACHMENT_DECODED_BYTES_EXCEEDED", nil)
	}
	return data, mimeType, nil
}

func normalizeMIME(value string) string {
	value, _, _ = mime.ParseMediaType(strings.TrimSpace(value))
	return strings.ToLower(value)
}
func allowedMIME(value string, allowed []string) bool {
	for _, candidate := range allowed {
		if normalizeMIME(candidate) == value {
			return true
		}
	}
	return false
}
func magicMatches(mt string, b []byte) bool {
	switch mt {
	case "image/png":
		return bytes.HasPrefix(b, []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a})
	case "image/jpeg":
		return len(b) >= 3 && b[0] == 0xff && b[1] == 0xd8 && b[2] == 0xff
	case "image/gif":
		return bytes.HasPrefix(b, []byte("GIF87a")) || bytes.HasPrefix(b, []byte("GIF89a"))
	case "image/webp":
		return len(b) >= 12 && bytes.Equal(b[:4], []byte("RIFF")) && bytes.Equal(b[8:12], []byte("WEBP"))
	case "application/pdf":
		return bytes.HasPrefix(b, []byte("%PDF-"))
	case "application/zip", "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
		return len(b) >= 4 && bytes.Equal(b[:2], []byte("PK"))
	case "text/plain":
		return utf8.Valid(b)
	case "application/json":
		return json.Valid(b)
	default:
		return false
	}
}
func checkExpansion(mt string, data []byte, cfg Config) error {
	if mt != "application/zip" && mt != "application/vnd.openxmlformats-officedocument.wordprocessingml.document" {
		return nil
	}
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fail("ATTACHMENT_ARCHIVE_INVALID", nil)
	}
	if len(r.File) > cfg.MaxAttachments*128 {
		return fail("ATTACHMENT_EXPANSION_LIMIT_EXCEEDED", nil)
	}
	var expanded int64
	for _, f := range r.File {
		entrySize, ok := boundedInt64(f.UncompressedSize64)
		if !ok || entrySize > cfg.MaxDecodedBytes {
			return fail("ATTACHMENT_EXPANSION_LIMIT_EXCEEDED", nil)
		}
		if entrySize > cfg.MaxDecodedBytes-expanded {
			return fail("ATTACHMENT_EXPANSION_LIMIT_EXCEEDED", nil)
		}
		expanded += entrySize
	}
	if len(data) > 0 && expanded/int64(len(data)) > cfg.MaxExpansionRatio {
		return fail("ATTACHMENT_EXPANSION_LIMIT_EXCEEDED", nil)
	}
	return nil
}
func boundedInt64(value uint64) (int64, bool) {
	const maxInt64 = uint64(1<<63 - 1)
	if value > maxInt64 {
		return 0, false
	}
	return int64(value), true
}
func boundedMetadata(in map[string]string) map[string]string {
	out := map[string]string{}
	n := 0
	for k, v := range in {
		if n >= 8 {
			break
		}
		if k != "mime_type" && k != "bytes" && k != "pages" && k != "inspection" && k != "profile" && k != "language" {
			continue
		}
		if len(k) > 32 || len(v) > 64 {
			continue
		}
		out[safeLabel(k)] = safeLabel(v)
		n++
	}
	return out
}
func safeLabel(v string) string {
	var b strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-/ ", r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func validateRemoteURL(u *url.URL, cfg Config) error {
	if u == nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("unsafe remote URL")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	allowed := false
	for _, candidate := range cfg.AllowedHosts {
		candidate = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(candidate, ".")))
		if candidate != "" && (host == candidate || strings.HasSuffix(host, "."+candidate)) {
			allowed = true
			break
		}
	}
	if !allowed {
		return errors.New("host is not allowlisted")
	}
	_, err := resolveAllowedIPs(context.Background(), host, cfg)
	return err
}

func resolveAllowedIPs(ctx context.Context, host string, cfg Config) ([]net.IP, error) {
	var ips []net.IP
	if parsed := net.ParseIP(host); parsed != nil {
		ips = []net.IP{parsed}
	} else {
		resolved, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, errors.New("host resolution failed")
		}
		ips = resolved
	}
	if len(ips) == 0 {
		return nil, errors.New("host resolution failed")
	}
	for _, ip := range ips {
		if isPrivateIP(ip) && !cfg.AllowPrivateHosts {
			return nil, errors.New("private address rejected")
		}
	}
	return ips, nil
}

func safeDialContext(cfg Config, dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("invalid remote address")
		}
		ips, err := resolveAllowedIPs(ctx, host, cfg)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, ip := range ips {
			conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		if lastErr == nil {
			lastErr = errors.New("remote connection failed")
		}
		return nil, lastErr
	}
}
func isPrivateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// BuiltinExtractor is intentionally bounded and deterministic. It supports
// text fixtures and image/PDF metadata only; OCR and document engines belong
// behind the authenticated private HTTP adapter.
type BuiltinExtractor struct{}

func (BuiltinExtractor) Extract(ctx context.Context, req ExtractionRequest) (ExtractionResult, error) {
	select {
	case <-ctx.Done():
		return ExtractionResult{}, ctx.Err()
	default:
	}
	result := ExtractionResult{Metadata: map[string]string{"mime_type": req.MIMEType, "bytes": strconv.Itoa(len(req.Bytes))}}
	switch req.MIMEType {
	case "text/plain", "application/json":
		result.Text = string(req.Bytes)
	case "application/pdf":
		result.Pages = bytes.Count(req.Bytes, []byte("/Type /Page"))
		if result.Pages == 0 {
			result.Pages = 1
		}
	case "image/png", "image/jpeg", "image/gif", "image/webp":
		result.Metadata["inspection"] = "metadata_only"
	default:
		result.Metadata["inspection"] = "archive_metadata_only"
	}
	return result, nil
}

type HTTPExtractor struct {
	endpoint string
	client   *http.Client
}

func NewHTTPExtractor(endpoint string, client *http.Client) *HTTPExtractor {
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPExtractor{endpoint: strings.TrimRight(endpoint, "/"), client: client}
}
func (h *HTTPExtractor) Extract(ctx context.Context, req ExtractionRequest) (ExtractionResult, error) {
	body, err := json.Marshal(struct {
		MIMEType string `json:"mime_type"`
		Kind     string `json:"kind"`
		Name     string `json:"name,omitempty"`
		Hash     string `json:"hash"`
		Data     string `json:"data"`
	}{req.MIMEType, req.Kind, req.Name, req.Hash, base64.RawStdEncoding.EncodeToString(req.Bytes)})
	if err != nil {
		return ExtractionResult{}, err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint+"/extract", bytes.NewReader(body))
	if err != nil {
		return ExtractionResult{}, err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	resp, err := h.client.Do(r)
	if err != nil {
		return ExtractionResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ExtractionResult{}, errors.New("extractor rejected request")
	}
	var out ExtractionResult
	limited := io.LimitReader(resp.Body, 1<<20)
	if err := json.NewDecoder(limited).Decode(&out); err != nil {
		return ExtractionResult{}, err
	}
	return out, nil
}

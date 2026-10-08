package attachment

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aegisllm/gateway/internal/core"
)

type testExtractor struct {
	result ExtractionResult
	err    error
	seen   ExtractionRequest
}

type contextExtractor struct{}

func (contextExtractor) Extract(ctx context.Context, _ ExtractionRequest) (ExtractionResult, error) {
	<-ctx.Done()
	return ExtractionResult{}, ctx.Err()
}

func (e *testExtractor) Extract(_ context.Context, in ExtractionRequest) (ExtractionResult, error) {
	e.seen = in
	return e.result, e.err
}

func ref(data, mt string) *core.InspectionEnvelope {
	return &core.InspectionEnvelope{Messages: []core.Message{{Parts: []core.ContentPart{{Type: core.PartAttachment, Attachment: &core.AttachmentRef{Kind: "file", MIMEType: mt, InlineData: data}}}}}}
}
func inspector(t *testing.T, ext Extractor, mut func(*Config)) *Inspector {
	t.Helper()
	cfg := Config{Enabled: true, Adapter: "builtin", MaxEncodedBytes: 1024, MaxDecodedBytes: 64, MaxTextBytes: 64, MaxAttachments: 2, MaxPages: 2, MaxExpansionRatio: 2, Timeout: time.Second}
	if mut != nil {
		mut(&cfg)
	}
	got, err := New(cfg, ext)
	if err != nil {
		t.Fatal(err)
	}
	return got
}
func dataURL(mt string, b []byte) string {
	return "data:" + mt + ";base64," + base64.RawStdEncoding.EncodeToString(b)
}

func TestInlineBase64AndExtractionAreBounded(t *testing.T) {
	ext := &testExtractor{result: ExtractionResult{Text: "secret from document", Pages: 1}}
	i := inspector(t, ext, nil)
	env := ref(dataURL("text/plain", []byte("document")), "")
	if err := i.Inspect(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if env.Messages[0].Parts[0].Text != "secret from document" || ext.seen.MIMEType != "text/plain" {
		t.Fatalf("extraction not normalized: %+v", env)
	}
	if env.Messages[0].Parts[0].Attachment.Hash == "" || len(env.Messages[0].Parts[0].Attachment.InlineData) == 0 {
		t.Fatal("metadata missing")
	}
}

func TestMalformedBase64MIMEAndLimitsFailClosed(t *testing.T) {
	cases := []struct{ name, body, mt, code string }{
		{"bad base64", "data:text/plain;base64,%%%", "", "ATTACHMENT_BASE64_INVALID"},
		{"spoof", dataURL("image/png", []byte("plain")), "", "ATTACHMENT_MIME_MISMATCH"},
		{"decoded limit", dataURL("text/plain", []byte(strings.Repeat("x", 65))), "", "ATTACHMENT_DECODED_BYTES_EXCEEDED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := inspector(t, &testExtractor{}, nil).Inspect(context.Background(), ref(tc.body, tc.mt))
			var ae *Error
			if !errors.As(err, &ae) || ae.Code != tc.code {
				t.Fatalf("error=%v want %s", err, tc.code)
			}
		})
	}
}

func TestDeclaredMIMECannotSpoofDataURLMIME(t *testing.T) {
	i := inspector(t, &testExtractor{}, nil)
	err := i.Inspect(context.Background(), ref(dataURL("text/plain", []byte("plain")), "image/png"))
	var ae *Error
	if !errors.As(err, &ae) || ae.Code != "ATTACHMENT_MIME_MISMATCH" {
		t.Fatalf("MIME spoof error=%v", err)
	}
}

func TestCountPagesAndExpansionLimits(t *testing.T) {
	i := inspector(t, &testExtractor{result: ExtractionResult{Pages: 3}}, nil)
	env := ref(dataURL("application/pdf", []byte("%PDF-1.7 /Type /Page /Type /Page")), "")
	var ae *Error
	if err := i.Inspect(context.Background(), env); !errors.As(err, &ae) || ae.Code != "ATTACHMENT_PAGE_LIMIT_EXCEEDED" {
		t.Fatalf("pages error=%v", err)
	}
	zipPayload := []byte{'P', 'K', 3, 4}
	check := inspector(t, &testExtractor{}, func(c *Config) { c.MaxExpansionRatio = 1 })
	if err := check.Inspect(context.Background(), ref(dataURL("application/zip", zipPayload), "")); err == nil {
		t.Fatal("invalid archive must fail closed")
	}
}

func TestURLPolicyRejectsUnsafeSources(t *testing.T) {
	i := inspector(t, &testExtractor{}, func(c *Config) { c.AllowedHosts = []string{"allowed.invalid"} })
	for _, raw := range []string{"http://allowed.invalid/a", "https://not-allowed.invalid/a", "https://allowed.invalid/a?secret=1", "file:///etc/passwd"} {
		env := &core.InspectionEnvelope{Messages: []core.Message{{Parts: []core.ContentPart{{Type: core.PartAttachment, Attachment: &core.AttachmentRef{Kind: "image", URL: raw}}}}}}
		var ae *Error
		if err := i.Inspect(context.Background(), env); !errors.As(err, &ae) || (ae.Code != "ATTACHMENT_URL_REJECTED" && ae.Code != "ATTACHMENT_HTTPS_REQUIRED") {
			t.Fatalf("url %q error=%v", raw, err)
		}
	}
}

func TestExtractorTimeoutAndCancellationAreDeterministic(t *testing.T) {
	i := inspector(t, contextExtractor{}, func(c *Config) { c.Timeout = time.Millisecond })
	var ae *Error
	if err := i.Inspect(context.Background(), ref(dataURL("text/plain", []byte("x")), "")); !errors.As(err, &ae) || ae.Code != "ATTACHMENT_EXTRACT_TIMEOUT" {
		t.Fatalf("timeout error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ae = nil
	if err := inspector(t, BuiltinExtractor{}, nil).Inspect(ctx, ref(dataURL("text/plain", []byte("x")), "")); !errors.As(err, &ae) || ae.Code != "ATTACHMENT_CANCELED" {
		t.Fatalf("cancel error=%v", err)
	}
}

func TestFakeHTTPExtractorContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		if json.NewDecoder(r.Body).Decode(&in) != nil || in["data"] == nil {
			t.Errorf("bad extractor request")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"cross block secret","pages":1,"metadata":{"profile":"fake"}}`))
	}))
	defer server.Close()
	ext := NewHTTPExtractor(server.URL, server.Client())
	i := inspector(t, ext, func(c *Config) { c.Adapter = "builtin" })
	i.extractor = ext
	env := ref(dataURL("text/plain", []byte("payload")), "")
	if err := i.Inspect(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if env.Messages[0].Parts[0].Text != "cross block secret" {
		t.Fatal("fake extraction result not used")
	}
}

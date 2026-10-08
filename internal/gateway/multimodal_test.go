package gateway

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/aegisllm/gateway/internal/attachment"
	"github.com/aegisllm/gateway/internal/core"
)

type multimodalExtractor struct {
	text string
	err  error
}

func (e multimodalExtractor) Extract(context.Context, attachment.ExtractionRequest) (attachment.ExtractionResult, error) {
	return attachment.ExtractionResult{Text: e.text, Pages: 1}, e.err
}

func TestProtocolAttachmentShapesNormalizeWithoutWireRewrite(t *testing.T) {
	png := base64.RawStdEncoding.EncodeToString([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a})
	cases := []struct{ name, path, body string }{
		{"openai chat data URL", "/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,` + png + `"}}]}]}`},
		{"openai responses file", "/v1/responses", `{"model":"m","input":[{"role":"user","content":[{"type":"input_file","file_data":"data:text/plain;base64,SGVsbG8="}]}]}`},
		{"anthropic document", "/v1/messages", `{"model":"m","max_tokens":4,"messages":[{"role":"user","content":[{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"JVBERi0xLjQ="}}]}]}`},
		{"generic alias", "/chat/completions", `{"model":"m","messages":[{"role":"user","content":[{"type":"attachment","mime_type":"text/plain","data":"data:text/plain;base64,SGVsbG8="}]}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, err := NormalizerFor(tc.path).ParseRequest([]byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			var found int
			for _, part := range env.Messages[0].Parts {
				if part.Attachment != nil {
					found++
				}
			}
			if found != 1 {
				t.Fatalf("attachments=%d env=%+v", found, env)
			}
			if strings.Contains(env.SafeString(), "SGVsbG8") {
				t.Fatal("safe summary leaked payload")
			}
		})
	}
}

func TestOpenAIImageDataURLIsInspectedInline(t *testing.T) {
	png := base64.RawStdEncoding.EncodeToString([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a})
	env, err := NormalizerFor("/v1/chat/completions").ParseRequest([]byte(`{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,` + png + `"}}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	inspector, err := attachment.New(attachment.Config{Enabled: true, Adapter: "builtin", MaxDecodedBytes: 1024, MaxTextBytes: 1024, MaxAttachments: 1, MaxPages: 1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer inspector.Close()
	if err := inspector.Inspect(context.Background(), env); err != nil {
		t.Fatalf("data URL inspection failed: %v", err)
	}
	if got := env.Messages[0].Parts[0].Attachment.MIMEType; got != "image/png" {
		t.Fatalf("MIME type=%q", got)
	}
}

func TestGenericAttachmentAliasWithoutTypeIsInspected(t *testing.T) {
	env, err := NormalizerFor("/chat/completions").ParseRequest([]byte(`{"model":"m","attachments":[{"mime_type":"text/plain","data":"data:text/plain;base64,SGVsbG8="}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(env.Messages) != 1 || len(env.Messages[0].Parts) != 1 || env.Messages[0].Parts[0].Attachment == nil {
		t.Fatalf("attachment alias was not normalized: %+v", env)
	}
}

func TestExtractedTextJoinsExistingDecisionPathAcrossBlocks(t *testing.T) {
	pipe, _ := newRealPipeline(t)
	pipe.SetSecurityMode(ModeEnforce)
	ext, err := attachment.New(attachment.Config{Enabled: true, Adapter: "builtin", MaxDecodedBytes: 1024, MaxTextBytes: 1024, MaxAttachments: 4, MaxPages: 4, MaxExpansionRatio: 20}, multimodalExtractor{text: "Abc123Xyz_-456DefGhi"})
	if err != nil {
		t.Fatal(err)
	}
	defer ext.Close()
	pipe.SetAttachmentInspector(ext)
	env, err := NormalizerFor("/v1/chat/completions").ParseRequest([]byte(`{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"glpat-"},{"type":"file","file_data":"data:text/plain;base64,SGVsbG8="}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	decision, err := pipe.ProcessRequestContext(context.Background(), env, nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != core.ActionBlock {
		t.Fatalf("split secret bypassed attachment boundary: %+v", decision)
	}
}

func TestAttachmentFailuresBecomeDeterministicBlocks(t *testing.T) {
	pipe, _ := newRealPipeline(t)
	pipe.SetSecurityMode(ModeEnforce)
	ext, err := attachment.New(attachment.Config{Enabled: true, Adapter: "builtin", MaxDecodedBytes: 16, MaxTextBytes: 16, MaxAttachments: 1, MaxPages: 1, MaxExpansionRatio: 2}, multimodalExtractor{})
	if err != nil {
		t.Fatal(err)
	}
	defer ext.Close()
	pipe.SetAttachmentInspector(ext)
	env, err := NormalizerFor("/v1/chat/completions").ParseRequest([]byte(`{"model":"m","messages":[{"role":"user","content":[{"type":"file","file_data":"data:text/plain;base64,%%%"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	decision, err := pipe.ProcessRequestContext(context.Background(), env, nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != core.ActionBlock || decision.Code != "ATTACHMENT_BASE64_INVALID" {
		t.Fatalf("failure mapping=%+v", decision)
	}
}

func TestAttachmentRedactionIsNotClaimedForBinaryPayloads(t *testing.T) {
	pipe, _ := newRealPipeline(t)
	pipe.SetSecurityMode(ModeEnforce)
	ext, err := attachment.New(attachment.Config{Enabled: true, Adapter: "builtin", MaxDecodedBytes: 1024, MaxTextBytes: 1024, MaxAttachments: 1, MaxPages: 1}, multimodalExtractor{text: "call 0812345678"})
	if err != nil {
		t.Fatal(err)
	}
	defer ext.Close()
	pipe.SetAttachmentInspector(ext)
	env, err := NormalizerFor("/v1/chat/completions").ParseRequest([]byte(`{"model":"m","messages":[{"role":"user","content":[{"type":"file","file_data":"data:text/plain;base64,SGVsbG8="}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	env.Target.Provider = "cloud"
	decision, err := pipe.ProcessRequestContext(context.Background(), env, nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != core.ActionBlock || decision.Code != "ATTACHMENT_TRANSFORM_UNSUPPORTED" {
		t.Fatalf("binary rewrite was claimed: %+v", decision)
	}
}

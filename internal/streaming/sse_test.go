package streaming

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestParserPreservesCommentsMultilineAndDone(t *testing.T) {
	p := NewParser(strings.NewReader(": keepalive\n\ndata: {\"a\":\ndata: 1}\nevent: message\n\ndata: [DONE]\n\n"), Config{MaxEventBytes: 1024})
	first, err := p.Next()
	if err != nil || !first.Comment || first.HasData {
		t.Fatalf("comment event = %+v, %v", first, err)
	}
	second, err := p.Next()
	if err != nil || second.Data != "{\"a\":\n1}" || second.Event != "message" {
		t.Fatalf("multiline event = %+v, %v", second, err)
	}
	done, err := p.Next()
	if err != nil || !done.IsDone || string(done.Encode(done.Data)) != "data: [DONE]\n\n" {
		t.Fatalf("done event = %+v, %v", done, err)
	}
	if _, err := p.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("final error = %v", err)
	}
}

func TestParserRejectsOversizedEvent(t *testing.T) {
	p := NewParser(bytes.NewBufferString("data: 123456789\n\n"), Config{MaxEventBytes: 8})
	if _, err := p.Next(); !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("error = %v", err)
	}
}

func TestExtractProviderDeltasAndRewrite(t *testing.T) {
	cases := []struct {
		family string
		data   string
		want   string
	}{
		{"openai-chat", `{"choices":[{"delta":{"content":"secret"}}]}`, `{"choices":[{"delta":{"content":"[REDACTED]"}}]}`},
		{"openai-responses", `{"type":"response.output_text.delta","delta":"secret"}`, `{"type":"response.output_text.delta","delta":"[REDACTED]"}`},
		{"anthropic", `{"type":"content_block_delta","delta":{"partial_json":"secret"}}`, `{"type":"content_block_delta","delta":{"partial_json":"[REDACTED]"}}`},
		{"anthropic-input-json", `{"type":"content_block_delta","delta":{"input_json_delta":{"partial_json":"secret"}}}`, `{"type":"content_block_delta","delta":{"input_json_delta":{"partial_json":"[REDACTED]"}}}`},
	}
	for _, tc := range cases {
		t.Run(tc.family, func(t *testing.T) {
			fragments, err := Extract(tc.family, tc.data)
			if err != nil || len(fragments) != 1 {
				t.Fatalf("fragments = %+v, %v", fragments, err)
			}
			got, err := Rewrite(tc.family, tc.data, fragments, map[int]string{0: "[REDACTED]"})
			var gotDoc, wantDoc any
			_ = json.Unmarshal([]byte(got), &gotDoc)
			_ = json.Unmarshal([]byte(tc.want), &wantDoc)
			if err != nil || !reflect.DeepEqual(gotDoc, wantDoc) {
				t.Fatalf("rewrite = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func FuzzParser(f *testing.F) {
	f.Add("data: hello\n\n")
	f.Add(": ping\n\ndata: [DONE]\n\n")
	f.Fuzz(func(t *testing.T, input string) {
		p := NewParser(strings.NewReader(input), Config{MaxEventBytes: 4096})
		for i := 0; i < 32; i++ {
			if _, err := p.Next(); errors.Is(err, io.EOF) || errors.Is(err, ErrEventTooLarge) {
				return
			}
		}
	})
}

func BenchmarkParser(b *testing.B) {
	payload := strings.Repeat("data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n", 32)
	b.ReportMetric(float64(len(payload)), "bytes/op-input")
	for i := 0; i < b.N; i++ {
		p := NewParser(strings.NewReader(payload), Config{MaxEventBytes: 64 * 1024})
		for {
			event, err := p.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				b.Fatal(err)
			}
			_, _ = Extract("openai-chat", event.Data)
		}
	}
}

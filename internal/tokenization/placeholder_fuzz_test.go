package tokenization

import "testing"

func FuzzPlaceholderParser(f *testing.F) {
	f.Add("<v1.phone.0123456789abcdef.00000000.00000000000000000000000000000000>")
	f.Add("plain text")
	codec, err := NewPlaceholderCodec([]byte("fuzz-placeholder-key"), nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, value string) {
		_, _ = codec.Parse(value)
	})
}

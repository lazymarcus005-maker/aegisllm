package detectors

import (
	"encoding/base64"
	"testing"
)

func BenchmarkEvasionTransforms(b *testing.B) {
	secret := "sk-abcdefghijklmnopqrstuvwxyz123456"
	cases := map[string]string{
		"nfkc":         "ｓｋ－abcdefghijklmnopqrstuvwxyz123456",
		"base64":       base64.StdEncoding.EncodeToString([]byte(secret)),
		"percent":      "%73%6b%2dabcdefghijklmnopqrstuvwxyz123456",
		"json_unicode": `{"payload":"\u0073\u006b\u002d\u0061\u0062\u0063\u0064\u0065\u0066\u0067\u0068\u0069\u006a\u006b\u006c\u006d\u006e\u006f\u0070\u0071\u0072\u0073\u0074\u0075\u0076\u0077\u0078\u0079\u007a\u0031\u0032\u0033\u0034\u0035\u0036"}`,
	}
	reg := NewRegistry(nil)
	for _, d := range SecretDetectors("") {
		reg.Register(d)
	}
	for name, text := range cases {
		b.Run(name, func(b *testing.B) {
			env := envelopeWith(text)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = reg.RunAll(env)
			}
		})
	}
}

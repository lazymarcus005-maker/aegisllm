package policy

import "testing"

func FuzzPolicyLoader(f *testing.F) {
	f.Add([]byte("id: test\nversion: 1\ndefault: {action: allow}\nsafe_default: {action: block}\n"))
	f.Add([]byte("id: test\nversion: 1\ndefault: {action: tokenize}\nsafe_default: {action: block}\nevasion: {}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Load(data)
	})
}

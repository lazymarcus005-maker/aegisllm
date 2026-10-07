package policydistribution

import "testing"

func FuzzBundlePublicKeyParser(f *testing.F) {
	f.Add("")
	f.Add("not-a-public-key")
	f.Fuzz(func(t *testing.T, value string) {
		_ = ParsePublicKey(value)
	})
}

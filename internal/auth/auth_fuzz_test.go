package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func FuzzJWTParser(f *testing.F) {
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.invalid")
	f.Add("not-a-token")
	f.Fuzz(func(t *testing.T, token string) {
		_, _ = jwt.Parse(token, func(*jwt.Token) (any, error) { return []byte("fuzz-key"), nil })
	})
}

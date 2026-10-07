package gateway

import (
	"os"
	"strconv"
)

// Security modes (FR-018).
const (
	ModeOff     = "off"
	ModeShadow  = "shadow"
	ModeEnforce = "enforce"
)

// Config holds all gateway runtime configuration, sourced from the
// environment (see .env.example).
type Config struct {
	ListenAddr              string
	UpstreamBaseURL         string
	UpstreamAuthMode        string // none | bearer | header
	UpstreamAPIKey          string
	UpstreamAuthHeaderName  string
	UpstreamAuthHeaderValue string
	UpstreamChatPathPrefix  string
	MaxBodyBytes            int64
	SecurityMode            string // off | shadow | enforce
	HeaderApplication       string
	HeaderTenant            string
	HeaderUser              string
	HeaderTargetProvider    string
	DefaultTargetProvider   string
}

// LoadConfig reads configuration from the process environment.
func LoadConfig() Config {
	return configFrom(os.Getenv)
}

func configFrom(get func(string) string) Config {
	return Config{
		ListenAddr:              getenvDefault(get, "LISTEN_ADDR", ":8080"),
		UpstreamBaseURL:         get("UPSTREAM_BASE_URL"),
		UpstreamAuthMode:        getenvDefault(get, "UPSTREAM_AUTH_MODE", "none"),
		UpstreamAPIKey:          get("UPSTREAM_API_KEY"),
		UpstreamAuthHeaderName:  getenvDefault(get, "UPSTREAM_AUTH_HEADER_NAME", "X-Upstream-Api-Key"),
		UpstreamAuthHeaderValue: get("UPSTREAM_AUTH_HEADER_VALUE"),
		UpstreamChatPathPrefix:  get("UPSTREAM_CHAT_PATH_PREFIX"),
		MaxBodyBytes:            getenvInt64(get, "MAX_BODY_BYTES", 1<<20),
		SecurityMode:            getenvDefault(get, "SECURITY_MODE", ModeOff),
		HeaderApplication:       getenvDefault(get, "HEADER_APPLICATION", "X-Application-Id"),
		HeaderTenant:            getenvDefault(get, "HEADER_TENANT", "X-Tenant-Id"),
		HeaderUser:              getenvDefault(get, "HEADER_USER", "X-User-Id"),
		HeaderTargetProvider:    getenvDefault(get, "HEADER_TARGET_PROVIDER", "X-Target-Provider"),
		DefaultTargetProvider:   getenvDefault(get, "DEFAULT_TARGET_PROVIDER", "cloud"),
	}
}

func getenvDefault(get func(string) string, key, def string) string {
	if v := get(key); v != "" {
		return v
	}
	return def
}

func getenvInt64(get func(string) string, key string, def int64) int64 {
	if v := get(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return def
}

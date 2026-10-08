// Command vaulttool performs privacy-safe token-vault operations. It accepts
// only hashed scope/index material for revocation and never prints key,
// ciphertext, placeholder, or original-value data.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aegisllm/gateway/internal/securetransport"
	"github.com/aegisllm/gateway/internal/tokenization"
	"github.com/redis/go-redis/v9"
)

type safeScopeFile struct {
	SessionIndexHash string `json:"session_index_hash"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "status":
		runStatus(os.Args[2:])
	case "verify-keyring":
		runVerifyKeyring(os.Args[2:])
	case "revoke-session":
		runRevoke(os.Args[2:])
	case "rotate-plan":
		runRotatePlan(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: vaulttool {status|verify-keyring|revoke-session|rotate-plan} [flags]")
}

func runStatus(args []string) {
	f := flag.NewFlagSet("status", flag.ExitOnError)
	redisURL := f.String("redis-url", os.Getenv("TOKEN_VAULT_REDIS_URL"), "Redis URL")
	if err := f.Parse(args); err != nil {
		fail("invalid status flags")
	}
	out := map[string]any{"schema_version": 1, "status": "configured"}
	if *redisURL != "" {
		client, err := redis.ParseURL(*redisURL)
		if err != nil {
			out["redis"] = "invalid"
		} else {
			rdb := redis.NewClient(client)
			defer closeRedis(rdb)
			if err := rdb.Ping(context.Background()).Err(); err != nil {
				out["redis"] = "unavailable"
			} else {
				out["redis"] = "ready"
			}
		}
	} else {
		out["redis"] = "unconfigured"
	}
	write(out)
}

func runVerifyKeyring(args []string) {
	f := flag.NewFlagSet("verify-keyring", flag.ExitOnError)
	path := f.String("file", os.Getenv("TOKEN_VAULT_KEYRING_FILE"), "keyring file")
	if err := f.Parse(args); err != nil {
		fail("invalid verify-keyring flags")
	}
	data, err := securetransport.ReadTrustedFile(*path)
	if err != nil {
		fail("keyring unavailable")
		return
	}
	kr, err := tokenization.ParseKeyring(data)
	if err != nil {
		fail("keyring invalid")
		return
	}
	write(map[string]any{"schema_version": 1, "status": "verified", "key_count": len(kr.KeyIDs()), "active_configured": kr.ActiveKeyID() != ""})
}

func runRotatePlan(args []string) {
	f := flag.NewFlagSet("rotate-plan", flag.ExitOnError)
	path := f.String("file", os.Getenv("TOKEN_VAULT_KEYRING_FILE"), "keyring file")
	if err := f.Parse(args); err != nil {
		fail("invalid rotate-plan flags")
	}
	data, err := securetransport.ReadTrustedFile(*path)
	if err != nil {
		fail("keyring unavailable")
		return
	}
	kr, err := tokenization.ParseKeyring(data)
	if err != nil {
		fail("keyring invalid")
		return
	}
	write(map[string]any{"schema_version": 1, "operation": "rotate-plan", "status": "ready", "retained_key_count": len(kr.KeyIDs()), "removal": "blocked until live-record dependency is absent"})
}

func runRevoke(args []string) {
	f := flag.NewFlagSet("revoke-session", flag.ExitOnError)
	redisURL := f.String("redis-url", os.Getenv("TOKEN_VAULT_REDIS_URL"), "Redis URL")
	prefix := f.String("prefix", "tokvault", "Redis prefix")
	hash := f.String("index-hash", "", "already-derived session index hash")
	file := f.String("scope-file", "", "secure file containing session_index_hash")
	if err := f.Parse(args); err != nil {
		fail("invalid revoke-session flags")
	}
	value := strings.TrimSpace(*hash)
	if value == "" && *file != "" {
		data, err := securetransport.ReadTrustedFile(*file)
		if err != nil {
			fail("scope file unavailable")
			return
		}
		var in safeScopeFile
		if json.Unmarshal(data, &in) == nil {
			value = strings.TrimSpace(in.SessionIndexHash)
		}
	}
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "\r\n") {
		fail("hashed scope input required")
		return
	}
	if *redisURL == "" {
		fail("redis unavailable")
		return
	}
	opts, err := redis.ParseURL(*redisURL)
	if err != nil {
		fail("redis unavailable")
		return
	}
	rdb := redis.NewClient(opts)
	defer closeRedis(rdb)
	// The backend accepts only the derived index and deletes records through
	// its bounded index. It does not need the vault encryption key.
	vault := tokenization.NewRedisVault(rdb, *prefix, time.Hour)
	if err := vault.RevokeIndex(context.Background(), value); err != nil {
		fail("session revocation failed")
		return
	}
	write(map[string]any{"schema_version": 1, "status": "revoked"})
}

func write(value any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(value)
}

func closeRedis(client *redis.Client) {
	if err := client.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "redis close:", err)
	}
}

func fail(message string) { fmt.Fprintln(os.Stderr, message); os.Exit(1) }

// Command audittool provides operator-safe metadata inspection for the audit
// WAL. It never prints event payloads.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/aegisllm/gateway/internal/audit"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	dir := fs.String("dir", "", "audit WAL directory")
	walDir := fs.String("wal-dir", "", "alias for -dir")
	hmacFile := fs.String("hmac-key-file", "", "file-backed WAL HMAC key")
	keyring := fs.String("encryption-keyring", "", "file-backed AES-GCM keyring")
	confirm := fs.Bool("confirm", false, "confirm quarantine during repair")
	_ = fs.Parse(os.Args[2:])
	if *dir == "" {
		*dir = *walDir
	}
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "-dir is required")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "verify":
		w, err := open(*dir, *hmacFile, *keyring)
		if err == nil {
			err = w.Verify(context.Background())
			_ = w.Close()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "audit verification failed")
			os.Exit(1)
		}
		fmt.Println(`{"status":"verified"}`)
	case "inspect":
		w, err := open(*dir, *hmacFile, *keyring)
		if err != nil {
			fmt.Fprintln(os.Stderr, "audit inspection failed")
			os.Exit(1)
		}
		status := w.Status()
		_ = w.Close()
		data, _ := json.Marshal(status)
		fmt.Println(string(data))
	case "repair":
		key, keyErr := keyMaterial(*hmacFile)
		if keyErr != nil {
			fmt.Fprintln(os.Stderr, "audit key unavailable")
			os.Exit(1)
		}
		report, err := audit.RepairWithConfig(audit.WALConfig{Dir: *dir, HMACKey: key, EncryptionKeyring: *keyring}, *confirm)
		if err != nil {
			fmt.Fprintln(os.Stderr, "audit repair requires explicit confirmation or failed")
			os.Exit(1)
		}
		data, _ := json.Marshal(report)
		fmt.Println(string(data))
	default:
		usage()
		os.Exit(2)
	}
}

func open(dir, hmacFile, keyring string) (*audit.WAL, error) {
	key, err := keyMaterial(hmacFile)
	if err != nil {
		return nil, err
	}
	return audit.OpenWAL(audit.WALConfig{Dir: dir, HMACKey: key, EncryptionKeyring: keyring})
}

func keyMaterial(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	return os.ReadFile(path)
}

func usage() { fmt.Fprintln(os.Stderr, "usage: audittool verify|inspect|repair -dir PATH [-confirm]") }

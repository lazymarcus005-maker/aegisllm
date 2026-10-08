// Command fleetctl is a thin operator client for the fleet contract. It
// never executes a remote command and prints only the sanitized control-plane
// projections returned by the API.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	base := os.Getenv("FLEET_CONTROL_PLANE_URL")
	if base == "" {
		base = "https://fleet-control-plane"
	}
	command := os.Args[1]
	fs := flag.NewFlagSet(command, flag.ExitOnError)
	urlFlag := fs.String("url", base, "fleet control-plane URL")
	input := fs.String("input", "", "JSON desired state or request file")
	id := fs.String("id", "", "opaque rollout or gateway ID")
	tenant := fs.String("tenant", "", "tenant scope")
	confirm := fs.Bool("confirm", false, "explicitly confirm a broad or destructive action")
	token := fs.String("token", os.Getenv("FLEET_OPERATOR_TOKEN"), "operator bearer token")
	if err := fs.Parse(os.Args[2:]); err != nil {
		fatal(err)
	}

	path, body, method := "", []byte(nil), http.MethodGet
	switch command {
	case "inventory", "status":
		path = "/v1/fleet/inventory?limit=100"
	case "gateway-status":
		path = "/v1/fleet/gateways/" + *id
	case "compliance":
		path = "/v1/fleet/compliance"
	case "desired-validate":
		method, path, body = http.MethodPost, "/v1/fleet/desired/validate", readInput(*input)
	case "desired-publish":
		method, path, body = http.MethodPost, "/v1/fleet/desired/publish", readInput(*input)
	case "rollout-create":
		method, path, body = http.MethodPost, "/v1/fleet/rollouts", readInput(*input)
	case "rollout-inspect":
		path = "/v1/fleet/rollouts/" + *id + "/status"
	case "rollout-pause":
		method, path, body = http.MethodPost, "/v1/fleet/rollouts/"+*id+"/pause", jsonBody(map[string]any{"reason": "operator pause", "confirm": *confirm})
	case "rollout-promote":
		method, path, body = http.MethodPost, "/v1/fleet/rollouts/"+*id+"/promote", jsonBody(map[string]any{"confirm": *confirm})
	case "enrollment-revoke":
		method, path, body = http.MethodPost, "/v1/fleet/enrollment/"+*id+"/revoke", jsonBody(map[string]any{"tenant": *tenant, "confirm": *confirm})
	default:
		usage()
		os.Exit(2)
	}
	if len(body) == 0 && method == http.MethodPost {
		fmt.Fprintln(os.Stderr, "--input is required")
		os.Exit(2)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	req, err := http.NewRequest(method, strings.TrimRight(*urlFlag, "/")+path, bytes.NewReader(body))
	if err != nil {
		fatal(err)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if *token != "" {
		req.Header.Set("Authorization", "Bearer "+*token)
	}
	resp, err := client.Do(req)
	if err != nil {
		fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "fleet API status %d\n", resp.StatusCode)
		os.Exit(1)
	}
	var out any
	if json.Unmarshal(data, &out) == nil {
		pretty, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(pretty))
	} else if len(data) > 0 {
		fmt.Println(string(data))
	}
}

func readInput(path string) []byte {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- offline operator CLI intentionally reads the explicitly supplied artifact path.
	if err != nil {
		fatal(err)
	}
	return data
}
func jsonBody(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		fatal(err)
	}
	return data
}
func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
func usage() {
	fmt.Fprintln(os.Stderr, "usage: fleetctl <inventory|status|gateway-status|compliance|desired-validate|desired-publish|rollout-create|rollout-inspect|rollout-pause|rollout-promote|enrollment-revoke> [flags]")
}

#!/usr/bin/env bash
set -euo pipefail

# Generates all material outside the repository. The openssl listeners model
# the verified mTLS seams used by upstream, Laya, and Redis; the Go test covers
# the exact shared transport and hostname/client-CA behavior.
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$tmp_dir"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=aegis-smoke-ca" \
  -keyout ca.key -out ca.pem >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout server.key -out server.csr >/dev/null 2>&1
openssl x509 -req -days 1 -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -extfile <(printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth') >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=aegis-smoke-client" -keyout client.key -out client.csr >/dev/null 2>&1
openssl x509 -req -days 1 -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out client.pem -extfile <(printf 'extendedKeyUsage=clientAuth') >/dev/null 2>&1

pids=()
cleanup_listeners() { for pid in "${pids[@]:-}"; do kill "$pid" 2>/dev/null || true; done; }
trap 'cleanup_listeners; rm -rf "$tmp_dir"' EXIT
for port in 19443 18300 16379; do
  openssl s_server -quiet -accept "$port" -cert server.pem -key server.key -CAfile ca.pem -Verify 1 >/dev/null 2>&1 &
  pids+=("$!")
done
sleep 1
for port in 19443 18300 16379; do
  printf '' | openssl s_client -quiet -connect "127.0.0.1:$port" -servername localhost \
    -CAfile ca.pem -cert client.pem -key client.key -verify_return_error >/dev/null 2>&1
done

(cd "$repo_root" && go test ./internal/securetransport -run 'TestTLSVerificationAndMTLS$' -count=1)
echo "ephemeral upstream/Laya/Redis mTLS seam: OK"

#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${RELEASE_OUT:-$root/build/release}
mkdir -p "$out/security"
go vet ./... >"$out/security/vet.txt"
if command -v staticcheck >/dev/null 2>&1; then staticcheck ./... >"$out/security/staticcheck.txt"; else printf '%s\n' '{"status":"blocked","reason":"staticcheck binary is not installed; CI uses pinned tool container"}' >"$out/security/staticcheck.json"; fi
if command -v govulncheck >/dev/null 2>&1; then govulncheck -json ./... >"$out/security/govulncheck.json"; else printf '%s\n' '{"status":"blocked","reason":"govulncheck binary is not installed; CI uses pinned tool container and vulnerability database"}' >"$out/security/govulncheck.json"; fi
if command -v gosec >/dev/null 2>&1; then gosec -fmt=json -out="$out/security/gosec.json" ./...; else printf '%s\n' '{"status":"blocked","reason":"gosec binary is not installed; CI uses pinned tool container"}' >"$out/security/gosec.json"; fi

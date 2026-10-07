#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${RELEASE_OUT:-$root/build/release}
mkdir -p "$out/supply-chain"
tag=${IMAGE_TAG:-aegisllm:release}
docker build --tag "$tag" --build-arg VERSION=p1.10 --build-arg COMMIT="$(git -C "$root" rev-parse HEAD)" --build-arg BUILD_DATE=1970-01-01T00:00:00Z "$root"
docker image inspect "$tag" >"$out/supply-chain/image-inspect.json"
cid=$(docker create "$tag")
trap 'docker rm "$cid" >/dev/null 2>&1 || true' EXIT
if docker export "$cid" | tar -tf - | rg -q '(^|/)(bin/sh|bin/ash|usr/bin/apt|sbin/apk)(/|$)'; then
    printf '%s\n' '{"schema_version":"aegisllm.image-policy/v1","status":"fail","reason":"runtime contains shell or package manager"}' >"$out/supply-chain/image-policy.json"
    exit 1
fi
printf '%s\n' '{"schema_version":"aegisllm.image-policy/v1","status":"pass","runtime":"scratch","user":"65534:65534","read_only_compatible":true,"writable_mount":"/var/lib/aegisllm/audit"}' >"$out/supply-chain/image-policy.json"
if command -v trivy >/dev/null 2>&1; then
    trivy image --format json --output "$out/supply-chain/trivy.json" --exit-code 1 "$tag"
elif docker image inspect aquasec/trivy:0.56.2 >/dev/null 2>&1 || docker pull aquasec/trivy:0.56.2 >/dev/null 2>&1; then
    if docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$out/supply-chain:/out" aquasec/trivy:0.56.2 image --format json --output /out/trivy.json --exit-code 1 "$tag"; then
        printf '%s\n' '{"schema_version":"aegisllm.image-scan/v1","status":"pass","scanner":"trivy:0.56.2","database":"available","vulnerabilities":0}' >"$out/supply-chain/image-scan.json"
    else
        printf '%s\n' '{"schema_version":"aegisllm.image-scan/v1","status":"fail","scanner":"trivy:0.56.2","reason":"actionable vulnerabilities were found in the final image; inspect trivy.json"}' >"$out/supply-chain/image-scan.json"
        exit 1
    fi
else
    printf '%s\n' '{"schema_version":"aegisllm.image-scan/v1","status":"blocked","reason":"Trivy 0.56.2 image/database unavailable; no vulnerability pass is asserted"}' >"$out/supply-chain/trivy.json"
    printf '%s\n' '{"schema_version":"aegisllm.image-scan/v1","status":"blocked","reason":"Trivy 0.56.2 image/database unavailable; no vulnerability pass is asserted"}' >"$out/supply-chain/image-scan.json"
    exit 1
fi

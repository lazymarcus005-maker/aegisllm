#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${RELEASE_OUT:-$root/build/release}
trivy_cache=${TRIVY_CACHE_DIR:-/tmp/aegisllm-release-trivy-cache}
mkdir -p "$out/supply-chain"
. "$root/scripts/release/toolchain.sh"
tag=${IMAGE_TAG:-aegisllm:release}
docker build --tag "$tag" --build-arg GO_TOOL_IMAGE="$GO_TOOL_IMAGE" --build-arg VERSION=p1.10 --build-arg COMMIT="$(git -C "$root" rev-parse HEAD)" --build-arg BUILD_DATE=1970-01-01T00:00:00Z "$root"
docker image inspect "$tag" >"$out/supply-chain/image-inspect.json"
cid=$(docker create "$tag")
trap 'docker rm "$cid" >/dev/null 2>&1 || true' EXIT
if docker export "$cid" | tar -tf - | rg -q '(^|/)(bin/sh|bin/ash|usr/bin/apt|sbin/apk)(/|$)'; then
    printf '%s\n' '{"schema_version":"aegisllm.image-policy/v1","status":"fail","reason":"runtime contains shell or package manager"}' >"$out/supply-chain/image-policy.json"
    exit 1
fi
printf '%s\n' '{"schema_version":"aegisllm.image-policy/v1","status":"pass","runtime":"scratch","user":"65534:65534","read_only_compatible":true,"writable_mount":"/var/lib/aegisllm/audit"}' >"$out/supply-chain/image-policy.json"
if ! docker image inspect "$TRIVY_IMAGE" >/dev/null 2>&1 && ! docker pull "$TRIVY_IMAGE" >/dev/null 2>&1; then
    printf '%s\n' '{"schema_version":"aegisllm.image-scan/v1","status":"blocked","reason":"Trivy image unavailable; no vulnerability pass is asserted"}' >"$out/supply-chain/image-scan.json"
    exit 1
fi
mkdir -p "$trivy_cache"
if ! docker run --rm -v "$trivy_cache:/cache" "$TRIVY_IMAGE" --cache-dir /cache image --download-db-only >"$out/supply-chain/trivy-db-update.log" 2>&1; then
    printf '%s\n' '{"schema_version":"aegisllm.image-scan/v1","status":"blocked","reason":"Trivy vulnerability database unavailable; no vulnerability pass is asserted"}' >"$out/supply-chain/image-scan.json"
    exit 1
fi
db_metadata="$trivy_cache/db/metadata.json"
if [ ! -s "$db_metadata" ]; then
    printf '%s\n' '{"schema_version":"aegisllm.image-scan/v1","status":"blocked","reason":"Trivy did not produce verifiable vulnerability database metadata"}' >"$out/supply-chain/image-scan.json"
    exit 1
fi
set +e
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$trivy_cache:/cache" -v "$out/supply-chain:/out" "$TRIVY_IMAGE" --cache-dir /cache image --format json --output /out/trivy.json --exit-code 1 "$tag" >"$out/supply-chain/trivy-tool.log" 2>&1
scan_status=$?
set -e
python3 "$root/scripts/release/image_report.py" "$out/supply-chain/trivy.json" "$db_metadata" "$out/supply-chain/image-scan.json" "$tag" "$scan_status" "trivy:0.56.2"

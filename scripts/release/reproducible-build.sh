#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${RELEASE_OUT:-$root/build/release}
mkdir -p "$out/reproducible"
. "$root/scripts/release/toolchain.sh"
version=${VERSION:-p1.10}
commit=${COMMIT:-$(git -C "$root" rev-parse HEAD)}
date=${BUILD_DATE:-1970-01-01T00:00:00Z}
docker run --rm --user root -e VERSION="$version" -e COMMIT="$commit" -e BUILD_DATE="$date" -v "$root:/src" -w /src "$GO_TOOL_IMAGE" sh -ceu '
    for n in a b; do
        SOURCE_DATE_EPOCH=0 CGO_ENABLED=0 GOFLAGS=-mod=readonly go build -trimpath -buildvcs=false \
            -ldflags "-s -w -X main.buildVersion=$VERSION -X main.buildCommit=$COMMIT -X main.buildDate=$BUILD_DATE" \
            -o "/src/build/release/reproducible/gateway-$n" ./cmd/gateway
    done
'
sha256sum "$out/reproducible/gateway-a" | awk '{print $1}' >"$out/reproducible/gateway-a.sha256"
sha256sum "$out/reproducible/gateway-b" | awk '{print $1}' >"$out/reproducible/gateway-b.sha256"
cmp "$out/reproducible/gateway-a.sha256" "$out/reproducible/gateway-b.sha256"
printf '{"schema_version":"aegisllm.reproducible/v1","version":"%s","commit":"%s","source_date_epoch":0,"sha256":"%s","match":true}\n' "$version" "$commit" "$(cat "$out/reproducible/gateway-a.sha256")" >"$out/reproducible/report.json"

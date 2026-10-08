#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${RELEASE_OUT:-$root/build/release}
mkdir -p "$out/race"
. "$root/scripts/release/toolchain.sh"
image=${GO_RACE_IMAGE:-$GO_TOOL_IMAGE}
docker run --rm --user root -e CGO_ENABLED=1 -e GOMAXPROCS=2 -v "$root:/src" -w /src "$image" sh -ceu '
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc libc6-dev
    go test -race -p 1 ./...
' 2>&1 | tee "$out/race/go-test-race.log"
printf '%s\n' '{"schema_version":"aegisllm.race/v1","status":"pass","image":"'"$image"'","compiler":"gcc","packages":"./...","parallelism":1}' >"$out/race/report.json"

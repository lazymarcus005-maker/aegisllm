#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${RELEASE_OUT:-$root/build/release/fuzz}
mkdir -p "$out"
. "$root/scripts/release/toolchain.sh"
manifest="$root/scripts/release/fuzz-targets.txt"
while IFS='|' read -r package target purpose; do
    case "$package" in ''|'#'*) continue;; esac
    name=$(printf '%s' "$package" | tr '/.' '__')-${target}
    log="$out/$name.log"
    printf '%s\n' "fuzz smoke: $package $target ($purpose)"
    start=$(date +%s)
    if docker run --rm --user root -e GOMAXPROCS=1 -e FUZZTIME="${FUZZTIME:-2s}" -v "$root:/src" -w /src "$GO_TOOL_IMAGE" sh -ceu "go test '$package' -run '^\$' -fuzz='^${target}\$' -fuzztime=\"\$FUZZTIME\"" >"$log" 2>&1; then
        status=pass
    else
        status=fail
        cat "$log"
        exit 1
    fi
    end=$(date +%s)
    printf '{"schema_version":"aegisllm.fuzz/v1","package":"%s","target":"%s","status":"%s","duration_seconds":%s}\n' "$package" "$target" "$status" "$((end-start))" >"$out/$name.json"
done <"$manifest"

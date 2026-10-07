#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${RELEASE_OUT:-$root/build/release}
mkdir -p "$out/benchmarks"
GOMAXPROCS=1 go test ./internal/streaming ./internal/detectors ./internal/limiter ./internal/gateway -run '^$' \
    -bench 'Benchmark(Parser|EvasionTransforms|Allow|ProxyForward)$' -benchtime=200ms -count=1 >/dev/null
GOMAXPROCS=1 go test ./internal/streaming ./internal/detectors ./internal/limiter ./internal/gateway -run '^$' \
    -bench 'Benchmark(Parser|EvasionTransforms|Allow|ProxyForward)$' -benchmem -count=5 >"$out/benchmarks/go-bench.txt"
cp "$root/benchmarks/release-baseline.json" "$out/benchmarks/baseline.json"
python3 - "$out/benchmarks/go-bench.txt" "$out/benchmarks/baseline.json" <<'PY'
import json, re, sys
text=open(sys.argv[1]).read()
rows=[]
for line in text.splitlines():
    m=re.search(r'^(\S+)\s+\d+\s+([0-9.]+)\s+ns/op(.*)$', line)
    if not m: continue
    tail=m.group(3)
    b=re.search(r'([0-9.]+)\s+B/op\s+([0-9.]+)\s+allocs/op', tail)
    rows.append({"benchmark":m.group(1),"ns_per_op":float(m.group(2),),"bytes_per_op":float(b.group(1)) if b else 0,"allocs_per_op":float(b.group(2)) if b else 0})
if not rows: raise SystemExit("no benchmark rows produced")
b=json.load(open(sys.argv[2]))
from collections import defaultdict
from statistics import median
grouped=defaultdict(list)
for row in rows: grouped[row["benchmark"]].append(row)
medians={name:{key:median(item[key] for item in samples) for key in ("ns_per_op","bytes_per_op","allocs_per_op")} for name,samples in grouped.items()}
baseline=b.get("metrics",{})
missing=sorted(set(medians)-set(baseline))
if missing: raise SystemExit("committed benchmark baseline is missing: " + ", ".join(missing))
failures=[]
for name,current in medians.items():
    expected=baseline[name]
    for key, tolerance_key in (("ns_per_op","ns_per_op"),("allocs_per_op","allocs_per_op")):
        limit=float(expected[key]) * (1 + float(b["regression_tolerance"][tolerance_key]))
        if current[key] > limit:
            failures.append({"benchmark":name,"metric":key,"current":current[key],"baseline":expected[key],"limit":limit})
json.dump({"schema_version":"aegisllm.benchmark/v1","lane":"shared-host-advisory","gomaxprocs":1,"samples":rows,"robust_medians":medians,"baseline":b,"regressions":failures,"comparison":"median of five samples compared with the committed relative tolerance; no wall-clock unit assertion is used"},open(sys.argv[1]+".json","w"),indent=2)
if failures: raise SystemExit("benchmark regression: " + json.dumps(failures, separators=(",", ":")))
PY

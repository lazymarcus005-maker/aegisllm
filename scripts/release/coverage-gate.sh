#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${RELEASE_OUT:-$root/build/release}
mkdir -p "$out/coverage/profiles"
go list -f '{{if .TestGoFiles}}{{.ImportPath}}{{end}}' ./... | while read -r pkg; do
    [ -n "$pkg" ] || continue
    safe=$(printf '%s' "$pkg" | tr '/.' '__')
    go test -coverprofile="$out/coverage/profiles/$safe.out" "$pkg" >/dev/null
done
python3 - "$root/coverage/release-baseline.json" "$out/coverage/profiles" "$out/coverage/report.json" <<'PY'
import json, pathlib, sys
baseline=json.load(open(sys.argv[1])); rows=[]; total=hit=0
for path in pathlib.Path(sys.argv[2]).glob('*.out'):
    lines=path.read_text().splitlines(); pkg_total=pkg_hit=0
    for line in lines[1:]:
        try: _,count=line.rsplit(' ',1); count=int(count); stmt=line.split(' ')[1]; n=int(stmt)
        except Exception: continue
        pkg_total += n; pkg_hit += n if count > 0 else 0
    if pkg_total: rows.append({'profile':path.name,'statements':pkg_total,'covered':pkg_hit,'coverage':pkg_hit/pkg_total}); total+=pkg_total; hit+=pkg_hit
overall=hit/total if total else 0
critical={}
for name,floor in baseline['critical_floors'].items():
    matches=[r for r in rows if name.replace('/','_') in r['profile']]
    critical[name]=max((r['coverage'] for r in matches), default=0)
fails=[]
if overall < baseline['overall_floor']: fails.append('overall coverage below floor')
for name,floor in baseline['critical_floors'].items():
    if critical[name] < floor: fails.append(f'{name} below critical floor')
json.dump({'schema_version':'aegisllm.coverage/v1','overall':overall,'floor':baseline['overall_floor'],'critical':critical,'critical_floors':baseline['critical_floors'],'packages':rows,'exclusions':baseline['exclusions'],'status':'fail' if fails else 'pass','failures':fails},open(sys.argv[3],'w'),indent=2)
if fails: raise SystemExit('; '.join(fails))
PY

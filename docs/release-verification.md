# P1.10 release verification

`make verify-release` is the single release entrypoint. It is fail-fast for
correctness, race, fuzz, benchmark, E2E, conformance, reproducibility,
secret-scan, and SBOM stages. Static-analysis, license, and image-vulnerability
stages continue far enough to write an evidence manifest when an external tool
or vulnerability database is unavailable, then fail the release; a blocked
required gate is never reported as a pass.

Reports are written to the ignored `build/release/` directory. The command does
not update conformance fixtures, baselines, or policy files. Fixture updates
remain an explicit reviewed command (`conformancetool update-fixtures ...
--confirm`). `build/release/evidence-manifest.json` records each command,
tool versions, report hash, status, and blocker reason.

## Tiers and pinned tools

The fast correctness tier is `go test -p 1 ./...`, `go build ./...`, `go vet
./...`, and `gofmt`. The race tier runs the complete suite in
`golang:1.25.0-bookworm`, installs the Debian GCC/libc toolchain in the
container, and uses `-race -p 1`; host compiler availability is irrelevant.
Fuzz smoke runs every target in `scripts/release/fuzz-targets.txt` for a
bounded two seconds by default. Seeds are committed as `Fuzz.Add` calls beside
the target and are reviewed as part of the source corpus.

The benchmark tier warms up, takes five benchmark samples, controls
`GOMAXPROCS=1`, and emits p50/p95/p99, throughput, status/error rate, and
allocation context. `benchmarks/release-baseline.json` is a reviewed baseline;
shared-host numbers are advisory, while the pinned CI runner is the blocking
lane. The clean-request p95 SLO remains 25 ms, but no normal unit test makes a
wall-clock assertion. `cmd/loadtest` is the bounded Go HTTP probe used by the
short E2E lane; it owns and closes bodies, supports cancellation, backpressure
status expectations, graceful restart checks, and JSON histograms. Run a
longer manual soak with `LOAD_DURATION=30m LOAD_URL=... scripts/release/load-short.sh`.

The Docker fake-provider matrix validates exactly 24 required conformance cases
(four profiles × six cases). Chaos and resource checks use the existing fake
dependencies and tolerance-based cancellation/reload tests; no sensitive body
is included in reports.

## Supply chain and evidence

Gateway builds use `-trimpath`, `-buildvcs=false`, controlled
`SOURCE_DATE_EPOCH=0`, and explicit version/commit/date ldflags. Two clean
outputs must have the same SHA-256. The offline CycloneDX 1.5 SBOM is schema
validated; the final scratch/non-root image has no shell or package manager,
declares a healthcheck, and is read-only-rootfs compatible except for the
explicit audit mount. Trivy 0.56.2, go-licenses 1.6.0, staticcheck 2025.1.1,
govulncheck 1.1.4, and gosec 2.22.8 are run in pinned containers. Signing is
not fabricated: provenance/checksums are produced, and signing is optional
until a keyless test identity is available.

# P1.10 release checklist

- [ ] `make verify-release` completed from a clean checkout; every required
      evidence stage is `pass`.
- [ ] Full suite/build/vet/gofmt/diff and Docker GCC race suite pass.
- [ ] Every registered fuzz target runs; no required target is skipped.
- [ ] Coverage report meets overall and critical-package floors.
- [ ] Warmed benchmark/load evidence reports p50/p95/p99, throughput,
      status/error rate, backpressure, and restart behavior.
- [ ] Fake Compose E2E, chaos/failure matrix, and exactly 24 conformance cases
      pass with no sensitive leakage.
- [ ] Two reproducible binary hashes match; checksums/provenance are recorded.
- [ ] CycloneDX SBOM validates; final image is scratch/non-root/read-only
      compatible with explicit audit storage and has a healthcheck.
- [ ] go vet, pinned staticcheck/gosec/govulncheck, secret scan, license
      inventory, and final-image vulnerability scan pass. Database/tool outage
      is a blocker with exact evidence, never a pass.
- [ ] GitHub workflow permissions/action SHAs and artifact retention are
      reviewed; fork PRs receive no secrets.
- [ ] P2.3 quarantine checks pass: tenant isolation, forged-signal rejection,
      CAS/revision lifecycle, Redis outage fail-closed, restart/probation,
      route/tool/RAG/token enforcement, privacy, metric-cardinality, and
      bounded-state/DoS coverage.
- [ ] Release evidence manifest hashes are attached; signing is only recorded
      when a real keyless identity is available.

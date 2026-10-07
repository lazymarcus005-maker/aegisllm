# Testing and contribution gates

Before a commit, run `make verify-release`. For iteration, use `make test`,
`make vet`, `make fuzz-smoke`, and `make load-short`. Do not change committed
fixtures or benchmark baselines during a test. Fixture or baseline updates
require an explicit command, a review note, and refreshed evidence.

Security-sensitive changes must include a deterministic test, a failure-mode
test, and an assertion that raw secrets are absent from audit/log output.
Concurrency changes must pass the Docker race tier. New parsers and bounded
input paths should register a fuzz target and at least two committed seeds in
the target source. Reports and binaries belong under ignored `build/` only.

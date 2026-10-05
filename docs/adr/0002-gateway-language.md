# ADR-002: Gateway implementation language

**Status:** Accepted
**Date:** 2026-10-05
**Deciders:** Project owner via implementation setup

## Context

`architecture.md` (§20) leaves the gateway language open: Go/.NET when long-term
enterprise operation and predictable resource usage matter, Python/FastAPI when
delivery speed is the highest priority. The security gateway is an inline
application-security control: every request pays its latency budget
(NFR-PERF-002: p95 ≤ 25 ms excluding Laya), and the deployment target is
local/on-prem first (Mode B sidecar, Mode C central gateway).

Two adjacent components are Python-shaped and stay out of process either way:

- **Laya** runs as a local `laya-serve` HTTP service (FR-007, T-013; the handoff
  explicitly forbids embedding Laya in a compiled gateway).
- **PII span detection** may later adopt Presidio/NER (ADR-003); the spec already
  requires it to be replaceable behind `PiiSpanProvider` (FR-006), so a future
  Python recognizer becomes a sidecar service, not a gateway dependency.

## Decision

Implement the gateway in **Go**.

## Consequences

- Single static binary per service; small container images; predictable
  memory/GC profile for inline proxying.
- Policy remains YAML-as-code evaluated by a typed, deterministic engine in Go.
- Laya (Python) and any future Presidio/NER recognizer (Python) integrate over
  HTTP behind the `DecisionProvider` and `PiiSpanProvider` interfaces.
- Team must staff Go expertise; ML-adjacent work stays in separate services.

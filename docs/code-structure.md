# Code structure

AegisLLM follows a layered layout. The runtime dependency direction points
inward toward domain contracts; domain packages never import transport code.

```text
cmd/gateway
    bootstrap and dependency wiring
        internal/gateway (transport + application orchestration)
            internal/core     domain contracts
            internal/policy    domain policy and precedence
            internal/detectors infrastructure: deterministic detectors
            internal/pii       infrastructure: spans and transformation plan
            internal/tokenization, audit, observability, decision
        web/leaderboard and internal/dashboard (transport presentation)

internal/evals (offline infrastructure; not a runtime dependency)
```

## Responsibilities

- `cmd/gateway` is a thin bootstrap: load configuration and policy, construct
  adapters, wire the server, and start HTTP.
- `internal/gateway` owns HTTP transport and the application pipeline. The
  pipeline remains in this package for compatibility, but its responsibilities
  are split into `pipeline.go` (wiring), `inspect.go` (the shared four-boundary
  routine), `semantic.go` (semantic gating), and `transform_apply.go`
  (request/response application).
- `internal/core` is the stable domain vocabulary. Findings are evidence;
  actions are produced by policy.
- `internal/policy` contains versioned policy parsing, validation, precedence,
  and decision rules. It does not know HTTP or file layout.
- `internal/detectors`, `internal/pii`, `internal/tokenization`,
  `internal/audit`, `internal/observability`, and `internal/decision` provide
  replaceable infrastructure adapters around domain contracts.
- `internal/dashboard` and `web/leaderboard` are transport presentation only;
  they expose aggregate, sanitized metrics and never receive raw content.

## Dependency rules

1. `core` imports no other internal package.
2. Domain policy may depend on `core`, but domain code must not import
   `internal/gateway`, `internal/dashboard`, or `web/leaderboard`.
3. Detectors and infrastructure depend on domain contracts, not on HTTP
   handlers.
4. The gateway composes the layers and is the only runtime package that wires
   transport, policy, detectors, tokenization, audit, and observability.
5. Offline evaluation code may consume domain and infrastructure contracts,
   but production transport does not depend on datasets or reports.

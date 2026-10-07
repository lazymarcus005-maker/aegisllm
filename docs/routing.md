# Local/cloud routing (P1.1)

`UPSTREAM_REGISTRY_FILE` points to a versioned, strict YAML registry. Each
entry declares its local/cloud class, provider and wire family, endpoint
capabilities, model allow/deny patterns, aliases, priority, health probe,
breaker, TLS/mTLS files, and file-backed authentication. The gateway never
prints `base_url`, credential paths, or secret values from a registry in
`GET /api/routes`, audit events, metrics, or errors.

Development can continue to use the P0 `UPSTREAM_BASE_URL` compatibility path.
The production server refuses to start without a registry; production route
credentials must use `auth.secret_file` and TLS material must use the existing
securetransport-backed files.

## Policy example

Route constraints are policy data, not hard-coded engine branches:

```yaml
routing:
  force_local:
    classes: [local]
  actions:
    ALLOW:
      fallback_chain: cloud-then-local
  provider_boundaries:
    cloud:
      classes: [cloud]
```

`FORCE_LOCAL_MODEL` always adds an unconditional `class=local` filter. It does
not consult a cloud fallback chain. If no enabled, healthy, compatible local
route remains, the request receives the deterministic
`ROUTE_LOCAL_UNAVAILABLE` error and no cloud request is made.

Normal fallback is attempted only when a policy names a registry
`fallback_chain`. A POST may be retried only after a clear connection-dial
failure; EOFs, timeouts, and write errors are treated as uncertain delivery.
This prevents duplicate non-idempotent requests.

The requested model is checked before forwarding. An upstream alias rewrites
only the outbound JSON `model`; sanitized audit records retain both
`requested_model` and `routed_model`, plus route id/class/provider. Endpoint
family, streaming, and tools must match declared capabilities.

## Operations

Health probes run against the configured endpoint at the configured interval.
Failures mark a route unhealthy and the breaker sheds traffic. A valid reload
atomically replaces the registry snapshot while preserving compatible runtime
health/breaker state. A malformed reload is rejected and the last-known-good
snapshot remains active. Route status is available to operators at
`GET /api/routes`; it requires `aegis.operator` and contains no URLs or
credentials. `/api/protection-stats` includes `local_applied` and
`cloud_applied` counts.

Recommended rollout is: validate the registry in development, exercise local
isolation with separate local/cloud mocks, deploy in shadow for claim and
capability observation, then enable enforcement with an operator-reviewed
fallback chain. Alert on route health, breaker-open, route-unavailable, and
reload-failure metrics; investigate route changes using the sanitized audit
event rather than request content.

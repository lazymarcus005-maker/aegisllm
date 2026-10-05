# 01: Scaffold, language ADR, and clean pass-through proxy

**What to build:** A running Go gateway service that accepts an OpenAI-compatible `POST /v1/chat/completions` request, parses it into an `InspectionEnvelope`, forwards clean requests unchanged to a configured upstream LLM Gateway (a mock upstream in Docker Compose for local demos), and returns the response to the client — plus `/health` and `/ready`, the core domain models, and the repository scaffold (module layout, CI skeleton, compose file, README). No security inspection yet: this slice proves the pipe.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] ADR-002 written: Go chosen for the gateway runtime, with rationale (compiled, low latency, predictable resource usage; Laya and any future Presidio/NER adapter stay separate Python services)
- [ ] Repository scaffold matches the handoff module layout (gateway, core, detectors, pii, decision, policy, tokenization, audit, observability) plus policies/, questions/, evals/, tests/, docs/adr/
- [ ] Core domain models exist: InspectionEnvelope, ContentPart, Direction, FindingCategory, Action enums; default string/logging representation contains no raw content
- [ ] Request parser handles model, messages, roles, text and structured content, tool definitions and tool calls without mutating the payload; golden tests for typical, malformed, and oversized payloads
- [ ] Clean request → gateway → upstream (UPSTREAM_BASE_URL / UPSTREAM_AUTH_MODE from config, no hardcoded keys) → client, preserving raw upstream behavior on the allow path
- [ ] GET /health and GET /ready; readiness verifies configuration and upstream reachability
- [ ] docker-compose brings up gateway + mock upstream; README run instructions; CI skeleton runs build, lint, unit tests

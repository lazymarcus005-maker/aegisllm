# P1.7 Security Operations Dashboard v2

The operator dashboard is served by the gateway at `/dashboard`. HTML, CSS,
and JavaScript are embedded in the Go binary and the Docker image has no CDN or
runtime npm dependency. All dashboard APIs are same-origin `GET` endpoints and
require `aegis.operator` through the existing bearer JWT or mTLS workflow:

| Endpoint | Purpose |
| --- | --- |
| `/api/dashboard/v2/overview` | global state, KPI definitions, funnel, freshness, and reset semantics |
| `/api/dashboard/v2/timeseries` | bounded action/finding buckets |
| `/api/dashboard/v2/breakdown` | bounded actions, categories/rule subtypes, provider classes, stages, canary, audit, and limit counters |
| `/api/dashboard/v2/alerts` | sanitized investigation links and control alerts |

Every response has `version: "aegisllm.dashboard/v2"`, UTC RFC3339 timestamps,
an explicit `window` (`start`, `end`, `bucket`, and `requested`), and no-store
cache semantics. Query windows are limited to 24 hours and series are limited
to 120 points. Action, category, provider class, and source-stage filters are
server-side bounded; dimensions have a fixed cap and overflow is represented by
`OTHER`. Tenant, user, prompt, finding value, token mapping, rule text, and
durable audit records are not dashboard data types.

## Data semantics and SLOs

The rolling aggregate is process-local, fixed-size, and reset at process start.
`reset.durable` is therefore `false` until a durable aggregate store is
designed and reviewed. A restart is shown in the UI. A healthy zero means the
process is ready and no events occurred in the selected window; unavailable
means the status provider cannot establish health; disabled means an optional
subsystem was not configured.

| KPI | Source and calculation | Reset | Owner/action |
| --- | --- | --- | --- |
| Protected events | bounded request actions `BLOCK`, `TOKENIZE`, `REDACT`, `REVIEW`, `RESTRICT_TOOLS` | process start | Security Operations investigates action/category spikes |
| Blocked high risk | `BLOCK` actions; policy action is the high-risk proxy | process start | Security Operations checks policy/provider changes |
| Tokenized / redacted | `TOKENIZE + REDACT` actions | process start | Privacy Operations verifies transformation coverage |
| Upstream/tool requests prevented | `BLOCK + REVIEW + RESTRICT_TOOLS` | process start | Security Operations opens sanitized alert detail |
| Control health / SLO | 100 when readiness is healthy/ready, otherwise 0; target is 100% readiness during the window | process start, status is current | Platform Operations restores degraded controls |

The funnel is aggregate `inspected → findings → transformed_or_blocked →
forwarded`. It is intentionally not a unique-request join and must not be
read as a conversion funnel. Findings and stream events are recorded at their
bounded event boundary. Local/cloud routing is sourced from the existing
sanitized route observer. Audit and admission panels are event counters, not
raw queue or record viewers.

The dashboard uses bounded polling with exponential retry backoff (2 seconds
to 30 seconds). The UI marks API failure as disconnected and aggregate event
age over 60 seconds as stale. No token is stored in localStorage, sessionStorage,
or a URL. For browser use, deploy the existing bearer-authenticated endpoint
behind a same-origin reverse-proxy session, or use mTLS; direct bearer clients
can call the APIs with `Authorization: Bearer ...`. The dashboard has no
state-changing admin action and links only to existing read-only status views.

The operator page and API responses set a strict same-origin CSP, no-store
cache control, MIME/referrer/clickjacking protections, and same-origin resource
policy. DOM updates use text nodes and allowlisted classes rather than HTML
interpolation. The page uses the colorblind-safe palette
`#0077BB/#EE7733/#009988/#CC3311`, semantic landmarks, keyboard focus states,
44px touch targets, long-label truncation with titles, and reduced-motion CSS.

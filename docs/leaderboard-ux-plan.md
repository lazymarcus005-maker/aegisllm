# Protection Leaderboard UX Plan

## User story and metric definition

As a security operator, I want a calm, glanceable view of how much sensitive
data the gateway kept from reaching an LLM, so I can verify that protection is
active without inspecting raw traffic.

The headline metric, **prevented sensitive sends**, is the sum of request
actions that stop or transform content before forwarding:

```text
TotalPrevented = blocked_total + tokenized_total + redacted_total + review_total
```

One prevented count means one request boundary recorded with `BLOCK`,
`TOKENIZE`, `REDACT`, or `REVIEW`. `requests_total{action,mode}` is the
request-level source of truth behind those action counters; `ALLOW` is shown
separately. `findings_total{category,subtype}` supplies the leaderboard rows.
`transformations_total` remains useful operational context for the number of
individual replacements/tokens, but does not inflate the number of prevented
sends. Shadow-mode predictions are visible because the metrics represent what
the policy would have prevented, while the gateway still forwards shadow
traffic according to its existing behavior.

## Wireframe

```text
+--------------------------------------------------------------------------+
| 🛡️  AegisLLM Protection Leaderboard              [Polling 2s]             |
|     จำนวนครั้งที่ป้องกัน sensitive sends to LLM                           |
|                                                                          |
|  Prevented sensitive sends / ป้องกันข้อมูลสำเร็จ                          |
|                              12,480  (count-up + shield pulse)            |
|                                                                          |
| [Blocked 4,200] [Tokenized 5,830] [Redacted 2,100] [Review 350] [Allowed] |
+--------------------------------------------------------------------------+
| What we protected / สิ่งที่ป้องกัน                                       |
|  🥇  PII       phone       ████████████████████             5,830         |
|  🥈  SECRET    api_key     ██████████████                   4,200         |
|  🥉  PII       email       ███████                           2,100         |
|  #4  PROMPT... injection   ██                                  350         |
|                                                                          |
|  Filters: [Time: All time ▾] [Category: All ▾]                            |
+--------------------------------------------------------------------------+
```

The first release keeps the interaction surface intentionally small. Rows are
sorted descending by count. Empty state: `ยังไม่มีการป้องกัน — ระบบพร้อมทำงาน`
with the English companion `No protections yet — the gateway is ready.`

## 2D animation concept

The canvas is a low-opacity field of slowly floating shield-like particles.
When `total_prevented` increases, the total card emits a soft shield pulse and
a short burst of small confetti particles. Animation is decorative only; the
counter and rows remain fully usable without it. `prefers-reduced-motion`
disables the canvas and transitions.

## Data flow

```text
Prometheus private registry
  -> observability.Metrics.Snapshot() (thread-safe metric gather)
  -> dashboard.Snapshot() (sanitized JSON projection)
  -> GET /api/protection-stats
  -> vanilla frontend polling every 2 seconds
  -> count-up counter + row bars + optional shield/confetti animation
```

No raw request body, secret, PII value, or token mapping enters the dashboard
snapshot or API response.

## Design tokens

- Minimal, clean cards with rounded corners and a soft shadow.
- System font only; no CDN, framework, or build step.
- Light and dark color schemes using CSS custom properties.
- Accent indigo for protection, green for allowed traffic, muted text for
  operational metadata.
- Mobile layout collapses the summary grid and turns each row into a compact
  two-line card.
- Vanilla HTML/CSS/JS plus one `requestAnimationFrame` canvas loop.
- Thai and English labels are paired where the UI communicates a key metric.

## API contract (Phase 3)

### `GET /api/protection-stats`

Returns `200 application/json`:

```json
{
  "total_prevented": 12480,
  "blocked": 4200,
  "tokenized": 5830,
  "redacted": 2100,
  "review": 350,
  "allowed": 9120,
  "by_category": [
    {"category": "PII", "subtype": "phone", "count": 5830},
    {"category": "SECRET", "subtype": "api_key", "count": 4200}
  ],
  "updated_at": "2026-10-07T10:00:00Z"
}
```

`by_category` is sorted by `count` descending, with deterministic category and
subtype tie-breakers. Counts are cumulative process-lifetime Prometheus
counters. `updated_at` is the UTC time at which the snapshot was generated.

### `GET /dashboard`

Returns the embedded leaderboard HTML. Its CSS and JavaScript are served at
`/dashboard/style.css` and `/dashboard/app.js`.

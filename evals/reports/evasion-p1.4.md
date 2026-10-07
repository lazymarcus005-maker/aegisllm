# P1.4 evasion corpus report

The committed corpus is a small regression gate for the bounded production
profile. Positive cases cover standard/raw and URL-safe Base64, percent and
JSON Unicode encoding, fullwidth normalization, and zero-width insertion.
Negative cases cover Thai, English, UUID, benign documentation Base64, and a
JWT-shaped non-credential string.

Expected corpus result: 6 positive cases detected (FNR 0/6 = 0%) and 5
negative cases allowed (FPR 0/5 = 0%). These are regression-corpus results,
not a claim of production prevalence or general DLP recall; expand the held-out
corpus before changing profile actions.

The detector latency gate remains the existing isolated p95 <= 10 ms target.
The P1.4 scanner uses these hard defaults unless policy overrides them:

| Budget | Production default |
| --- | ---: |
| Decode depth | 1 |
| Decode work | 262,144 bytes |
| Decoded expansion ratio | 8x |
| JSON depth / nodes | 8 / 512 |
| JSON string bytes | 16,384 |
| Candidate bytes | 32,768 |

On the verification host (AMD EPYC, Go benchmark `-benchtime=200ms`), the
transform microbenchmarks were: NFKC/confusable 71.6 µs/op, percent 120.6
µs/op, Base64 125.6 µs/op, and structured JSON Unicode 422.2 µs/op. The full
detector regression measured isolated p95 5.736 ms; the existing 10 ms gate
was unchanged.

Same-part NFKC/control/confusable transforms preserve source byte spans and can
be transformed by the ordinary policy action. Decoded, structured-escaped,
cross-part, and budget findings are represented only by evasion type and
bounded encoding depth in audit/metrics; their raw and decoded values are never
reported. The existing streaming holdback is the cross-chunk state machine.

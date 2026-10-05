# 04: Complete deterministic detector corpus

**What to build:** The full MVP deterministic detector set: the remaining secret families plus Thai/structured PII, all on the ticket-02 framework. From the user's perspective: the spec's FR-004 and FR-005 detection lists work with validated corpora, and a random 13-digit number that fails the Thai checksum is not treated as a citizen ID.

**Blocked by:** 02 (detector framework). Parallel with 03.

**Status:** done

- [x] Secrets: AWS access keys, connection-string candidates, generic high-entropy candidates with contextual evidence — negative corpora tuned to minimize false positives
- [x] PII: Thai citizen ID with checksum (synthetic checksum-valid fixtures only; invalid checksum rejected; separator/spacing variants), Thai/mobile phone numbers, email, credit card candidates with Luhn validation, IPv4/IPv6
- [x] Findings conform to the spec §10 internal finding schema (category, subtype, detector, location, value_hash); no raw detected value persisted
- [x] Organization-specific IDs remain pluggable rules (extension point exists, no specific org rules yet)
- [x] Golden tests per detector; deterministic scan p95 ≤ 10 ms on typical payloads measured in the test harness (NFR-PERF-001)

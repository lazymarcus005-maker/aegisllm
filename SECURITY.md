# Security policy

The gateway is an inline security boundary. Reports must not contain prompts,
responses, tokens, credentials, private keys, or unbounded identities. Report
only sanitized metadata and hashes. Vulnerability reports should include a
minimal reproduction, affected commit, impact, and whether the issue crosses
the client/gateway/provider, policy, audit, vault, or tool trust boundary.

Release verification requires the secret scan, pinned static analysis,
dependency vulnerability scan, license inventory, final-image scan, and
conformance/chaos evidence. An unavailable external vulnerability database is
a release blocker and must be recorded as `blocked`, never converted to a
pass. Synthetic fixtures are non-production and must remain clearly marked.

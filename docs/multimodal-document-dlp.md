# Multimodal and document DLP (P2.1)

The gateway normalizes OpenAI Chat/Responses, Anthropic Messages, and generic
attachment aliases into the same inspection envelope as text. Inline data URLs
are decoded only inside a bounded inspection context. HTTPS URL media is
fetched by a separate client that validates the scheme, allowlisted host,
resolved IPs, every redirect, response size, and response MIME/magic bytes.
No caller headers, query credentials, local-file paths, or base64 bodies cross
that boundary.

The attachment inspector enforces encoded/decoded byte ceilings, attachment,
page, extracted-text, archive expansion, timeout, cancellation, and MIME
allowlists. Extracted text and bounded metadata are then scanned by the normal
evasion, secret, PII, semantic, policy, audit, and metrics path. Cross-part
canonicalization remains active, so a value split between ordinary text and an
extracted block cannot avoid detection.

`DLP_ATTACHMENT_ADAPTER=builtin` is a deterministic development fixture: it
returns plain text and bounded PDF/image metadata, not OCR or full document
parsing. `cmd/fakeextractor` and `docker-compose.fake-extractor.yml` are
integration/conformance fixtures and are not promotion dependencies. The
production adapter is `http` and must point to a
private authenticated HTTPS endpoint with a CA bundle and client certificate
and key. Real OCR/document engines, PKI issuance/rotation, and data calibration
remain promotion dependencies.

Clean attachments are forwarded byte-for-byte. If a finding would require
REDACT or TOKENIZE inside an attachment, the gateway returns BLOCK with
`ATTACHMENT_TRANSFORM_UNSUPPORTED`; it never claims binary reconstruction
succeeded. Request and buffered response attachments follow this rule.

Contract evidence is in `internal/attachment/attachment_test.go` and
`internal/gateway/multimodal_test.go`. These prove gateway contracts and fake
service integration only; real OCR/document engines, production PKI, redirect
infrastructure, and sensitive-data calibration remain promotion dependencies.

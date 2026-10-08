# Policy control-plane contract

`GET POLICY_CONTROL_PLANE_URL` returns JSON:

```json
{"manifest":{},"signature":"base64-ed25519","files":{"policy.yaml":"base64","questions.yaml":"base64"}}
```

The endpoint returns an `ETag`; gateways send `If-None-Match` and accept
`304 Not Modified`. Responses are bounded by `POLICY_DISTRIBUTION_TIMEOUT`
and the manager's maximum bundle size. The endpoint must use HTTPS with the
gateway's configured CA and optional client certificate/key. Malformed,
oversized, timed-out, unsigned, expired, hash-mismatched, or untrusted
responses leave the last-known-good snapshot active.

`cmd/fakecontrolplane` and `docker-compose.fake-policy.yml` implement this
contract for tests only. They are explicitly non-production fixtures and use
plain HTTP unless test TLS files are supplied.

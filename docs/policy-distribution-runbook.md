# Policy distribution, canary, promotion, and rollback

1. Build and contract-test a bundle with `policytool bundle create`, run the
   policytool contract and evaluation fixtures, then sign it with the release
   signer. Store the private key outside the repository and outside bundle
   directories.
2. Publish the signed directory/envelope. Keep the sequence monotonic and
   ensure the fleet trust store contains the signing key before publishing.
3. Confirm `/api/policies/status`: the active sequence remains unchanged while
   the candidate is fetched, verified, and canaried. Canary assignment is a
   stable hash of gateway instance plus verified tenant/application identity.
4. Review bounded disagreement/error and evaluation metrics for the configured
   soak period. Promotion is a manual operator action with a non-empty reason;
   there is no model-driven promotion path.
5. For an incident, issue a signed rollback authorization naming the retained
   sequence and bundle hash, include the operator role and reason, and POST it
   to `/api/policies/rollback`. The complete snapshot is restored atomically;
   no process restart is needed.

The status and audit surfaces expose IDs, sequences, hashes, counts, reasons,
and key IDs only. Raw policy conditions, prompts, credentials, and traffic are
not returned. Use bearer JWT or mTLS operator authentication; do not add a
browser-cookie authorization path.

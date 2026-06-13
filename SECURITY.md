# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately**. Do not open a public issue
for an undisclosed vulnerability.

- Use GitHub's *Report a vulnerability* (Security → Advisories) on this
  repository, or
- Email the maintainers at the address listed in the repository profile.

Include: affected version/commit, a description, reproduction steps or a proof
of concept, and any suggested remediation. We aim to acknowledge reports within
**3 business days** and to provide a remediation timeline after triage.

Please act in good faith: give us reasonable time to remediate before public
disclosure, and avoid privacy violations, data destruction, or service
degradation while testing.

## Supported versions

This project is pre-1.0. Security fixes are applied to the `main` branch and the
latest released version. Pin a specific version in production and watch releases.

## Security model (summary)

Mnemosyne is a defense-in-depth control against OWASP ASI06. Its load-bearing
guarantees are the trust invariant, HMAC record integrity, namespace
segmentation, and the tamper-evident audit log. See
[`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md) for the full attacker model,
including explicit out-of-scope items (host compromise, theft of the signing
key).

## Operational hardening checklist

- [ ] Set a strong `MNEMOSYNE_INTEGRITY_KEY` (≥ 32 bytes of entropy). **Never**
      ship the default. Prefer a KMS/HSM-backed `KeyProvider`.
- [ ] Set `MNEMOSYNE_API_KEYS` (the API refuses auth only when unset, which is a
      dev-only mode). Place the service behind mTLS / an identity-aware proxy.
- [ ] Keep `fail_closed=true` and `require_integrity_on_read=true` (defaults).
- [ ] Persist the audit log to append-only / WORM storage and verify the chain
      on a schedule (`GET /v1/audit/verify`).
- [ ] Review the policy YAML in code review; treat it as security-critical
      configuration.
- [ ] Use a distinct `namespace` per tenant/session to enforce segmentation.
- [ ] Rotate the integrity key on a defined cadence and on suspected compromise.

## Cryptography

- Record integrity: HMAC-SHA256 over a canonical serialisation, constant-time
  comparison on verify.
- Audit chain: SHA-256 hash chaining from a fixed genesis.

These are integrity/authenticity controls, not confidentiality. Encrypt data at
rest and in transit using your platform's mechanisms.

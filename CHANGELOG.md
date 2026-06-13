# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-13

### Added
- **Memory-integrity gateway** with two guarded operations, `guard_write` and
  `guard_read`, enforcing the cardinal ASI06 invariant: content below the
  `TRUSTED` tier can never reach an `INSTRUCTION` (control-plane) surface.
- **Provenance → trust-tier** resolution and **surface**-aware policy
  (`INSTRUCTION` / `KNOWLEDGE` / `EPISODIC` / `SCRATCH`).
- **Detectors:**
  - `injection` — instruction-override, role-reassignment, persistence,
    tooling/config manipulation, exfiltration, delimiter smuggling, and
    **delayed/conditional execution** (Gemini-style "delayed tool invocation").
  - `secrets_pii` — cloud/provider keys, JWTs, private keys, and PII with
    Luhn-checked card detection; redaction helper.
  - `anomaly` — size/entropy checks plus a per-writer behavioral baseline with a
    robust MAD z-score for gradual-erosion ("sleeper agent") detection.
  - `obfuscation` — invisible-Unicode smuggling: Unicode Tag characters,
    bidirectional overrides (Trojan Source), and zero-width interleaving, with
    emoji-ZWJ awareness and a `strip()` sanitiser.
- **Declarative YAML policy engine** (most-restrictive-wins) with a secure
  default policy.
- **Integrity:** HMAC-SHA256 record signing (constant-time verify, KMS/HSM hook)
  and a hash-chained, tamper-evident audit log with chain verification.
- **Storage:** `MemoryStore` / `QuarantineStore` protocols with in-memory and
  SQLite backends; namespace segmentation; human-in-the-loop quarantine
  promotion that elevates trust to the target surface's requirement.
- **FastAPI sidecar** (bearer auth) and `mnemosyne` **CLI** (`scan`/`nist`/`version`).
- **NIST/OWASP control catalog** (MN-01…MN-11) mapping to NIST SP 800-53 Rev 5,
  SP 800-218A, AI 600-1, and CSF 2.0; surfaced via `GET /v1/compliance`,
  `mnemosyne nist`, and a generated `docs/NIST_CONTROL_MAPPING.md`.
- **Telemetry:** structured JSON logging and Prometheus metrics.
- **Tests:** 131 tests including a red-team corpus that asserts 100% detection
  of the bundled ASI06 payloads and a 0% false-positive rate on benign writes.
- **Tooling & ops:** ruff, mypy, bandit, pip-audit, pre-commit, GitHub Actions
  CI (lint/type/security/test matrix + doc-sync check), Dockerfile,
  docker-compose, and a release workflow.

[Unreleased]: https://github.com/rsh1k/mnemosyne/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rsh1k/mnemosyne/releases/tag/v0.1.0

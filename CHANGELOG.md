# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4] - 2026-06-13

### Changed
- Injection-class findings are now governed by a dedicated, stricter policy
  table (`injection_severity_decisions`): a medium-severity injection signal on
  the `knowledge` surface is **quarantined** for review rather than sanitized,
  because `sanitize` cannot neutralise injection phrasing. Anomaly/obfuscation
  findings continue to use the generic `severity_decisions` table (so benign
  behavioural drift and large writes are not over-blocked). The new section is
  optional and falls back to the generic table for existing custom policies.
- CLI program name is now `mnem` in all usage and error output.

### Added
- `validation_harness.py`: a 75-scenario end-to-end behavioural audit, run in
  CI on every push/PR (exits non-zero on any scenario failure).

## [0.1.3] - 2026-06-13

### Changed
- Release pipeline switched to PyPI Trusted Publishing (OIDC); no API tokens.

## [0.1.2] - 2026-06-13

### Changed
- `__version__` is now read from installed package metadata, so the CLI version
  banner can never drift from `pyproject.toml`.

### Fixed
- `mnem version` now prints the correct command name (`mnem`) and the actual
  installed version.

## [0.1.1] - 2026-06-13

### Changed
- Renamed the CLI command to **`mnem`** (was `mnemosyne`) and added
  `python -m mnemosyne` as an alias.

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
- **FastAPI sidecar** (bearer auth) and a CLI exposed as **`mnem`** with
  `scan`/`nist`/`version`.
- **NIST/OWASP control catalog** (MN-01…MN-11) mapping to NIST SP 800-53 Rev 5,
  SP 800-218A, AI 600-1, and CSF 2.0; surfaced via `GET /v1/compliance`,
  `mnem nist`, and a generated `docs/NIST_CONTROL_MAPPING.md`.
- **Telemetry:** structured JSON logging and Prometheus metrics.
- **Tests:** 131 tests including a red-team corpus that asserts 100% detection
  of the bundled ASI06 payloads and a 0% false-positive rate on benign writes.
- **Tooling & ops:** ruff, mypy, bandit, pip-audit, pre-commit, GitHub Actions
  CI (lint/type/security/test matrix + doc-sync check), Dockerfile,
  docker-compose, and a release workflow.

[Unreleased]: https://github.com/rsh1k/mnemosyne/compare/v0.1.4...HEAD
[0.1.4]: https://github.com/rsh1k/mnemosyne/releases/tag/v0.1.4
[0.1.3]: https://github.com/rsh1k/mnemosyne/releases/tag/v0.1.3
[0.1.2]: https://github.com/rsh1k/mnemosyne/releases/tag/v0.1.2
[0.1.1]: https://github.com/rsh1k/mnemosyne/releases/tag/v0.1.1
[0.1.0]: https://github.com/rsh1k/mnemosyne/releases/tag/v0.1.0

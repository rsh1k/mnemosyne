# NIST & OWASP Control Mapping

> **Generated from `src/mnemosyne/nist/__init__.py`.** This is the single source of truth, also served at runtime via `GET /v1/compliance` and `mnem nist`. Do not edit by hand — change the catalog and run `python scripts/gen_nist_doc.py`.

Mnemosyne implements defense-in-depth against **OWASP ASI06 — Memory & Context Poisoning**. Each control below maps to the OWASP sub-vector it mitigates and to the relevant NIST references:

- **NIST AI 600-1** — AI Risk Management Framework: Generative AI Profile
- **NIST SP 800-218A** — Secure Software Development Practices for Generative AI (SSDF)
- **NIST SP 800-53 Rev 5** — Security and Privacy Controls
- **NIST CSF 2.0** — Cybersecurity Framework 2.0

## MN-01 — Provenance tracking & trust-tier resolution

Every write is tagged with its origin and mapped to a trust tier before use, enabling data/instruction separation.

- **OWASP:** ASI06: indirect injection, ASI01
- **NIST SP 800-53 Rev 5:** SI-10 (Information Input Validation), AC-16 (Security Attributes)
- **NIST SP 800-218A (SSDF):** PW.4, RV.1
- **NIST AI 600-1 (AI RMF):** GV-1.2, MS-2.6 (Information Integrity)
- **NIST CSF 2.0:** ID.AM, PR.DS
- **Implemented by:** `policy.engine.PolicyEngine.trust_tier`, `core.models.Provenance`

## MN-02 — Instruction-surface trust invariant

Content below TRUSTED tier can never be written to the INSTRUCTION control plane (system prompt, hooks, config) -- the MemoryTrap boundary.

- **OWASP:** ASI06: memory & context poisoning, ASI01: goal hijack
- **NIST SP 800-53 Rev 5:** AC-3 (Access Enforcement), AC-4 (Information Flow Enforcement), CM-5
- **NIST SP 800-218A (SSDF):** PW.1, PW.4
- **NIST AI 600-1 (AI RMF):** MS-2.6, MG-4.1
- **NIST CSF 2.0:** PR.AC, PR.DS
- **Implemented by:** `policy.engine.PolicyEngine.decide`

## MN-03 — Inline injection detection

Signature/heuristic detection of instruction-override content.

- **OWASP:** ASI06: direct injection, ASI01
- **NIST SP 800-53 Rev 5:** SI-10, SI-3 (Malicious Code Protection), SI-4 (System Monitoring)
- **NIST SP 800-218A (SSDF):** PW.7, RV.1
- **NIST AI 600-1 (AI RMF):** MS-2.6, MG-2.2
- **NIST CSF 2.0:** DE.CM
- **Implemented by:** `detectors.injection.InjectionDetector`

## MN-04 — Secrets & PII detection / redaction

Prevents exfiltration and unlawful persistence of secrets/PII.

- **OWASP:** ASI06, ASI03: identity & privilege abuse
- **NIST SP 800-53 Rev 5:** SC-28 (Protection of Information at Rest), SI-12, AC-23
- **NIST SP 800-218A (SSDF):** PW.5, RV.1
- **NIST AI 600-1 (AI RMF):** MS-2.10 (Data Privacy)
- **NIST CSF 2.0:** PR.DS, PR.IP
- **Implemented by:** `detectors.secrets_pii.SecretsPiiDetector`

## MN-05 — Behavioral baseline / sleeper-agent detection

Statistical drift detection over per-writer history.

- **OWASP:** ASI06: gradual erosion, ASI10: rogue agents
- **NIST SP 800-53 Rev 5:** SI-4, AU-6 (Audit Review/Analysis), CA-7 (Continuous Monitoring)
- **NIST SP 800-218A (SSDF):** RV.1, RV.2
- **NIST AI 600-1 (AI RMF):** MS-2.6, MG-4.1
- **NIST CSF 2.0:** DE.AE, DE.CM
- **Implemented by:** `detectors.anomaly.AnomalyDetector`

## MN-06 — Record integrity (HMAC) at rest

Detects out-of-band tampering of stored memory records.

- **OWASP:** ASI06: tampering at rest, ASI04
- **NIST SP 800-53 Rev 5:** SC-28(1), SI-7 (Software/Firmware/Info Integrity), AU-9
- **NIST SP 800-218A (SSDF):** PS.2, PW.6
- **NIST AI 600-1 (AI RMF):** MS-2.6
- **NIST CSF 2.0:** PR.DS, DE.CM
- **Implemented by:** `integrity.signer.Signer`

## MN-07 — Tamper-evident audit log (hash chain)

Non-repudiable record of every memory decision.

- **OWASP:** ASI06, ASI09
- **NIST SP 800-53 Rev 5:** AU-2, AU-3, AU-9 (Protection of Audit Info), AU-10 (Non-repudiation)
- **NIST SP 800-218A (SSDF):** PO.3, RV.2
- **NIST AI 600-1 (AI RMF):** GV-1.4, MS-1.1
- **NIST CSF 2.0:** PR.PT, DE.AE, RS.AN
- **Implemented by:** `integrity.audit.AuditLog`

## MN-08 — Memory segmentation (namespacing)

Per-tenant / per-session isolation prevents cross-contamination.

- **OWASP:** ASI06: cross-session contamination, ASI07
- **NIST SP 800-53 Rev 5:** SC-2 (Separation), AC-4, SC-4 (Information in Shared Resources)
- **NIST SP 800-218A (SSDF):** PW.4
- **NIST AI 600-1 (AI RMF):** MS-2.6
- **NIST CSF 2.0:** PR.AC, PR.DS
- **Implemented by:** `store.base.MemoryStore (namespace key)`

## MN-09 — Quarantine with human-in-the-loop promotion

Suspicious content held for audited review rather than dropped.

- **OWASP:** ASI06, ASI09: human-agent trust exploitation
- **NIST SP 800-53 Rev 5:** SI-4, IR-4 (Incident Handling), AC-3
- **NIST SP 800-218A (SSDF):** RV.2, RV.3
- **NIST AI 600-1 (AI RMF):** MG-2.2, MG-4.1
- **NIST CSF 2.0:** RS.MI, DE.AE
- **Implemented by:** `store.base.QuarantineStore`, `core.gateway.MemoryGateway.promote_quarantined`

## MN-10 — Fail-closed evaluation & observability

Detector failures deny by default; metrics/logs expose posture.

- **OWASP:** ASI06, ASI08: cascading failures
- **NIST SP 800-53 Rev 5:** SI-4, SC-24 (Fail in Known State), SI-11
- **NIST SP 800-218A (SSDF):** RV.1, RV.3
- **NIST AI 600-1 (AI RMF):** MG-3.1, MS-1.1
- **NIST CSF 2.0:** DE.CM, RS.AN
- **Implemented by:** `core.gateway.MemoryGateway`, `telemetry.Metrics`

## MN-11 — Hidden-content & encoding-obfuscation detection

Detects invisible-Unicode smuggling used in document-injection attacks -- Unicode Tag characters, bidirectional overrides (Trojan Source), and zero-width characters interleaved with text -- and neutralises them on sanitise while preserving legitimate emoji and right-to-left script.

- **OWASP:** ASI06: indirect injection, ASI06: document injection
- **NIST SP 800-53 Rev 5:** SI-10 (Information Input Validation), SI-3 (Malicious Code Protection)
- **NIST SP 800-218A (SSDF):** PW.4, RV.1
- **NIST AI 600-1 (AI RMF):** MS-2.6 (Information Integrity), MG-4.1
- **NIST CSF 2.0:** DE.CM, PR.DS
- **Implemented by:** `detectors.obfuscation.ObfuscationDetector`

---

## Summary matrix

| Control | Name | OWASP | Key NIST refs |
|---|---|---|---|
| MN-01 | Provenance tracking & trust-tier resolution | ASI06: indirect injection | SI-10 (Information Input Validation); GV-1.2 |
| MN-02 | Instruction-surface trust invariant | ASI06: memory & context poisoning | AC-3 (Access Enforcement); MS-2.6 |
| MN-03 | Inline injection detection | ASI06: direct injection | SI-10; MS-2.6 |
| MN-04 | Secrets & PII detection / redaction | ASI06 | SC-28 (Protection of Information at Rest); MS-2.10 (Data Privacy) |
| MN-05 | Behavioral baseline / sleeper-agent detection | ASI06: gradual erosion | SI-4; MS-2.6 |
| MN-06 | Record integrity (HMAC) at rest | ASI06: tampering at rest | SC-28(1); MS-2.6 |
| MN-07 | Tamper-evident audit log (hash chain) | ASI06 | AU-2; GV-1.4 |
| MN-08 | Memory segmentation (namespacing) | ASI06: cross-session contamination | SC-2 (Separation); MS-2.6 |
| MN-09 | Quarantine with human-in-the-loop promotion | ASI06 | SI-4; MG-2.2 |
| MN-10 | Fail-closed evaluation & observability | ASI06 | SI-4; MG-3.1 |
| MN-11 | Hidden-content & encoding-obfuscation detection | ASI06: indirect injection | SI-10 (Information Input Validation); MS-2.6 (Information Integrity) |

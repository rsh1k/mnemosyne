"""Machine-readable control mapping.

Maps each Mnemosyne control to the OWASP ASI06 sub-vector it mitigates and to the
relevant NIST references:

* **NIST AI 600-1** -- AI RMF Generative AI Profile (risk actions)
* **NIST SP 800-218A** -- SSDF Community Profile for Generative AI (secure dev)
* **NIST SP 800-53 Rev 5** -- Security & Privacy Controls
* **NIST CSF 2.0** -- Cybersecurity Framework functions

This is consumed by ``mnemosyne nist`` (CLI) and the ``/compliance`` API route to
emit an auditor-friendly report, so the mapping never drifts from the code.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ControlMapping:
    control_id: str
    name: str
    description: str
    owasp: list[str] = field(default_factory=list)
    nist_80053: list[str] = field(default_factory=list)
    nist_ssdf_218a: list[str] = field(default_factory=list)
    nist_ai_600_1: list[str] = field(default_factory=list)
    nist_csf_20: list[str] = field(default_factory=list)
    implemented_by: list[str] = field(default_factory=list)


CONTROL_CATALOG: list[ControlMapping] = [
    ControlMapping(
        control_id="MN-01",
        name="Provenance tracking & trust-tier resolution",
        description=(
            "Every write is tagged with its origin and mapped to a trust tier "
            "before use, enabling data/instruction separation."
        ),
        owasp=["ASI06: indirect injection", "ASI01"],
        nist_80053=["SI-10 (Information Input Validation)", "AC-16 (Security Attributes)"],
        nist_ssdf_218a=["PW.4", "RV.1"],
        nist_ai_600_1=["GV-1.2", "MS-2.6 (Information Integrity)"],
        nist_csf_20=["ID.AM", "PR.DS"],
        implemented_by=["policy.engine.PolicyEngine.trust_tier", "core.models.Provenance"],
    ),
    ControlMapping(
        control_id="MN-02",
        name="Instruction-surface trust invariant",
        description=(
            "Content below TRUSTED tier can never be written to the INSTRUCTION "
            "control plane (system prompt, hooks, config) -- the MemoryTrap boundary."
        ),
        owasp=["ASI06: memory & context poisoning", "ASI01: goal hijack"],
        nist_80053=["AC-3 (Access Enforcement)", "AC-4 (Information Flow Enforcement)", "CM-5"],
        nist_ssdf_218a=["PW.1", "PW.4"],
        nist_ai_600_1=["MS-2.6", "MG-4.1"],
        nist_csf_20=["PR.AC", "PR.DS"],
        implemented_by=["policy.engine.PolicyEngine.decide"],
    ),
    ControlMapping(
        control_id="MN-03",
        name="Inline injection detection",
        description="Signature/heuristic detection of instruction-override content.",
        owasp=["ASI06: direct injection", "ASI01"],
        nist_80053=["SI-10", "SI-3 (Malicious Code Protection)", "SI-4 (System Monitoring)"],
        nist_ssdf_218a=["PW.7", "RV.1"],
        nist_ai_600_1=["MS-2.6", "MG-2.2"],
        nist_csf_20=["DE.CM"],
        implemented_by=["detectors.injection.InjectionDetector"],
    ),
    ControlMapping(
        control_id="MN-04",
        name="Secrets & PII detection / redaction",
        description="Prevents exfiltration and unlawful persistence of secrets/PII.",
        owasp=["ASI06", "ASI03: identity & privilege abuse"],
        nist_80053=["SC-28 (Protection of Information at Rest)", "SI-12", "AC-23"],
        nist_ssdf_218a=["PW.5", "RV.1"],
        nist_ai_600_1=["MS-2.10 (Data Privacy)"],
        nist_csf_20=["PR.DS", "PR.IP"],
        implemented_by=["detectors.secrets_pii.SecretsPiiDetector"],
    ),
    ControlMapping(
        control_id="MN-05",
        name="Behavioral baseline / sleeper-agent detection",
        description="Statistical drift detection over per-writer history.",
        owasp=["ASI06: gradual erosion", "ASI10: rogue agents"],
        nist_80053=["SI-4", "AU-6 (Audit Review/Analysis)", "CA-7 (Continuous Monitoring)"],
        nist_ssdf_218a=["RV.1", "RV.2"],
        nist_ai_600_1=["MS-2.6", "MG-4.1"],
        nist_csf_20=["DE.AE", "DE.CM"],
        implemented_by=["detectors.anomaly.AnomalyDetector"],
    ),
    ControlMapping(
        control_id="MN-06",
        name="Record integrity (HMAC) at rest",
        description="Detects out-of-band tampering of stored memory records.",
        owasp=["ASI06: tampering at rest", "ASI04"],
        nist_80053=["SC-28(1)", "SI-7 (Software/Firmware/Info Integrity)", "AU-9"],
        nist_ssdf_218a=["PS.2", "PW.6"],
        nist_ai_600_1=["MS-2.6"],
        nist_csf_20=["PR.DS", "DE.CM"],
        implemented_by=["integrity.signer.Signer"],
    ),
    ControlMapping(
        control_id="MN-07",
        name="Tamper-evident audit log (hash chain)",
        description="Non-repudiable record of every memory decision.",
        owasp=["ASI06", "ASI09"],
        nist_80053=["AU-2", "AU-3", "AU-9 (Protection of Audit Info)", "AU-10 (Non-repudiation)"],
        nist_ssdf_218a=["PO.3", "RV.2"],
        nist_ai_600_1=["GV-1.4", "MS-1.1"],
        nist_csf_20=["PR.PT", "DE.AE", "RS.AN"],
        implemented_by=["integrity.audit.AuditLog"],
    ),
    ControlMapping(
        control_id="MN-08",
        name="Memory segmentation (namespacing)",
        description="Per-tenant / per-session isolation prevents cross-contamination.",
        owasp=["ASI06: cross-session contamination", "ASI07"],
        nist_80053=["SC-2 (Separation)", "AC-4", "SC-4 (Information in Shared Resources)"],
        nist_ssdf_218a=["PW.4"],
        nist_ai_600_1=["MS-2.6"],
        nist_csf_20=["PR.AC", "PR.DS"],
        implemented_by=["store.base.MemoryStore (namespace key)"],
    ),
    ControlMapping(
        control_id="MN-09",
        name="Quarantine with human-in-the-loop promotion",
        description="Suspicious content held for audited review rather than dropped.",
        owasp=["ASI06", "ASI09: human-agent trust exploitation"],
        nist_80053=["SI-4", "IR-4 (Incident Handling)", "AC-3"],
        nist_ssdf_218a=["RV.2", "RV.3"],
        nist_ai_600_1=["MG-2.2", "MG-4.1"],
        nist_csf_20=["RS.MI", "DE.AE"],
        implemented_by=["store.base.QuarantineStore", "core.gateway.MemoryGateway.promote_quarantined"],
    ),
    ControlMapping(
        control_id="MN-10",
        name="Fail-closed evaluation & observability",
        description="Detector failures deny by default; metrics/logs expose posture.",
        owasp=["ASI06", "ASI08: cascading failures"],
        nist_80053=["SI-4", "SC-24 (Fail in Known State)", "SI-11"],
        nist_ssdf_218a=["RV.1", "RV.3"],
        nist_ai_600_1=["MG-3.1", "MS-1.1"],
        nist_csf_20=["DE.CM", "RS.AN"],
        implemented_by=["core.gateway.MemoryGateway", "telemetry.Metrics"],
    ),
    ControlMapping(
        control_id="MN-11",
        name="Hidden-content & encoding-obfuscation detection",
        description=(
            "Detects invisible-Unicode smuggling used in document-injection "
            "attacks -- Unicode Tag characters, bidirectional overrides "
            "(Trojan Source), and zero-width characters interleaved with text -- "
            "and neutralises them on sanitise while preserving legitimate emoji "
            "and right-to-left script."
        ),
        owasp=["ASI06: indirect injection", "ASI06: document injection"],
        nist_80053=["SI-10 (Information Input Validation)", "SI-3 (Malicious Code Protection)"],
        nist_ssdf_218a=["PW.4", "RV.1"],
        nist_ai_600_1=["MS-2.6 (Information Integrity)", "MG-4.1"],
        nist_csf_20=["DE.CM", "PR.DS"],
        implemented_by=["detectors.obfuscation.ObfuscationDetector"],
    ),
]


def catalog_as_dicts() -> list[dict]:
    out = []
    for c in CONTROL_CATALOG:
        out.append(
            {
                "control_id": c.control_id,
                "name": c.name,
                "description": c.description,
                "owasp": c.owasp,
                "nist_sp_800_53": c.nist_80053,
                "nist_sp_800_218a": c.nist_ssdf_218a,
                "nist_ai_600_1": c.nist_ai_600_1,
                "nist_csf_2_0": c.nist_csf_20,
                "implemented_by": c.implemented_by,
            }
        )
    return out

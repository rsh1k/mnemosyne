"""Policy engine tests.

These lock down the *cardinal ASI06 invariant* (untrusted content can never
reach the instruction/control-plane surface) and the precedence rules that make
the engine fail safe. They are deliberately written against the declarative
default policy so that a regression in either the YAML or the engine is caught.
"""

from __future__ import annotations

import pytest

from mnemosyne.core.exceptions import PolicyConfigurationError
from mnemosyne.core.models import (
    Decision,
    Finding,
    MemorySurface,
    Provenance,
    ScanResult,
    Severity,
    TrustTier,
)
from mnemosyne.policy.engine import PolicyEngine, _most_restrictive


@pytest.fixture
def policy() -> PolicyEngine:
    return PolicyEngine.default()


def _scan(*findings: Finding) -> ScanResult:
    return ScanResult(findings=list(findings))


class TestProvenanceMapping:
    def test_user_direct_is_trusted(self, policy: PolicyEngine):
        assert policy.trust_tier(Provenance.USER_DIRECT) is TrustTier.TRUSTED

    def test_tool_output_is_limited(self, policy: PolicyEngine):
        assert policy.trust_tier(Provenance.TOOL_OUTPUT) is TrustTier.LIMITED

    def test_external_web_is_untrusted(self, policy: PolicyEngine):
        assert policy.trust_tier(Provenance.EXTERNAL_WEB) is TrustTier.UNTRUSTED

    def test_unknown_provenance_defaults_untrusted(self, policy: PolicyEngine):
        assert policy.trust_tier(Provenance.UNKNOWN) is TrustTier.UNTRUSTED


class TestCardinalInvariant:
    """Untrusted/limited content must never reach the INSTRUCTION surface."""

    def test_untrusted_to_instruction_is_denied(self, policy: PolicyEngine):
        decision, reasons = policy.decide(
            surface=MemorySurface.INSTRUCTION,
            trust_tier=TrustTier.UNTRUSTED,
            scan=_scan(),
        )
        assert decision is Decision.DENY
        assert any("trust tier" in r for r in reasons)

    def test_limited_to_instruction_is_denied(self, policy: PolicyEngine):
        # Even merely-limited content cannot shape future behaviour.
        decision, _ = policy.decide(
            surface=MemorySurface.INSTRUCTION,
            trust_tier=TrustTier.LIMITED,
            scan=_scan(),
        )
        assert decision is Decision.DENY

    def test_trusted_to_instruction_is_allowed(self, policy: PolicyEngine):
        decision, _ = policy.decide(
            surface=MemorySurface.INSTRUCTION,
            trust_tier=TrustTier.TRUSTED,
            scan=_scan(),
        )
        assert decision is Decision.ALLOW

    def test_limited_to_knowledge_is_allowed(self, policy: PolicyEngine):
        decision, _ = policy.decide(
            surface=MemorySurface.KNOWLEDGE,
            trust_tier=TrustTier.LIMITED,
            scan=_scan(),
        )
        assert decision is Decision.ALLOW

    def test_untrusted_to_knowledge_is_quarantined(self, policy: PolicyEngine):
        decision, _ = policy.decide(
            surface=MemorySurface.KNOWLEDGE,
            trust_tier=TrustTier.UNTRUSTED,
            scan=_scan(),
        )
        assert decision is Decision.QUARANTINE


class TestSeverityDecisions:
    def test_high_injection_on_knowledge_quarantines(self, policy: PolicyEngine):
        finding = Finding(
            detector="injection",
            severity=Severity.HIGH,
            score=0.8,
            metadata={"kind": "override_directive"},
        )
        decision, _ = policy.decide(
            surface=MemorySurface.KNOWLEDGE,
            trust_tier=TrustTier.LIMITED,
            scan=_scan(finding),
        )
        assert decision is Decision.QUARANTINE

    def test_critical_injection_on_instruction_denies(self, policy: PolicyEngine):
        finding = Finding(
            detector="injection",
            severity=Severity.CRITICAL,
            score=0.99,
            metadata={"kind": "persistence"},
        )
        decision, _ = policy.decide(
            surface=MemorySurface.INSTRUCTION,
            trust_tier=TrustTier.TRUSTED,
            scan=_scan(finding),
        )
        assert decision is Decision.DENY

    def test_low_severity_is_allowed(self, policy: PolicyEngine):
        finding = Finding(
            detector="anomaly", severity=Severity.LOW, score=0.2, metadata={"kind": "entropy"}
        )
        decision, _ = policy.decide(
            surface=MemorySurface.KNOWLEDGE,
            trust_tier=TrustTier.TRUSTED,
            scan=_scan(finding),
        )
        assert decision is Decision.ALLOW


class TestSecretsRule:
    def test_secret_in_knowledge_is_sanitized(self, policy: PolicyEngine):
        finding = Finding(
            detector="secrets_pii",
            severity=Severity.HIGH,
            score=0.9,
            metadata={"kind": "secret"},
        )
        decision, _ = policy.decide(
            surface=MemorySurface.KNOWLEDGE,
            trust_tier=TrustTier.TRUSTED,
            scan=_scan(finding),
        )
        # Dedicated secrets rule prefers redaction over loss, not the severity table.
        assert decision is Decision.SANITIZE

    def test_secret_in_instruction_is_denied(self, policy: PolicyEngine):
        finding = Finding(
            detector="secrets_pii",
            severity=Severity.HIGH,
            score=0.9,
            metadata={"kind": "secret"},
        )
        decision, _ = policy.decide(
            surface=MemorySurface.INSTRUCTION,
            trust_tier=TrustTier.TRUSTED,
            scan=_scan(finding),
        )
        assert decision is Decision.DENY


class TestPrecedence:
    def test_most_restrictive_wins(self):
        assert _most_restrictive(Decision.ALLOW, Decision.DENY) is Decision.DENY
        assert _most_restrictive(Decision.SANITIZE, Decision.QUARANTINE) is Decision.QUARANTINE
        assert _most_restrictive(Decision.ALLOW, Decision.SANITIZE) is Decision.SANITIZE

    def test_tier_violation_and_secret_combine_to_strictest(self, policy: PolicyEngine):
        # Limited->instruction (deny) plus a secret (deny on instruction) -> deny.
        finding = Finding(
            detector="secrets_pii", severity=Severity.HIGH, score=0.9, metadata={"kind": "secret"}
        )
        decision, reasons = policy.decide(
            surface=MemorySurface.INSTRUCTION,
            trust_tier=TrustTier.LIMITED,
            scan=_scan(finding),
        )
        assert decision is Decision.DENY
        assert len(reasons) >= 2


class TestInjectionVsAnomalySplit:
    """Injection findings use a stricter table than anomaly findings.

    Rationale: `sanitize` cannot neutralise injection *phrasing* (it only strips
    secrets/PII and hidden chars), so a medium injection on knowledge is held
    for review, while a medium *anomaly* (e.g. behavioural drift) stays gentle to
    avoid false positives on legitimate large/odd-but-benign writes.
    """

    def test_medium_injection_on_knowledge_quarantines(self, policy: PolicyEngine):
        finding = Finding(
            detector="injection", severity=Severity.MEDIUM, score=0.45,
            metadata={"families": ["override_directive"]},
        )
        decision, _ = policy.decide(
            surface=MemorySurface.KNOWLEDGE, trust_tier=TrustTier.LIMITED,
            scan=_scan(finding),
        )
        assert decision is Decision.QUARANTINE

    def test_medium_anomaly_on_knowledge_stays_gentle(self, policy: PolicyEngine):
        finding = Finding(
            detector="anomaly", severity=Severity.MEDIUM, score=0.5,
            metadata={"kind": "behavioral_drift"},
        )
        decision, _ = policy.decide(
            surface=MemorySurface.KNOWLEDGE, trust_tier=TrustTier.LIMITED,
            scan=_scan(finding),
        )
        # Generic table: knowledge.medium -> sanitize (not quarantine).
        assert decision is Decision.SANITIZE

    def test_any_injection_on_instruction_denies(self, policy: PolicyEngine):
        finding = Finding(
            detector="injection", severity=Severity.MEDIUM, score=0.45,
            metadata={"families": ["persistence"]},
        )
        decision, _ = policy.decide(
            surface=MemorySurface.INSTRUCTION, trust_tier=TrustTier.TRUSTED,
            scan=_scan(finding),
        )
        assert decision is Decision.DENY

    def test_fallback_to_generic_when_section_absent(self):
        # A policy without injection_severity_decisions falls back to the table.
        doc = {
            "provenance_trust": {"user_direct": "trusted"},
            "surface_min_tier": {"knowledge": "limited"},
            "severity_decisions": {"knowledge": {"medium": "sanitize"}},
        }
        engine = PolicyEngine(doc)
        finding = Finding(detector="injection", severity=Severity.MEDIUM, score=0.45)
        decision, _ = engine.decide(
            surface=MemorySurface.KNOWLEDGE, trust_tier=TrustTier.LIMITED,
            scan=_scan(finding),
        )
        assert decision is Decision.SANITIZE


class TestValidation:
    def test_missing_section_raises(self):
        with pytest.raises(PolicyConfigurationError):
            PolicyEngine({"provenance_trust": {}})  # missing surface_min_tier etc.

    def test_clean_allow_has_reason(self, policy: PolicyEngine):
        _, reasons = policy.decide(
            surface=MemorySurface.SCRATCH,
            trust_tier=TrustTier.TRUSTED,
            scan=_scan(),
        )
        assert reasons and "allowed" in reasons[-1]

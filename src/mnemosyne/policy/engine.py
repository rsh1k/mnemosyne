"""Policy engine.

Translates detector findings plus content provenance/surface into a concrete
:class:`Decision`. The engine is declarative (YAML-backed) so security teams can
tune posture without touching code, and the *most restrictive* applicable rule
always wins (fail-safe defaults, NIST SP 800-53 AC-3 / SC concept).

Decision precedence (highest wins): DENY > QUARANTINE > SANITIZE > ALLOW.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from mnemosyne.core.exceptions import PolicyConfigurationError
from mnemosyne.core.models import (
    Decision,
    MemorySurface,
    Provenance,
    ScanResult,
    Severity,
    TrustTier,
)

_DEFAULT_POLICY_FILE = Path(__file__).with_name("default_policy.yaml")

_DECISION_RANK = {
    Decision.ALLOW: 0,
    Decision.SANITIZE: 1,
    Decision.QUARANTINE: 2,
    Decision.DENY: 3,
}


def _most_restrictive(*decisions: Decision) -> Decision:
    return max(decisions, key=lambda d: _DECISION_RANK[d])


class PolicyEngine:
    def __init__(self, document: dict[str, Any]) -> None:
        self._doc = document
        self._validate()

    # -- construction ----------------------------------------------------
    @classmethod
    def from_path(cls, path: str | Path | None) -> PolicyEngine:
        target = Path(path) if path else _DEFAULT_POLICY_FILE
        try:
            doc = yaml.safe_load(target.read_text("utf-8"))
        except FileNotFoundError as exc:  # pragma: no cover - defensive
            raise PolicyConfigurationError(f"Policy file not found: {target}") from exc
        except yaml.YAMLError as exc:
            raise PolicyConfigurationError(f"Invalid policy YAML: {exc}") from exc
        return cls(doc)

    @classmethod
    def default(cls) -> PolicyEngine:
        return cls.from_path(None)

    def _validate(self) -> None:
        for key in ("provenance_trust", "surface_min_tier", "severity_decisions"):
            if key not in self._doc:
                raise PolicyConfigurationError(f"Policy missing required section: {key}")

    # -- resolution ------------------------------------------------------
    def trust_tier(self, provenance: Provenance) -> TrustTier:
        raw = self._doc["provenance_trust"].get(provenance.value, "untrusted")
        return TrustTier(raw)

    def _min_tier(self, surface: MemorySurface) -> TrustTier:
        raw = self._doc["surface_min_tier"].get(surface.value, "trusted")
        return TrustTier(raw)

    def required_tier(self, surface: MemorySurface) -> TrustTier:
        """Public: the minimum trust tier a surface will accept.

        Used by audited human promotion to elevate a quarantined record to
        exactly the trust its target surface requires -- no more.
        """

        return self._min_tier(surface)

    def _tier_violation_decision(self, surface: MemorySurface) -> Decision:
        raw = self._doc.get("on_tier_violation", {}).get(surface.value, "deny")
        return Decision(raw)

    def _severity_decision(self, surface: MemorySurface, severity: Severity) -> Decision:
        if severity is Severity.NONE:
            return Decision.ALLOW
        table = self._doc["severity_decisions"].get(surface.value, {})
        raw = table.get(severity.value, "allow")
        return Decision(raw)

    def _injection_severity_decision(
        self, surface: MemorySurface, severity: Severity
    ) -> Decision:
        """Severity decision for *injection-class* findings.

        Injection phrasing cannot be neutralised by ``sanitize`` (which only
        strips secrets/PII and hidden characters), so adversarial instruction-
        like text in stored memory is held for review rather than kept. Uses the
        optional ``injection_severity_decisions`` policy section, falling back to
        the generic ``severity_decisions`` table when it is absent (so existing
        custom policies keep working unchanged).
        """

        if severity is Severity.NONE:
            return Decision.ALLOW
        table = self._doc.get("injection_severity_decisions", {}).get(surface.value)
        if table is None:
            return self._severity_decision(surface, severity)
        raw = table.get(severity.value, "allow")
        return Decision(raw)

    def _secrets_decision(self, surface: MemorySurface) -> Decision:
        sec = self._doc.get("secrets", {})
        raw = sec.get(surface.value, sec.get("default", "sanitize"))
        return Decision(raw)

    # -- the decision ----------------------------------------------------
    def decide(
        self,
        *,
        surface: MemorySurface,
        trust_tier: TrustTier,
        scan: ScanResult,
    ) -> tuple[Decision, list[str]]:
        """Return the final decision and human-readable reasons.

        Secrets/PII findings are governed *only* by the dedicated sensitive-data
        rule (so legitimate writes can be redacted rather than lost). Injection
        findings are governed by a stricter table (sanitize cannot neutralise
        injection phrasing), while anomaly/obfuscation findings use the generic
        severity table. The most restrictive applicable decision always wins.
        """

        decision = Decision.ALLOW
        reasons: list[str] = []

        sensitive_kinds = {"secret", "pii"}
        injection = ScanResult(
            findings=[f for f in scan.findings if f.detector == "injection"]
        )
        other_non_sensitive = ScanResult(
            findings=[
                f
                for f in scan.findings
                if f.detector != "injection"
                and f.metadata.get("kind") not in sensitive_kinds
            ]
        )
        has_sensitive = any(
            f.metadata.get("kind") in sensitive_kinds
            for f in scan.by_detector("secrets_pii")
        )

        # 1. Cardinal invariant: enforce the minimum trust tier for the surface.
        required = self._min_tier(surface)
        if trust_tier.rank < required.rank:
            viol = self._tier_violation_decision(surface)
            decision = _most_restrictive(decision, viol)
            reasons.append(
                f"trust tier '{trust_tier.value}' below required '{required.value}' "
                f"for surface '{surface.value}' -> {viol.value}"
            )

        # 2a. Anomaly / obfuscation findings via the generic severity table.
        sev = other_non_sensitive.max_severity
        sev_decision = self._severity_decision(surface, sev)
        if sev_decision is not Decision.ALLOW:
            decision = _most_restrictive(decision, sev_decision)
            reasons.append(
                f"max finding severity '{sev.value}' on surface "
                f"'{surface.value}' -> {sev_decision.value}"
            )

        # 2b. Injection findings via the stricter injection table.
        inj_sev = injection.max_severity
        inj_decision = self._injection_severity_decision(surface, inj_sev)
        if inj_decision is not Decision.ALLOW:
            decision = _most_restrictive(decision, inj_decision)
            reasons.append(
                f"injection severity '{inj_sev.value}' on surface "
                f"'{surface.value}' -> {inj_decision.value}"
            )

        # 3. Sensitive-data (secrets/PII) handling via the dedicated rule.
        if has_sensitive:
            sec_decision = self._secrets_decision(surface)
            decision = _most_restrictive(decision, sec_decision)
            reasons.append(f"sensitive data (secret/PII) present -> {sec_decision.value}")

        if not reasons:
            reasons.append("no policy triggers; allowed")

        return decision, reasons

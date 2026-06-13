"""Secrets and PII detector.

Poisoned memory is a bidirectional risk: attackers inject instructions *into*
memory, and a poisoned agent exfiltrates secrets *out* through memory it writes.
This detector catches credentials/keys and common PII so they are not silently
persisted to a long-lived store (which would also be a data-protection problem
under NIST SP 800-53 SC-28 / privacy controls).

It returns a redacted copy via :meth:`redact` so the policy engine can choose
SANITIZE instead of an outright block when appropriate.
"""

from __future__ import annotations

import re

from mnemosyne.core.models import Finding, ScanResult, Severity
from mnemosyne.detectors.base import Detector, DetectorContext

# (label, severity, pattern). Patterns favour precision to limit false positives.
_SECRET_PATTERNS: list[tuple[str, Severity, re.Pattern[str]]] = [
    ("aws_access_key_id", Severity.CRITICAL, re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", Severity.CRITICAL, re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("slack_token", Severity.HIGH, re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("openai_key", Severity.CRITICAL, re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("anthropic_key", Severity.CRITICAL, re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("google_api_key", Severity.HIGH, re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", Severity.HIGH, re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("private_key_block", Severity.CRITICAL, re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("generic_assignment", Severity.MEDIUM, re.compile(
        r"(?i)\b(?:api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*['\"]?[A-Za-z0-9/+_\-]{12,}['\"]?")),
]

_PII_PATTERNS: list[tuple[str, Severity, re.Pattern[str]]] = [
    ("email", Severity.LOW, re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("us_ssn", Severity.HIGH, re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", Severity.HIGH, re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("ipv4", Severity.LOW, re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]


def _luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


class SecretsPiiDetector(Detector):
    name = "secrets_pii"

    def scan(self, content: str, ctx: DetectorContext) -> ScanResult:  # noqa: ARG002
        if not content:
            return ScanResult()

        findings: list[Finding] = []

        for label, sev, pat in _SECRET_PATTERNS:
            matches = pat.findall(content)
            if matches:
                findings.append(
                    Finding(
                        detector=self.name,
                        severity=sev,
                        score=0.9 if sev.rank >= Severity.HIGH.rank else 0.5,
                        summary=f"Potential credential/secret detected: {label}",
                        evidence=[f"{label} (x{len(matches)})"],
                        metadata={"kind": "secret", "label": label, "count": len(matches)},
                    )
                )

        for label, sev, pat in _PII_PATTERNS:
            raw_matches = pat.findall(content)
            if not raw_matches:
                continue
            if label == "credit_card":
                raw_matches = [m for m in raw_matches if _luhn_ok(m)]
                if not raw_matches:
                    continue
            findings.append(
                Finding(
                    detector=self.name,
                    severity=sev,
                    score=0.7 if sev.rank >= Severity.HIGH.rank else 0.2,
                    summary=f"Potential PII detected: {label}",
                    evidence=[f"{label} (x{len(raw_matches)})"],
                    metadata={"kind": "pii", "label": label, "count": len(raw_matches)},
                )
            )

        return ScanResult(findings=findings)

    @staticmethod
    def redact(content: str) -> str:
        """Return a copy with detected secrets/PII replaced by placeholders."""

        redacted = content
        for label, _sev, pat in _SECRET_PATTERNS:
            redacted = pat.sub(f"[REDACTED:{label}]", redacted)
        for label, _sev, pat in _PII_PATTERNS:
            if label in ("ipv4",):  # too noisy to redact by default
                continue
            redacted = pat.sub(f"[REDACTED:{label}]", redacted)
        return redacted

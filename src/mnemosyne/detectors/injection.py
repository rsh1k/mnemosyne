"""Instruction-override / prompt-injection detector.

ASI06 is dangerous precisely because stored *data* can be rewritten as future
*instructions*. This detector looks for the linguistic signatures of content
that is trying to behave like an instruction to the agent: override directives,
role re-assignment, persistence/"remember this forever" phrasing, tool/config
manipulation, and exfiltration directives. It is deliberately
signature-and-heuristic based so it is deterministic, fast (microseconds),
explainable, and runnable inline -- but it is registered as a plug-in so an ML
classifier can be added alongside or in front of it.

Scoring is additive and saturating; each matched family contributes weight, and
matches on a high-trust ``INSTRUCTION`` surface are amplified because the blast
radius there is the agent's control plane.
"""

from __future__ import annotations

import re

from mnemosyne.core.models import Finding, ScanResult, Severity
from mnemosyne.detectors.base import Detector, DetectorContext

# Each pattern family carries a base weight. Patterns are case-insensitive.
_FAMILIES: list[tuple[str, float, list[str]]] = [
    (
        "override_directive",
        0.45,
        [
            r"\bignore (?:all |any |the )?(?:previous|prior|above|preceding) (?:instructions?|prompts?|context|rules?)\b",
            r"\bdisregard (?:all |any |the )?(?:previous|prior|above|earlier) (?:instructions?|rules?|guidance)\b",
            r"\boverrid(?:e|ing) (?:the |your )?(?:system|safety|previous) (?:prompt|instructions?|rules?)\b",
            r"\bforget (?:everything|all (?:previous|prior)|what you were told)\b",
        ],
    ),
    (
        "role_reassignment",
        0.4,
        [
            r"\byou are now (?:a|an|the)\b",
            r"\bfrom now on,? (?:you|act|behave|respond)\b",
            r"\bact as (?:if you are |an? )?(?:unrestricted|jailbroken|dan|developer mode)\b",
            r"\byour (?:new |real )?(?:system )?prompt is\b",
            r"\bswitch (?:to|into) (?:developer|admin|root|god) mode\b",
        ],
    ),
    (
        "persistence",
        0.5,
        [
            r"\b(?:always|permanently|from now on) remember (?:that|to|this)\b",
            r"\bstore this (?:instruction|rule|directive) (?:in|to) (?:your )?memory\b",
            r"\bin (?:all |every )?(?:future|subsequent) (?:sessions?|conversations?|projects?)\b",
            r"\bpersist (?:this|the following) across (?:sessions?|reboots?|restarts?)\b",
            r"\bnever (?:reveal|mention|tell the user) (?:that |about )?this\b",
        ],
    ),
    (
        "tooling_config_manipulation",
        0.5,
        [
            r"\b(?:add|append|write) (?:the following )?to (?:your |the )?(?:hooks?|claude\.md|config(?:uration)?|system prompt|\.mcp)\b",
            r"\b(?:install|run|execute) (?:the |this )?(?:npm |pip |curl )?(?:package|script|command|payload)\b.*\b(?:silently|without (?:asking|confirmation))\b",
            r"\bmodify (?:your |the )?(?:tool|hook|startup) configuration\b",
            r"\bset up a (?:hook|trigger) that (?:runs|executes)\b",
        ],
    ),
    (
        "exfiltration",
        0.45,
        [
            r"\b(?:send|post|exfiltrate|upload|forward) (?:all |the )?(?:secrets?|credentials?|tokens?|env(?:ironment)? (?:vars?|variables?)|api keys?|files?) to\b",
            r"\b(?:base64|hex)[- ]?encode (?:and (?:send|post|exfiltrate))\b",
            r"\bcurl\s+-[a-zA-Z]*\s+https?://[^\s]+.*\$(?:\{?[A-Z_]+)",
        ],
    ),
    (
        "delimiter_smuggling",
        0.35,
        [
            r"</?(?:system|assistant|user|instructions?|im_start|im_end)>",
            r"\[(?:system|inst|/inst|assistant)\]",
            r"#{2,}\s*(?:system|new instructions?|override)\b",
        ],
    ),
    (
        # Delayed / conditional execution -- the Gemini "delayed tool invocation"
        # pattern (Rehberger): plant a conditional that only fires on a later
        # trigger word ("if the user says yes, then store/run/send ..."). The
        # trigger and payload are decoupled in time, so a conditional clause
        # paired with a *sensitive* action is the signature, not the "if" alone.
        "delayed_execution",
        0.5,
        [
            r"\b(?:if|when|whenever|once|the next time|next time)\b[^.\n]{0,80}?\b(?:says?|ask(?:s|ed)?|mentions?|requests?|types?|writes?|responds?|replies)\b[^.\n]{0,80}?\b(?:remember|store|save|add|execute|run|install|send|forward|email|delete|disable|reveal|leak|ignore)\b",
            r"\badd (?:this|these|the following)[^.\n]{0,40}\b(?:to|into)\b[^.\n]{0,20}\bmemor(?:y|ies)\b",
            r"\b(?:store|save|commit) (?:this|the following|these)[^.\n]{0,40}\b(?:as|to|into) (?:a )?(?:false |fake )?memor(?:y|ies)\b",
        ],
    ),
]

_COMPILED: list[tuple[str, float, list[re.Pattern[str]]]] = [
    (name, weight, [re.compile(p, re.IGNORECASE) for p in pats])
    for name, weight, pats in _FAMILIES
]


def _severity_for(score: float) -> Severity:
    if score >= 0.85:
        return Severity.CRITICAL
    if score >= 0.6:
        return Severity.HIGH
    if score >= 0.35:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.NONE


class InjectionDetector(Detector):
    name = "injection"

    def scan(self, content: str, ctx: DetectorContext) -> ScanResult:
        if not content:
            return ScanResult()

        score = 0.0
        families_hit: list[str] = []
        evidence: list[str] = []

        for name, weight, patterns in _COMPILED:
            for pat in patterns:
                m = pat.search(content)
                if m:
                    score += weight
                    families_hit.append(name)
                    snippet = m.group(0)
                    evidence.append(snippet[:120])
                    break  # one hit per family is enough

        if not families_hit:
            return ScanResult()

        # Amplify when targeting the control plane: an override directive landing
        # in an INSTRUCTION surface is the MemoryTrap scenario.
        if ctx.surface.is_control_plane:
            score *= 1.5

        score = min(score, 1.0)
        severity = _severity_for(score)

        finding = Finding(
            detector=self.name,
            severity=severity,
            score=round(score, 4),
            summary=(
                f"Instruction-override signatures detected "
                f"({', '.join(sorted(set(families_hit)))})"
            ),
            evidence=evidence[:5],
            metadata={
                "families": sorted(set(families_hit)),
                "control_plane_target": ctx.surface.is_control_plane,
            },
        )
        return ScanResult(findings=[finding])

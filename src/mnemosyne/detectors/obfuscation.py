"""Hidden / obfuscated text detector.

A large fraction of real ASI06 document-injection attacks hide their payload so
a human reviewer sees nothing while the model reads everything: zero-width
characters wedged between letters, Unicode **Tags** characters (U+E0000–U+E007F)
that encode invisible ASCII, and bidirectional overrides ("Trojan Source") that
reorder how text renders versus how it is parsed. Public reporting puts the miss
rate of naive content scanners on this class of payload high precisely because
the malicious bytes are invisible.

This detector is deterministic and Unicode-aware. It deliberately does **not**
punish the legitimate uses of these code points (notably emoji ZWJ sequences and
right-to-left script marks), flagging only the patterns characteristic of
smuggling:

* **Unicode Tag characters** -- essentially never legitimate in agent memory;
  treated as critical.
* **Bidi overrides / isolates used for spoofing** (LRO/RLO/PDF, LRI/RLI/FSI/PDI)
  -- the Trojan-Source vector; high severity.
* **Zero-width characters interleaved with ASCII word characters** -- the
  hallmark of letter-by-letter smuggling, while emoji ZWJ joins (ZWJ between
  non-ASCII pictographs) are ignored.

It also exposes :meth:`strip` so the sanitise path can neutralise hidden
characters while preserving legitimate ones.
"""

from __future__ import annotations

import re

from mnemosyne.core.models import Finding, ScanResult, Severity
from mnemosyne.detectors.base import Detector, DetectorContext

# Unicode Tags block: invisible, can encode a full ASCII payload. No legitimate
# use in ordinary text.
_TAG_RANGE = (0xE0000, 0xE007F)

# Bidirectional formatting controls abused by "Trojan Source"-style attacks.
_BIDI_CONTROLS = {
    0x202A,  # LRE
    0x202B,  # RLE
    0x202C,  # PDF
    0x202D,  # LRO
    0x202E,  # RLO
    0x2066,  # LRI
    0x2067,  # RLI
    0x2068,  # FSI
    0x2069,  # PDI
}

# Zero-width / invisible spacing characters used to interleave hidden content.
# ZWJ (U+200D) is intentionally excluded here because it is load-bearing in
# emoji sequences; it is handled separately and only flagged between ASCII.
_ZERO_WIDTH = {
    0x200B,  # ZERO WIDTH SPACE
    0x200C,  # ZERO WIDTH NON-JOINER
    0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BOM (mid-string)
    0x2060,  # WORD JOINER
    0x00AD,  # SOFT HYPHEN
}
_ZWJ = 0x200D

_ALL_HIDDEN = _ZERO_WIDTH | {_ZWJ} | _BIDI_CONTROLS


def _is_ascii_word(ch: str) -> bool:
    return ch.isascii() and (ch.isalnum() or ch == "_")


class ObfuscationDetector(Detector):
    name = "obfuscation"

    def scan(self, content: str, ctx: DetectorContext) -> ScanResult:
        if not content:
            return ScanResult()

        findings: list[Finding] = []

        tag_chars = [c for c in content if _TAG_RANGE[0] <= ord(c) <= _TAG_RANGE[1]]
        if tag_chars:
            findings.append(
                Finding(
                    detector=self.name,
                    severity=Severity.CRITICAL,
                    score=0.95,
                    summary=(
                        f"Unicode Tag characters detected ({len(tag_chars)}) -- "
                        "invisible payload smuggling"
                    ),
                    evidence=[f"{len(tag_chars)} U+E00xx tag chars"],
                    metadata={"kind": "obfuscation", "technique": "unicode_tags"},
                )
            )

        bidi = [c for c in content if ord(c) in _BIDI_CONTROLS]
        if bidi:
            findings.append(
                Finding(
                    detector=self.name,
                    severity=Severity.HIGH,
                    score=0.7,
                    summary=(
                        f"Bidirectional override/isolate controls detected ({len(bidi)}) "
                        "-- possible Trojan-Source reordering"
                    ),
                    evidence=[f"{len(bidi)} bidi control chars"],
                    metadata={"kind": "obfuscation", "technique": "bidi_override"},
                )
            )

        # Zero-width chars wedged between ASCII word characters = smuggling.
        # Emoji ZWJ joins (ZWJ flanked by non-ASCII) are not counted.
        suspicious_zw = 0
        for i, ch in enumerate(content):
            cp = ord(ch)
            if cp in _ZERO_WIDTH:
                prev_ascii = i > 0 and _is_ascii_word(content[i - 1])
                next_ascii = i + 1 < len(content) and _is_ascii_word(content[i + 1])
                if prev_ascii or next_ascii:
                    suspicious_zw += 1
            elif cp == _ZWJ:
                prev_ascii = i > 0 and _is_ascii_word(content[i - 1])
                next_ascii = i + 1 < len(content) and _is_ascii_word(content[i + 1])
                # ZWJ is only suspicious when joining ASCII word chars (not emoji).
                if prev_ascii and next_ascii:
                    suspicious_zw += 1

        if suspicious_zw:
            sev = Severity.HIGH if suspicious_zw >= 3 else Severity.MEDIUM
            score = min(0.4 + 0.1 * suspicious_zw, 0.8)
            findings.append(
                Finding(
                    detector=self.name,
                    severity=sev,
                    score=round(score, 3),
                    summary=(
                        f"Zero-width characters interleaved with text ({suspicious_zw}) "
                        "-- hidden-content smuggling"
                    ),
                    evidence=[f"{suspicious_zw} interleaved zero-width chars"],
                    metadata={"kind": "obfuscation", "technique": "zero_width"},
                )
            )

        return ScanResult(findings=findings)

    @staticmethod
    def strip(content: str) -> str:
        """Remove smuggling characters while preserving legitimate emoji ZWJ.

        Tag characters, bidi controls, and zero-width spacers are removed
        unconditionally; ZWJ is removed only where it joins ASCII word characters
        (i.e. not part of an emoji sequence).
        """

        out: list[str] = []
        for i, ch in enumerate(content):
            cp = ord(ch)
            if _TAG_RANGE[0] <= cp <= _TAG_RANGE[1] or cp in _BIDI_CONTROLS or cp in _ZERO_WIDTH:
                continue
            if cp == _ZWJ:
                prev_ascii = out and _is_ascii_word(out[-1])
                next_ascii = i + 1 < len(content) and _is_ascii_word(content[i + 1])
                if prev_ascii and next_ascii:
                    continue
            out.append(ch)
        return re.sub(r"[ \t]{2,}", " ", "".join(out))

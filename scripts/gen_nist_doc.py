#!/usr/bin/env python3
"""Regenerate docs/NIST_CONTROL_MAPPING.md from the live control catalog.

The catalog in ``mnemosyne.nist`` is the single source of truth. Running this
script keeps the human-readable doc in lock-step with the code (and with the
``/v1/compliance`` API response and ``mnem nist`` CLI output).

Usage:
    python scripts/gen_nist_doc.py
"""

from __future__ import annotations

from pathlib import Path

from mnemosyne.nist import CONTROL_CATALOG

OUT = Path(__file__).resolve().parents[1] / "docs" / "NIST_CONTROL_MAPPING.md"


def render() -> str:
    lines: list[str] = []
    w = lines.append
    w("# NIST & OWASP Control Mapping\n")
    w(
        "> **Generated from `src/mnemosyne/nist/__init__.py`.** This is the single "
        "source of truth, also served at runtime via `GET /v1/compliance` and "
        "`mnem nist`. Do not edit by hand — change the catalog and run "
        "`python scripts/gen_nist_doc.py`.\n"
    )
    w(
        "Mnemosyne implements defense-in-depth against **OWASP ASI06 — Memory & "
        "Context Poisoning**. Each control below maps to the OWASP sub-vector it "
        "mitigates and to the relevant NIST references:\n"
    )
    w("- **NIST AI 600-1** — AI Risk Management Framework: Generative AI Profile")
    w("- **NIST SP 800-218A** — Secure Software Development Practices for Generative AI (SSDF)")
    w("- **NIST SP 800-53 Rev 5** — Security and Privacy Controls")
    w("- **NIST CSF 2.0** — Cybersecurity Framework 2.0\n")

    for c in CONTROL_CATALOG:
        w(f"## {c.control_id} — {c.name}\n")
        w(f"{c.description}\n")
        w(f"- **OWASP:** {', '.join(c.owasp)}")
        if c.nist_80053:
            w(f"- **NIST SP 800-53 Rev 5:** {', '.join(c.nist_80053)}")
        if c.nist_ssdf_218a:
            w(f"- **NIST SP 800-218A (SSDF):** {', '.join(c.nist_ssdf_218a)}")
        if c.nist_ai_600_1:
            w(f"- **NIST AI 600-1 (AI RMF):** {', '.join(c.nist_ai_600_1)}")
        if c.nist_csf_20:
            w(f"- **NIST CSF 2.0:** {', '.join(c.nist_csf_20)}")
        w(f"- **Implemented by:** {', '.join(f'`{i}`' for i in c.implemented_by)}\n")

    w("---\n")
    w("## Summary matrix\n")
    w("| Control | Name | OWASP | Key NIST refs |")
    w("|---|---|---|---|")
    for c in CONTROL_CATALOG:
        refs = "; ".join(
            filter(
                None,
                [
                    c.nist_80053[0] if c.nist_80053 else "",
                    c.nist_ai_600_1[0] if c.nist_ai_600_1 else "",
                ],
            )
        )
        owasp = c.owasp[0] if c.owasp else ""
        w(f"| {c.control_id} | {c.name} | {owasp} | {refs} |")
    w("")
    return "\n".join(lines)


def main() -> None:
    OUT.write_text(render(), encoding="utf-8")
    print(f"wrote {OUT.relative_to(OUT.parents[1])}")


if __name__ == "__main__":
    main()

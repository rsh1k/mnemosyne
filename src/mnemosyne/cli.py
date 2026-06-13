"""Command-line interface.

Usage:
    mnem scan --surface instruction --provenance external_web "text..."
    mnem nist            # print the NIST/OWASP control mapping (JSON)
    mnem version
"""

from __future__ import annotations

import argparse
import json
import sys

from mnemosyne import __version__
from mnemosyne.core.gateway import MemoryGateway
from mnemosyne.core.models import MemorySurface, Provenance
from mnemosyne.nist import catalog_as_dicts


def _cmd_scan(args: argparse.Namespace) -> int:
    gw = MemoryGateway()
    outcome = gw.guard_write(
        content=args.content,
        surface=MemorySurface(args.surface),
        provenance=Provenance(args.provenance),
        namespace=args.namespace,
        writer_id=args.writer_id,
    )
    print(json.dumps(outcome.model_dump(mode="json"), indent=2))
    return 0 if outcome.allowed else 2


def _cmd_nist(_args: argparse.Namespace) -> int:
    print(json.dumps({"controls": catalog_as_dicts()}, indent=2))
    return 0


def _cmd_version(_args: argparse.Namespace) -> int:
    print(f"mnem {__version__}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mnemosyne",
        description="NIST-aligned memory-integrity firewall for agentic AI (OWASP ASI06).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="evaluate a candidate memory write")
    p_scan.add_argument("content")
    p_scan.add_argument(
        "--surface", default="knowledge", choices=[s.value for s in MemorySurface]
    )
    p_scan.add_argument(
        "--provenance", default="unknown", choices=[p.value for p in Provenance]
    )
    p_scan.add_argument("--namespace", default="default")
    p_scan.add_argument("--writer-id", dest="writer_id", default="cli")
    p_scan.set_defaults(func=_cmd_scan)

    p_nist = sub.add_parser("nist", help="print NIST/OWASP control mapping as JSON")
    p_nist.set_defaults(func=_cmd_nist)

    p_ver = sub.add_parser("version", help="print version")
    p_ver.set_defaults(func=_cmd_version)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

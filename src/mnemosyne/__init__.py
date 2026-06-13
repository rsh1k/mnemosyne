"""Mnemosyne -- a NIST-aligned Memory Integrity & Context-Provenance Firewall
for agentic AI.

Defense-in-depth against OWASP ASI06 (Memory & Context Poisoning).
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from mnemosyne.core import (
    Decision,
    GuardOutcome,
    MemoryGateway,
    MemoryPoisoningBlocked,
    MemoryRecord,
    MemorySurface,
    Provenance,
    Settings,
    Severity,
    TrustTier,
    get_settings,
)

try:
    __version__ = _pkg_version("mnemosyne-guard")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0+local"

__all__ = [
    "__version__",
    "MemoryGateway",
    "MemoryRecord",
    "MemorySurface",
    "Provenance",
    "TrustTier",
    "Decision",
    "Severity",
    "GuardOutcome",
    "Settings",
    "get_settings",
    "MemoryPoisoningBlocked",
]

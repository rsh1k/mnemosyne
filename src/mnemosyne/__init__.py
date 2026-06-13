"""Mnemosyne -- a NIST-aligned Memory Integrity & Context-Provenance Firewall
for agentic AI.

Defense-in-depth against OWASP ASI06 (Memory & Context Poisoning).
"""

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

__version__ = "0.1.0"

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

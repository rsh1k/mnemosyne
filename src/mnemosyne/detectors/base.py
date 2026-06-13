"""Detector base class.

Detectors are pluggable, stateless-by-default analysers that examine a piece of
content (plus light context) and emit :class:`Finding` objects. They never make
the final allow/deny decision -- that is the policy engine's job. This keeps
detection (observation) and policy (judgement) cleanly separated, which is what
lets an organisation tune posture without rewriting detection logic.

To add a custom detector (e.g. an ML prompt-injection classifier), subclass
:class:`Detector`, implement :meth:`scan`, and register it.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass

from mnemosyne.core.models import (
    Finding,
    MemorySurface,
    Provenance,
    ScanResult,
    TrustTier,
)


@dataclass(slots=True)
class DetectorContext:
    """Lightweight context handed to every detector."""

    surface: MemorySurface
    provenance: Provenance
    trust_tier: TrustTier
    namespace: str
    writer_id: str
    operation: str  # "write" or "read"


class Detector(abc.ABC):
    """Base class for content detectors."""

    #: Stable identifier used in findings and configuration.
    name: str = "detector"

    @abc.abstractmethod
    def scan(self, content: str, ctx: DetectorContext) -> ScanResult:
        """Analyse ``content`` and return findings."""

    @staticmethod
    def _result(*findings: Finding) -> ScanResult:
        return ScanResult(findings=[f for f in findings if f is not None])

"""Detector registry.

Holds the active set of detectors and runs them over content. The anomaly
detector is special-cased only insofar as the gateway feeds it baseline
observations; from the registry's perspective every detector is uniform.
"""

from __future__ import annotations

from mnemosyne.core.models import ScanResult
from mnemosyne.detectors.anomaly import AnomalyDetector
from mnemosyne.detectors.base import Detector, DetectorContext
from mnemosyne.detectors.injection import InjectionDetector
from mnemosyne.detectors.obfuscation import ObfuscationDetector
from mnemosyne.detectors.secrets_pii import SecretsPiiDetector

__all__ = [
    "Detector",
    "DetectorContext",
    "DetectorRegistry",
    "InjectionDetector",
    "ObfuscationDetector",
    "SecretsPiiDetector",
    "AnomalyDetector",
    "default_registry",
]


class DetectorRegistry:
    def __init__(self, detectors: list[Detector] | None = None) -> None:
        self._detectors: list[Detector] = detectors or []

    def register(self, detector: Detector) -> None:
        self._detectors.append(detector)

    def get(self, name: str) -> Detector | None:
        return next((d for d in self._detectors if d.name == name), None)

    @property
    def detectors(self) -> list[Detector]:
        return list(self._detectors)

    def scan_all(self, content: str, ctx: DetectorContext) -> ScanResult:
        result = ScanResult()
        for detector in self._detectors:
            result = result.merged(detector.scan(content, ctx))
        return result


def default_registry(
    *, max_size_bytes: int = 64_000
) -> DetectorRegistry:
    """Build the registry with the bundled detectors."""

    return DetectorRegistry(
        [
            InjectionDetector(),
            ObfuscationDetector(),
            SecretsPiiDetector(),
            AnomalyDetector(max_size_bytes=max_size_bytes),
        ]
    )

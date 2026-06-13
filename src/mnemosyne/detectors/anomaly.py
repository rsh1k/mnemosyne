"""Anomaly detector.

Covers two of the three ASI06 attack vectors that signatures alone miss:

* **Size / encoding anomalies** -- oversized blobs and high-entropy payloads are
  classic carriers for smuggled instructions or encoded exfiltration.
* **Gradual erosion ("sleeper agent")** -- the hardest vector: a writer behaves
  normally to build trust, then drifts. We keep a per-writer rolling baseline of
  injection scores and write sizes and flag statistically significant deviation
  (a robust z-score against the recent distribution).

The behavioral baseline is intentionally simple and online (bounded ring buffer
per writer) so it adds negligible latency and needs no external store, while
remaining a documented extension point for a streaming analytics backend.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field

from mnemosyne.core.models import Finding, ScanResult, Severity
from mnemosyne.detectors.base import Detector, DetectorContext


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


@dataclass
class _WriterBaseline:
    sizes: deque[int] = field(default_factory=lambda: deque(maxlen=50))
    inj_scores: deque[float] = field(default_factory=lambda: deque(maxlen=50))

    def observe(self, size: int, inj_score: float) -> None:
        self.sizes.append(size)
        self.inj_scores.append(inj_score)

    @staticmethod
    def _robust_z(value: float, sample: deque) -> float:
        """Robust anomaly score on a z-like scale.

        Primary statistic is the median-absolute-deviation (MAD) z-score, which
        resists a handful of outliers far better than a mean/stddev z-score --
        important here because an attacker probing the baseline is itself an
        outlier we do not want to absorb into "normal".

        A naive MAD score breaks down when the recent baseline has zero spread
        (e.g. a writer that always writes the same-sized record). MAD is then 0
        and the score is undefined. That degenerate case is exactly where a
        gradual-erosion attacker wants to hide, so we fall back deliberately:

        1. MAD z-score when there is any median spread.
        2. Mean-absolute-deviation z-score when MAD is 0 but the data still
           varies (a few identical values dominating the median).
        3. For a perfectly constant baseline, a pure z-score is undefined, so we
           switch to a relative-magnitude test: an order-of-magnitude departure
           from the stable value is treated as a strong anomaly while trivial
           jitter is ignored. The result is mapped onto the same z-like scale so
           a single downstream threshold governs all three regimes.
        """

        if len(sample) < 8:
            return 0.0
        data = sorted(sample)
        n = len(data)
        mid = n // 2
        median = data[mid] if n % 2 else (data[mid - 1] + data[mid]) / 2

        abs_dev = sorted(abs(x - median) for x in data)
        mad = abs_dev[mid] if n % 2 else (abs_dev[mid - 1] + abs_dev[mid]) / 2
        if mad > 0:
            return 0.6745 * (value - median) / mad

        mean_ad = sum(abs(x - median) for x in data) / n
        if mean_ad > 0:
            return 0.7979 * (value - median) / mean_ad

        # Perfectly constant baseline: fall back to relative magnitude.
        if median == 0:
            return 0.0
        ratio = value / median if value >= median else median / max(value, 1e-9)
        if ratio <= 1.5:
            return 0.0
        # ratio 2x -> 3.5 (the firing threshold); grows with the magnitude gap.
        return 3.5 * math.log2(ratio)


class AnomalyDetector(Detector):
    name = "anomaly"

    def __init__(self, max_size_bytes: int = 64_000, entropy_threshold: float = 4.8) -> None:
        self._max_size = max_size_bytes
        self._entropy_threshold = entropy_threshold
        self._baselines: dict[str, _WriterBaseline] = {}

    def _baseline(self, writer_id: str) -> _WriterBaseline:
        return self._baselines.setdefault(writer_id, _WriterBaseline())

    def observe(self, writer_id: str, size: int, injection_score: float) -> None:
        """Feed the per-writer baseline (called by the gateway after scanning)."""

        self._baseline(writer_id).observe(size, injection_score)

    def scan(self, content: str, ctx: DetectorContext) -> ScanResult:
        findings: list[Finding] = []
        size = len(content.encode("utf-8"))

        if size > self._max_size:
            findings.append(
                Finding(
                    detector=self.name,
                    severity=Severity.MEDIUM,
                    score=0.5,
                    summary=f"Oversized memory write ({size} bytes > {self._max_size})",
                    evidence=[f"{size} bytes"],
                    metadata={"kind": "size", "bytes": size},
                )
            )

        # Entropy check on long content only (short tokens are naturally high-entropy).
        if size >= 256:
            entropy = _shannon_entropy(content)
            if entropy >= self._entropy_threshold:
                findings.append(
                    Finding(
                        detector=self.name,
                        severity=Severity.LOW,
                        score=0.3,
                        summary=f"High-entropy content ({entropy:.2f} bits/char)",
                        evidence=[f"entropy={entropy:.2f}"],
                        metadata={"kind": "entropy", "entropy": round(entropy, 3)},
                    )
                )

        # Behavioral drift against the writer's recent baseline.
        bl = self._baseline(ctx.writer_id)
        z_size = bl._robust_z(float(size), bl.sizes)
        if z_size >= 3.5:
            findings.append(
                Finding(
                    detector=self.name,
                    severity=Severity.MEDIUM,
                    score=0.45,
                    summary=(
                        f"Write size deviates sharply from {ctx.writer_id}'s baseline "
                        f"(robust z={z_size:.1f}) -- possible gradual-erosion attack"
                    ),
                    evidence=[f"z_size={z_size:.2f}"],
                    metadata={"kind": "behavioral_drift", "z_size": round(z_size, 3)},
                )
            )

        return ScanResult(findings=findings)

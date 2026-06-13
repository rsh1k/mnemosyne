"""Telemetry: structured logging and lightweight in-process metrics.

Security controls are only as good as their observability. This module gives the
gateway structured (optionally JSON) logs and simple counters/latency histograms
that an enterprise can scrape (the API exposes them at ``/metrics``). It avoids a
hard dependency on Prometheus client libs so the core stays lightweight, while
the format is trivially adaptable to OpenTelemetry.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from collections import defaultdict
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any


def configure_logging(level: str = "INFO", json_format: bool = True) -> None:
    handler = logging.StreamHandler(sys.stdout)
    if json_format:
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        )
    root = logging.getLogger("mnemosyne")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())
    root.propagate = False


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if hasattr(record, "extra_fields"):
            payload.update(record.extra_fields)  # type: ignore[attr-defined]
        return json.dumps(payload)


def get_logger(name: str = "mnemosyne") -> logging.Logger:
    return logging.getLogger(name)


def log_event(logger: logging.Logger, level: int, msg: str, **fields: Any) -> None:
    logger.log(level, msg, extra={"extra_fields": fields})


class Metrics:
    """Thread-safe counters and latency accumulators."""

    def __init__(self) -> None:
        self._counters: dict[str, int] = defaultdict(int)
        self._latency_sum: dict[str, float] = defaultdict(float)
        self._latency_count: dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

    def inc(self, name: str, by: int = 1, **labels: str) -> None:
        key = self._key(name, labels)
        with self._lock:
            self._counters[key] += by

    def observe_latency(self, name: str, seconds: float, **labels: str) -> None:
        key = self._key(name, labels)
        with self._lock:
            self._latency_sum[key] += seconds
            self._latency_count[key] += 1

    @contextmanager
    def timer(self, name: str, **labels: str) -> Iterator[None]:
        start = time.perf_counter()
        try:
            yield
        finally:
            self.observe_latency(name, time.perf_counter() - start, **labels)

    @staticmethod
    def _key(name: str, labels: dict[str, str]) -> str:
        if not labels:
            return name
        label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"

    def render_prometheus(self) -> str:
        lines: list[str] = []
        with self._lock:
            for key, value in sorted(self._counters.items()):
                lines.append(f"mnemosyne_{key} {value}")
            for key, total in sorted(self._latency_sum.items()):
                count = self._latency_count[key]
                lines.append(f"mnemosyne_{key}_seconds_sum {total}")
                lines.append(f"mnemosyne_{key}_seconds_count {count}")
        return "\n".join(lines) + "\n"

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "counters": dict(self._counters),
                "latency_sum": dict(self._latency_sum),
                "latency_count": dict(self._latency_count),
            }

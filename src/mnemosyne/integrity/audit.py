"""Tamper-evident audit log (hash chain).

Every security-relevant decision is appended as an entry whose hash incorporates
the previous entry's hash, forming a chain. Truncating, reordering, or editing
any entry breaks verification downstream of the change. This provides the
non-repudiation / accountability property required by NIST SP 800-53 AU-9
(Protection of Audit Information) and AU-10 (Non-repudiation), and supports
ASI06 incident reconstruction ("when and how did poisoned content enter?").

The default sink is append-only JSONL on disk; ``AuditSink`` can be implemented
for a SIEM, Kafka, or a WORM bucket.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

GENESIS = "0" * 64


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_entry(prev_hash: str, payload: dict[str, Any]) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


class AuditSink(Protocol):
    def write(self, line: str) -> None: ...

    def read_all(self) -> list[str]: ...


class JsonlFileSink:
    """Append-only JSONL file sink."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.touch(exist_ok=True)

    def write(self, line: str) -> None:
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def read_all(self) -> list[str]:
        if not self._path.exists():
            return []
        return [ln for ln in self._path.read_text("utf-8").splitlines() if ln.strip()]


class InMemorySink:
    def __init__(self) -> None:
        self._lines: list[str] = []

    def write(self, line: str) -> None:
        self._lines.append(line)

    def read_all(self) -> list[str]:
        return list(self._lines)


class AuditLog:
    """Hash-chained, thread-safe audit log."""

    def __init__(self, sink: AuditSink | None = None) -> None:
        self._sink: AuditSink = sink or InMemorySink()
        self._lock = threading.Lock()
        existing = self._sink.read_all()
        if existing:
            self._last_hash = json.loads(existing[-1])["entry_hash"]
        else:
            self._last_hash = GENESIS

    def record(self, event: str, data: dict[str, Any]) -> str:
        """Append an event; returns the new chain head hash."""

        with self._lock:
            payload = {
                "ts": _utcnow_iso(),
                "event": event,
                "prev_hash": self._last_hash,
                "data": data,
            }
            entry_hash = _hash_entry(self._last_hash, payload)
            payload["entry_hash"] = entry_hash
            self._sink.write(json.dumps(payload, sort_keys=True, separators=(",", ":")))
            self._last_hash = entry_hash
            return entry_hash

    def verify_chain(self) -> tuple[bool, int | None]:
        """Verify the full chain.

        Returns ``(ok, broken_index)``. ``broken_index`` is the 0-based index of
        the first corrupted entry, or ``None`` when the chain is intact.
        """

        prev = GENESIS
        for idx, raw in enumerate(self._sink.read_all()):
            entry = json.loads(raw)
            stated = entry.pop("entry_hash", None)
            if entry.get("prev_hash") != prev:
                return False, idx
            recomputed = _hash_entry(prev, entry)
            if recomputed != stated:
                return False, idx
            prev = stated
        return True, None

"""Memory store backends.

The gateway is storage-agnostic: it depends only on the :class:`MemoryStore`
and :class:`QuarantineStore` protocols. Bundled backends are an in-memory store
(tests/dev) and a SQLite store (single-node persistence). For production scale,
implement these protocols over your vector DB / Redis / Postgres. Namespacing is
mandatory and is how per-tenant / per-session **memory segmentation** is achieved
(the ASI06 mitigation that stops poisoned context leaking across tenants).
"""

from __future__ import annotations

import abc
import threading

from mnemosyne.core.models import MemoryRecord


class MemoryStore(abc.ABC):
    @abc.abstractmethod
    def put(self, record: MemoryRecord) -> None: ...

    @abc.abstractmethod
    def get(self, namespace: str, record_id: str) -> MemoryRecord | None: ...

    @abc.abstractmethod
    def list(self, namespace: str) -> list[MemoryRecord]: ...

    @abc.abstractmethod
    def delete(self, namespace: str, record_id: str) -> bool: ...


class QuarantineStore(abc.ABC):
    @abc.abstractmethod
    def quarantine(self, record: MemoryRecord, reasons: list[str]) -> str: ...

    @abc.abstractmethod
    def get(self, quarantine_id: str) -> tuple[MemoryRecord, list[str]] | None: ...

    @abc.abstractmethod
    def list(self, namespace: str | None = None) -> list[tuple[str, MemoryRecord]]: ...

    @abc.abstractmethod
    def release(self, quarantine_id: str) -> MemoryRecord | None: ...

    @abc.abstractmethod
    def discard(self, quarantine_id: str) -> bool: ...


class InMemoryStore(MemoryStore):
    def __init__(self) -> None:
        self._data: dict[str, dict[str, MemoryRecord]] = {}
        self._lock = threading.RLock()

    def put(self, record: MemoryRecord) -> None:
        with self._lock:
            self._data.setdefault(record.namespace, {})[record.id] = record

    def get(self, namespace: str, record_id: str) -> MemoryRecord | None:
        with self._lock:
            return self._data.get(namespace, {}).get(record_id)

    def list(self, namespace: str) -> list[MemoryRecord]:
        with self._lock:
            return list(self._data.get(namespace, {}).values())

    def delete(self, namespace: str, record_id: str) -> bool:
        with self._lock:
            ns = self._data.get(namespace, {})
            return ns.pop(record_id, None) is not None


class InMemoryQuarantine(QuarantineStore):
    def __init__(self) -> None:
        self._data: dict[str, tuple[MemoryRecord, list[str]]] = {}
        self._lock = threading.RLock()

    def quarantine(self, record: MemoryRecord, reasons: list[str]) -> str:
        with self._lock:
            self._data[record.id] = (record, reasons)
            return record.id

    def get(self, quarantine_id: str) -> tuple[MemoryRecord, list[str]] | None:
        with self._lock:
            return self._data.get(quarantine_id)

    def list(self, namespace: str | None = None) -> list[tuple[str, MemoryRecord]]:
        with self._lock:
            return [
                (qid, rec)
                for qid, (rec, _r) in self._data.items()
                if namespace is None or rec.namespace == namespace
            ]

    def release(self, quarantine_id: str) -> MemoryRecord | None:
        with self._lock:
            entry = self._data.pop(quarantine_id, None)
            return entry[0] if entry else None

    def discard(self, quarantine_id: str) -> bool:
        with self._lock:
            return self._data.pop(quarantine_id, None) is not None

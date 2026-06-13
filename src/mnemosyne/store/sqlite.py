"""SQLite-backed persistent store.

Single-node durable backend used for the reference deployment and demos. It
serialises the full :class:`MemoryRecord` (including the integrity tag) so that
verification on read still detects out-of-band tampering of the row.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from mnemosyne.core.models import MemoryRecord
from mnemosyne.store.base import MemoryStore

_SCHEMA = """
CREATE TABLE IF NOT EXISTS memory_records (
    id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (namespace, id)
);
CREATE INDEX IF NOT EXISTS idx_records_ns ON memory_records(namespace);
"""


class SqliteStore(MemoryStore):
    def __init__(self, path: str | Path = "mnemosyne.db") -> None:
        self._path = str(path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def put(self, record: MemoryRecord) -> None:
        payload = record.model_dump_json()
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO memory_records (id, namespace, payload) "
                "VALUES (?, ?, ?)",
                (record.id, record.namespace, payload),
            )
            self._conn.commit()

    def get(self, namespace: str, record_id: str) -> MemoryRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT payload FROM memory_records WHERE namespace=? AND id=?",
                (namespace, record_id),
            ).fetchone()
        if not row:
            return None
        return MemoryRecord.model_validate(json.loads(row[0]))

    def list(self, namespace: str) -> list[MemoryRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT payload FROM memory_records WHERE namespace=?",
                (namespace,),
            ).fetchall()
        return [MemoryRecord.model_validate(json.loads(r[0])) for r in rows]

    def delete(self, namespace: str, record_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM memory_records WHERE namespace=? AND id=?",
                (namespace, record_id),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def close(self) -> None:
        with self._lock:
            self._conn.close()

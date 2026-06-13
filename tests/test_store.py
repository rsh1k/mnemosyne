"""Store backend tests.

Covers both bundled backends through the same behavioural contract: namespaced
put/get/list/delete, cross-namespace isolation (the segmentation control), the
quarantine lifecycle, and -- importantly -- that the integrity tag survives a
serialisation round-trip so tamper detection still works after persistence.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mnemosyne.core.models import MemoryRecord, MemorySurface, Provenance, TrustTier
from mnemosyne.integrity.signer import Signer, StaticKeyProvider
from mnemosyne.store.base import InMemoryQuarantine, InMemoryStore
from mnemosyne.store.sqlite import SqliteStore


def _record(ns: str = "default", content: str = "hello") -> MemoryRecord:
    return MemoryRecord(
        namespace=ns,
        surface=MemorySurface.KNOWLEDGE,
        content=content,
        provenance=Provenance.USER_DIRECT,
        trust_tier=TrustTier.TRUSTED,
        writer_id="tester",
    )


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path: Path):
    if request.param == "memory":
        yield InMemoryStore()
    else:
        s = SqliteStore(tmp_path / "test.db")
        yield s
        s.close()


class TestStoreContract:
    def test_put_get_roundtrip(self, store):
        rec = _record()
        store.put(rec)
        got = store.get(rec.namespace, rec.id)
        assert got is not None
        assert got.content == "hello"
        assert got.id == rec.id

    def test_get_missing_returns_none(self, store):
        assert store.get("nope", "missing") is None

    def test_list_scopes_to_namespace(self, store):
        store.put(_record(ns="a", content="one"))
        store.put(_record(ns="a", content="two"))
        store.put(_record(ns="b", content="three"))
        assert len(store.list("a")) == 2
        assert len(store.list("b")) == 1

    def test_namespace_isolation(self, store):
        rec = _record(ns="tenant-a")
        store.put(rec)
        # Correct id but wrong namespace must not leak across the boundary.
        assert store.get("tenant-b", rec.id) is None

    def test_delete(self, store):
        rec = _record()
        store.put(rec)
        assert store.delete(rec.namespace, rec.id) is True
        assert store.get(rec.namespace, rec.id) is None
        assert store.delete(rec.namespace, rec.id) is False


class TestIntegritySurvivesPersistence:
    def test_signed_record_verifies_after_roundtrip(self, store):
        signer = Signer(StaticKeyProvider("k" * 24))
        rec = _record(content="immutable fact")
        signer.sign(rec)
        store.put(rec)
        loaded = store.get(rec.namespace, rec.id)
        assert signer.verify(loaded) is True

    def test_tamper_after_roundtrip_is_detected(self, store):
        signer = Signer(StaticKeyProvider("k" * 24))
        rec = _record(content="immutable fact")
        signer.sign(rec)
        store.put(rec)
        loaded = store.get(rec.namespace, rec.id)
        loaded.content = "tampered fact"
        assert signer.verify(loaded) is False


class TestQuarantine:
    def test_quarantine_lifecycle(self):
        q = InMemoryQuarantine()
        rec = _record(ns="t1")
        qid = q.quarantine(rec, ["test reason"])
        assert q.get(qid) is not None
        listed = q.list("t1")
        assert len(listed) == 1
        released = q.release(qid)
        assert released is not None and released.id == rec.id
        # Released items are removed from quarantine.
        assert q.get(qid) is None

    def test_discard(self):
        q = InMemoryQuarantine()
        rec = _record()
        qid = q.quarantine(rec, ["r"])
        assert q.discard(qid) is True
        assert q.discard(qid) is False

    def test_list_filters_by_namespace(self):
        q = InMemoryQuarantine()
        q.quarantine(_record(ns="a"), ["r"])
        q.quarantine(_record(ns="b"), ["r"])
        assert len(q.list("a")) == 1
        assert len(q.list()) == 2

"""Shared test fixtures."""

from __future__ import annotations

import pytest

from mnemosyne.core.config import Settings
from mnemosyne.core.gateway import MemoryGateway
from mnemosyne.integrity.audit import AuditLog, InMemorySink
from mnemosyne.integrity.signer import Signer, StaticKeyProvider
from mnemosyne.store.base import InMemoryQuarantine, InMemoryStore


@pytest.fixture
def settings() -> Settings:
    return Settings(integrity_key="test-key-0123456789", api_keys="")


@pytest.fixture
def gateway(settings: Settings) -> MemoryGateway:
    return MemoryGateway(
        settings=settings,
        store=InMemoryStore(),
        quarantine=InMemoryQuarantine(),
        signer=Signer(StaticKeyProvider(settings.integrity_key)),
        audit=AuditLog(InMemorySink()),
    )

"""Record integrity via HMAC-SHA256.

Why this matters for ASI06: the Cisco "MemoryTrap" attack worked by writing
directly to the files an agent later trusts (memory, hooks, config), *bypassing*
any application-layer checks. Signing every record at write time and verifying
on read lets the gateway detect content that was mutated or inserted out of band
-- i.e. tampering at rest -- even if the attacker never goes through the API.

``KeyProvider`` is an extension point: the default reads the key from settings,
but enterprises can subclass it to fetch from AWS KMS, GCP KMS, HashiCorp Vault,
or a PKCS#11 HSM, and to support key rotation with key IDs.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Protocol

from mnemosyne.core.models import MemoryRecord


class KeyProvider(Protocol):
    """Supplies the active signing key. Implement for KMS/HSM/Vault backends."""

    def current_key(self) -> bytes: ...

    def key_for_verification(self, key_id: str | None) -> bytes: ...


class StaticKeyProvider:
    """Simple single-key provider sourced from configuration.

    Suitable for dev and single-key production. For rotation, supply a provider
    that maps ``key_id`` -> historical keys.
    """

    def __init__(self, key: str | bytes) -> None:
        self._key = key.encode("utf-8") if isinstance(key, str) else key

    def current_key(self) -> bytes:
        return self._key

    def key_for_verification(self, key_id: str | None) -> bytes:  # noqa: ARG002
        return self._key


class Signer:
    """Signs and verifies :class:`MemoryRecord` integrity tags."""

    def __init__(self, key_provider: KeyProvider) -> None:
        self._keys = key_provider

    def compute_tag(self, record: MemoryRecord) -> str:
        key = self._keys.current_key()
        mac = hmac.new(key, record.canonical_bytes(), hashlib.sha256)
        return mac.hexdigest()

    def sign(self, record: MemoryRecord) -> MemoryRecord:
        """Return the record with its ``integrity_tag`` populated."""

        record.integrity_tag = self.compute_tag(record)
        return record

    def verify(self, record: MemoryRecord) -> bool:
        """Constant-time verification of a record's integrity tag."""

        if not record.integrity_tag:
            return False
        key = self._keys.key_for_verification(record.metadata.get("key_id"))
        expected = hmac.new(key, record.canonical_bytes(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, record.integrity_tag)

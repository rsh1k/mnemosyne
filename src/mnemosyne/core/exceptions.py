"""Exception hierarchy for Mnemosyne."""

from __future__ import annotations


class MnemosyneError(Exception):
    """Base class for all Mnemosyne errors."""


class MemoryPoisoningBlocked(MnemosyneError):
    """Raised when a write is denied or quarantined by policy.

    Carries the structured outcome so callers can inspect findings.
    """

    def __init__(self, message: str, outcome: object | None = None) -> None:
        super().__init__(message)
        self.outcome = outcome


class IntegrityVerificationError(MnemosyneError):
    """Raised when a record fails HMAC integrity verification on read."""


class PolicyConfigurationError(MnemosyneError):
    """Raised when a policy document is malformed."""


class StoreError(MnemosyneError):
    """Raised for backend storage failures."""

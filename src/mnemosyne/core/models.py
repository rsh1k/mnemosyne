"""Core domain models for the Mnemosyne memory-integrity firewall.

These models encode the central security abstractions behind defense against
OWASP ASI06 (Memory & Context Poisoning):

* **Provenance** -- where a piece of content originated.
* **TrustTier** -- the derived trust level the system is willing to grant it.
* **MemorySurface** -- the kind of store it is being written to, ranked by how
  much the agent's future behaviour depends on it. ``INSTRUCTION`` surfaces are
  the agent's *control plane* (system prompt, CLAUDE.md, hooks, local config);
  these are exactly the surfaces the Cisco "MemoryTrap" exploit crossed into.

The cardinal invariant of the system -- enforced by :mod:`mnemosyne.policy` --
is that content whose trust tier is not ``TRUSTED`` must never reach an
``INSTRUCTION`` surface without explicit, audited human promotion.
"""

from __future__ import annotations

import enum
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return uuid.uuid4().hex


class Provenance(str, enum.Enum):
    """Origin of a piece of content.

    Ordering here reflects decreasing inherent trustworthiness and is used by
    the default policy to map provenance onto a :class:`TrustTier`.
    """

    USER_DIRECT = "user_direct"          # typed by an authenticated human principal
    AGENT_DERIVED = "agent_derived"      # produced by the agent's own reasoning
    TOOL_OUTPUT = "tool_output"          # returned by an internal/first-party tool
    RETRIEVED_DOC = "retrieved_doc"      # pulled from a managed knowledge base / RAG
    INTER_AGENT = "inter_agent"          # received from another agent (ASI07 surface)
    EXTERNAL_WEB = "external_web"         # fetched from the open internet
    UNTRUSTED_FILE = "untrusted_file"    # files from a cloned repo / uploaded artifact
    UNKNOWN = "unknown"                  # provenance could not be established


class TrustTier(str, enum.Enum):
    """Derived trust level. Lower tiers receive stricter handling."""

    TRUSTED = "trusted"        # may inform instruction surfaces
    LIMITED = "limited"        # usable as knowledge, never as instruction
    UNTRUSTED = "untrusted"    # quarantine-by-default, treat as hostile data

    @property
    def rank(self) -> int:
        return {"trusted": 2, "limited": 1, "untrusted": 0}[self.value]


class MemorySurface(str, enum.Enum):
    """The class of memory store content is being written to.

    ``INSTRUCTION`` is the high-trust control plane. ``KNOWLEDGE`` holds facts
    (RAG / archival). ``EPISODIC`` holds conversational history. ``SCRATCH`` is
    transient working memory.
    """

    INSTRUCTION = "instruction"
    KNOWLEDGE = "knowledge"
    EPISODIC = "episodic"
    SCRATCH = "scratch"

    @property
    def is_control_plane(self) -> bool:
        return self is MemorySurface.INSTRUCTION


class Severity(str, enum.Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Decision(str, enum.Enum):
    """The action the policy engine takes on a request."""

    ALLOW = "allow"            # store/return content unchanged
    SANITIZE = "sanitize"      # store/return a neutralised version
    QUARANTINE = "quarantine"  # divert to quarantine for human review
    DENY = "deny"              # reject outright


class Finding(BaseModel):
    """A single observation produced by a detector."""

    detector: str
    severity: Severity = Severity.NONE
    score: float = Field(0.0, ge=0.0, le=1.0)
    summary: str = ""
    evidence: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Aggregated output of all detectors for one piece of content."""

    findings: list[Finding] = Field(default_factory=list)

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.NONE
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    @property
    def max_score(self) -> float:
        return max((f.score for f in self.findings), default=0.0)

    def by_detector(self, name: str) -> list[Finding]:
        return [f for f in self.findings if f.detector == name]

    def merged(self, other: ScanResult) -> ScanResult:
        return ScanResult(findings=[*self.findings, *other.findings])


class MemoryRecord(BaseModel):
    """A persisted unit of agent memory plus its security metadata."""

    id: str = Field(default_factory=_new_id)
    namespace: str = "default"                  # tenant / session isolation key
    surface: MemorySurface = MemorySurface.KNOWLEDGE
    content: str = ""
    provenance: Provenance = Provenance.UNKNOWN
    trust_tier: TrustTier = TrustTier.UNTRUSTED
    writer_id: str = "unknown"                  # principal/agent that wrote it
    created_at: datetime = Field(default_factory=_utcnow)
    # Integrity: HMAC over the canonical serialization (see integrity.signer).
    integrity_tag: str | None = None
    sanitized: bool = False
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("namespace", "writer_id")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        return v or "default"

    def canonical_bytes(self) -> bytes:
        """Deterministic byte representation used for integrity signing.

        Only the security-relevant immutable fields are covered; ``integrity_tag``
        itself is excluded to avoid a self-reference.
        """

        parts = [
            self.id,
            self.namespace,
            self.surface.value,
            self.provenance.value,
            self.trust_tier.value,
            self.writer_id,
            self.created_at.isoformat(),
            self.content,
        ]
        joined = "\x1f".join(parts).encode("utf-8")
        return joined

    def content_sha256(self) -> str:
        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()


class GuardOutcome(BaseModel):
    """Result returned by the gateway for a write or read operation."""

    decision: Decision
    allowed: bool
    record: MemoryRecord | None = None
    scan: ScanResult = Field(default_factory=ScanResult)
    trust_tier: TrustTier = TrustTier.UNTRUSTED
    reasons: list[str] = Field(default_factory=list)
    quarantine_id: str | None = None
    integrity_verified: bool | None = None  # populated on reads

    @property
    def blocked(self) -> bool:
        return self.decision in (Decision.DENY, Decision.QUARANTINE)

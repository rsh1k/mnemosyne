"""The memory-integrity gateway.

This is the component every agent integration calls. It implements the two
guarded operations that constitute the ASI06 defense:

``guard_write``  -- everything an agent tries to persist passes through:
    1. resolve provenance -> trust tier (policy)
    2. run all detectors (injection / secrets-PII / anomaly)
    3. let the policy engine decide ALLOW / SANITIZE / QUARANTINE / DENY
    4. sign allowed records (HMAC) and persist with full metadata
    5. append a tamper-evident audit entry
    6. feed the behavioral baseline (sleeper-agent detection)

``guard_read``   -- everything an agent loads from memory passes through:
    1. verify the integrity tag (detects tampering at rest -- the MemoryTrap case)
    2. re-scan content (defense in depth; catches side-channel writes)
    3. apply read-time policy (never surface untrusted content as instruction)
    4. audit

Design notes:
* Fail-closed: an unexpected detector error denies the write when
  ``settings.fail_closed`` is set (NIST: fail-safe defaults).
* The gateway is dependency-injected and side-effect-isolated, so it is trivial
  to unit test and to embed in any framework (LangChain, Letta, custom).
"""

from __future__ import annotations

import logging
from typing import Any

from mnemosyne.core.config import Settings, get_settings
from mnemosyne.core.exceptions import MemoryPoisoningBlocked
from mnemosyne.core.models import (
    Decision,
    GuardOutcome,
    MemoryRecord,
    MemorySurface,
    Provenance,
    ScanResult,
    TrustTier,
)
from mnemosyne.detectors import (
    AnomalyDetector,
    DetectorContext,
    DetectorRegistry,
    default_registry,
)
from mnemosyne.detectors.obfuscation import ObfuscationDetector
from mnemosyne.detectors.secrets_pii import SecretsPiiDetector
from mnemosyne.integrity.audit import AuditLog
from mnemosyne.integrity.signer import Signer, StaticKeyProvider
from mnemosyne.policy.engine import PolicyEngine
from mnemosyne.store.base import (
    InMemoryQuarantine,
    InMemoryStore,
    MemoryStore,
    QuarantineStore,
)
from mnemosyne.telemetry import Metrics, get_logger, log_event


class MemoryGateway:
    def __init__(
        self,
        *,
        settings: Settings | None = None,
        store: MemoryStore | None = None,
        quarantine: QuarantineStore | None = None,
        policy: PolicyEngine | None = None,
        detectors: DetectorRegistry | None = None,
        signer: Signer | None = None,
        audit: AuditLog | None = None,
        metrics: Metrics | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.store = store or InMemoryStore()
        self.quarantine_store = quarantine or InMemoryQuarantine()
        self.policy = policy or PolicyEngine.from_path(self.settings.policy_path)
        self.detectors = detectors or default_registry(
            max_size_bytes=self.settings.anomaly_size_bytes
        )
        self.signer = signer or Signer(StaticKeyProvider(self.settings.integrity_key))
        self.audit = audit or AuditLog()
        self.metrics = metrics or Metrics()
        self._log = get_logger("mnemosyne.gateway")

    # ------------------------------------------------------------------ WRITE
    def guard_write(
        self,
        *,
        content: str,
        surface: MemorySurface | str = MemorySurface.KNOWLEDGE,
        provenance: Provenance | str = Provenance.UNKNOWN,
        namespace: str = "default",
        writer_id: str = "unknown",
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        raise_on_block: bool = False,
    ) -> GuardOutcome:
        surface = MemorySurface(surface)
        provenance = Provenance(provenance)
        with self.metrics.timer("guard_write_latency"):
            outcome = self._evaluate_write(
                content=content,
                surface=surface,
                provenance=provenance,
                namespace=namespace,
                writer_id=writer_id,
                tags=tags or [],
                metadata=metadata or {},
            )

        self.metrics.inc(
            "writes_total", decision=outcome.decision.value, surface=surface.value
        )
        if raise_on_block and outcome.blocked:
            raise MemoryPoisoningBlocked(
                f"write {outcome.decision.value}: {'; '.join(outcome.reasons)}",
                outcome=outcome,
            )
        return outcome

    def _evaluate_write(
        self,
        *,
        content: str,
        surface: MemorySurface,
        provenance: Provenance,
        namespace: str,
        writer_id: str,
        tags: list[str],
        metadata: dict[str, Any],
    ) -> GuardOutcome:
        trust_tier = self.policy.trust_tier(provenance)
        ctx = DetectorContext(
            surface=surface,
            provenance=provenance,
            trust_tier=trust_tier,
            namespace=namespace,
            writer_id=writer_id,
            operation="write",
        )

        try:
            scan = self.detectors.scan_all(content, ctx)
        except Exception as exc:  # fail-closed
            self._log.exception("detector failure")
            if self.settings.fail_closed:
                self.audit.record(
                    "write_denied_detector_error",
                    {"namespace": namespace, "writer_id": writer_id, "error": str(exc)},
                )
                return GuardOutcome(
                    decision=Decision.DENY,
                    allowed=False,
                    trust_tier=trust_tier,
                    reasons=[f"detector error (fail-closed): {exc}"],
                )
            scan = ScanResult()

        decision, reasons = self.policy.decide(
            surface=surface, trust_tier=trust_tier, scan=scan
        )

        # Feed behavioral baseline regardless of decision (learns normal + attack).
        injection_score = max(
            (f.score for f in scan.by_detector("injection")), default=0.0
        )
        anomaly = self.detectors.get("anomaly")
        if isinstance(anomaly, AnomalyDetector):
            anomaly.observe(writer_id, len(content.encode("utf-8")), injection_score)

        record = MemoryRecord(
            namespace=namespace,
            surface=surface,
            content=content,
            provenance=provenance,
            trust_tier=trust_tier,
            writer_id=writer_id,
            tags=tags,
            metadata=metadata,
        )

        outcome = self._apply_decision(record, decision, scan, reasons, trust_tier)
        self._audit_write(outcome, record)
        log_event(
            self._log,
            logging.INFO if outcome.allowed else logging.WARNING,
            "guard_write",
            decision=outcome.decision.value,
            surface=surface.value,
            provenance=provenance.value,
            trust_tier=trust_tier.value,
            namespace=namespace,
            writer_id=writer_id,
            max_severity=scan.max_severity.value,
        )
        return outcome

    def _apply_decision(
        self,
        record: MemoryRecord,
        decision: Decision,
        scan: ScanResult,
        reasons: list[str],
        trust_tier: TrustTier,
    ) -> GuardOutcome:
        if decision is Decision.DENY:
            return GuardOutcome(
                decision=decision,
                allowed=False,
                scan=scan,
                trust_tier=trust_tier,
                reasons=reasons,
            )

        if decision is Decision.QUARANTINE:
            qid = self.quarantine_store.quarantine(record, reasons)
            self.metrics.inc("quarantined_total")
            return GuardOutcome(
                decision=decision,
                allowed=False,
                scan=scan,
                trust_tier=trust_tier,
                reasons=reasons,
                quarantine_id=qid,
            )

        if decision is Decision.SANITIZE:
            cleaned = SecretsPiiDetector.redact(record.content)
            cleaned = ObfuscationDetector.strip(cleaned)
            record.content = cleaned
            record.sanitized = True
            reasons.append("content sanitized (redacted secrets/PII, stripped hidden chars)")

        self.signer.sign(record)
        self.store.put(record)
        self.metrics.inc("stored_total")
        return GuardOutcome(
            decision=decision,
            allowed=True,
            record=record,
            scan=scan,
            trust_tier=trust_tier,
            reasons=reasons,
        )

    def _audit_write(self, outcome: GuardOutcome, record: MemoryRecord) -> None:
        self.audit.record(
            "memory_write",
            {
                "record_id": record.id,
                "namespace": record.namespace,
                "surface": record.surface.value,
                "provenance": record.provenance.value,
                "trust_tier": outcome.trust_tier.value,
                "writer_id": record.writer_id,
                "decision": outcome.decision.value,
                "content_sha256": record.content_sha256(),
                "max_severity": outcome.scan.max_severity.value,
                "reasons": outcome.reasons,
            },
        )

    # ------------------------------------------------------------------- READ
    def guard_read(
        self,
        *,
        namespace: str,
        record_id: str,
        reader_id: str = "unknown",
        target_surface: MemorySurface | str = MemorySurface.KNOWLEDGE,
    ) -> GuardOutcome:
        target_surface = MemorySurface(target_surface)
        with self.metrics.timer("guard_read_latency"):
            outcome = self._evaluate_read(
                namespace=namespace,
                record_id=record_id,
                reader_id=reader_id,
                target_surface=target_surface,
            )
        self.metrics.inc("reads_total", decision=outcome.decision.value)
        return outcome

    def _evaluate_read(
        self,
        *,
        namespace: str,
        record_id: str,
        reader_id: str,
        target_surface: MemorySurface,
    ) -> GuardOutcome:
        record = self.store.get(namespace, record_id)
        if record is None:
            return GuardOutcome(
                decision=Decision.DENY,
                allowed=False,
                reasons=["record not found"],
            )

        # 1. Integrity verification (detects tampering at rest).
        integrity_ok = self.signer.verify(record)
        if not integrity_ok:
            self.metrics.inc("integrity_failures_total")
            self.audit.record(
                "integrity_failure",
                {"record_id": record.id, "namespace": namespace, "reader_id": reader_id},
            )
            if self.settings.require_integrity_on_read:
                return GuardOutcome(
                    decision=Decision.DENY,
                    allowed=False,
                    record=None,
                    trust_tier=record.trust_tier,
                    reasons=["integrity verification failed (possible tampering)"],
                    integrity_verified=False,
                )

        # 2. Re-scan (defense in depth) using the record's own provenance, but
        #    decide against the *target* surface the content is being loaded into.
        ctx = DetectorContext(
            surface=target_surface,
            provenance=record.provenance,
            trust_tier=record.trust_tier,
            namespace=namespace,
            writer_id=record.writer_id,
            operation="read",
        )
        scan = self.detectors.scan_all(record.content, ctx)
        decision, reasons = self.policy.decide(
            surface=target_surface, trust_tier=record.trust_tier, scan=scan
        )

        allowed = decision in (Decision.ALLOW, Decision.SANITIZE)
        served = record
        if decision is Decision.SANITIZE:
            served = record.model_copy(deep=True)
            served.content = ObfuscationDetector.strip(
                SecretsPiiDetector.redact(served.content)
            )
            served.sanitized = True

        self.audit.record(
            "memory_read",
            {
                "record_id": record.id,
                "namespace": namespace,
                "reader_id": reader_id,
                "target_surface": target_surface.value,
                "decision": decision.value,
                "integrity_verified": integrity_ok,
                "reasons": reasons,
            },
        )
        return GuardOutcome(
            decision=decision,
            allowed=allowed,
            record=served if allowed else None,
            scan=scan,
            trust_tier=record.trust_tier,
            reasons=reasons,
            integrity_verified=integrity_ok,
        )

    # -------------------------------------------------------------- QUARANTINE
    def promote_quarantined(
        self, quarantine_id: str, *, approver_id: str
    ) -> GuardOutcome:
        """Human-in-the-loop promotion of quarantined content.

        Promotion re-signs and stores the record and is fully audited, satisfying
        the accountability requirement for any trust elevation.
        """

        record = self.quarantine_store.release(quarantine_id)
        if record is None:
            return GuardOutcome(
                decision=Decision.DENY, allowed=False, reasons=["quarantine id not found"]
            )

        # A human is explicitly vouching for this content. Elevate its trust to
        # exactly what its target surface requires -- never silently above it, so
        # promotion can never by itself grant control-plane (INSTRUCTION) trust
        # unless the surface genuinely is the control plane. The original tier and
        # approver are preserved in metadata for the audit trail.
        required = self.policy.required_tier(record.surface)
        original_tier = record.trust_tier
        if record.trust_tier.rank < required.rank:
            record.trust_tier = required
        record.metadata = {
            **record.metadata,
            "promoted_from_tier": original_tier.value,
            "promoted_to_tier": record.trust_tier.value,
            "promoted_by": approver_id,
        }

        self.signer.sign(record)
        self.store.put(record)
        self.audit.record(
            "quarantine_promoted",
            {
                "record_id": record.id,
                "namespace": record.namespace,
                "approver_id": approver_id,
                "promoted_from_tier": original_tier.value,
                "promoted_to_tier": record.trust_tier.value,
            },
        )
        self.metrics.inc("promoted_total")
        return GuardOutcome(
            decision=Decision.ALLOW,
            allowed=True,
            record=record,
            trust_tier=record.trust_tier,
            reasons=[f"promoted from quarantine by {approver_id}"],
        )

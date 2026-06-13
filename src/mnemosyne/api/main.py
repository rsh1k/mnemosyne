"""FastAPI gateway service.

Exposes the gateway as a language-agnostic sidecar so non-Python agents can call
it over HTTP. Authentication is bearer-token (API keys from settings); in
production place this behind your mesh/mTLS and an identity-aware proxy.

Endpoints:
    POST /v1/memory/write            guard + persist a write
    POST /v1/memory/read             guard + return a read
    GET  /v1/quarantine              list quarantined items
    POST /v1/quarantine/{id}/promote human approval
    GET  /v1/audit/verify            verify the audit hash chain
    GET  /v1/compliance              NIST/OWASP control mapping
    GET  /metrics                    Prometheus exposition
    GET  /healthz                    liveness
"""

from __future__ import annotations

from typing import Any

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Response
    from pydantic import BaseModel
except ModuleNotFoundError as exc:  # pragma: no cover
    raise ModuleNotFoundError(
        "API extras not installed. Install with: pip install 'mnemosyne[api]'"
    ) from exc

from mnemosyne.core.config import get_settings
from mnemosyne.core.gateway import MemoryGateway
from mnemosyne.core.models import MemorySurface, Provenance
from mnemosyne.nist import catalog_as_dicts
from mnemosyne.telemetry import configure_logging


class WriteRequest(BaseModel):
    content: str
    surface: MemorySurface = MemorySurface.KNOWLEDGE
    provenance: Provenance = Provenance.UNKNOWN
    namespace: str = "default"
    writer_id: str = "unknown"
    tags: list[str] = []
    metadata: dict[str, Any] = {}


class ReadRequest(BaseModel):
    namespace: str
    record_id: str
    reader_id: str = "unknown"
    target_surface: MemorySurface = MemorySurface.KNOWLEDGE


def create_app(gateway: MemoryGateway | None = None) -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)
    gw = gateway or MemoryGateway(settings=settings)
    app = FastAPI(title="Mnemosyne Memory Gateway", version="0.1.0")

    def require_auth(authorization: str | None = Header(default=None)) -> None:
        keys = settings.api_key_set()
        if not keys:
            return  # auth disabled (dev) -- documented as insecure
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        token = authorization.split(" ", 1)[1].strip()
        if token not in keys:
            raise HTTPException(status_code=403, detail="invalid token")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/metrics")
    def metrics() -> Response:
        return Response(gw.metrics.render_prometheus(), media_type="text/plain")

    @app.get("/v1/compliance", dependencies=[Depends(require_auth)])
    def compliance() -> dict[str, Any]:
        return {"framework_version": 1, "controls": catalog_as_dicts()}

    @app.get("/v1/audit/verify", dependencies=[Depends(require_auth)])
    def audit_verify() -> dict[str, Any]:
        ok, broken = gw.audit.verify_chain()
        return {"intact": ok, "broken_index": broken}

    @app.post("/v1/memory/write", dependencies=[Depends(require_auth)])
    def write(req: WriteRequest) -> dict[str, Any]:
        outcome = gw.guard_write(
            content=req.content,
            surface=req.surface,
            provenance=req.provenance,
            namespace=req.namespace,
            writer_id=req.writer_id,
            tags=req.tags,
            metadata=req.metadata,
        )
        return outcome.model_dump(mode="json")

    @app.post("/v1/memory/read", dependencies=[Depends(require_auth)])
    def read(req: ReadRequest) -> dict[str, Any]:
        outcome = gw.guard_read(
            namespace=req.namespace,
            record_id=req.record_id,
            reader_id=req.reader_id,
            target_surface=req.target_surface,
        )
        return outcome.model_dump(mode="json")

    @app.get("/v1/quarantine", dependencies=[Depends(require_auth)])
    def list_quarantine(namespace: str | None = None) -> dict[str, Any]:
        items = gw.quarantine_store.list(namespace)
        return {
            "items": [
                {"quarantine_id": qid, "record": rec.model_dump(mode="json")}
                for qid, rec in items
            ]
        }

    @app.post("/v1/quarantine/{quarantine_id}/promote", dependencies=[Depends(require_auth)])
    def promote(quarantine_id: str, approver_id: str = "unknown") -> dict[str, Any]:
        outcome = gw.promote_quarantined(quarantine_id, approver_id=approver_id)
        if not outcome.allowed:
            raise HTTPException(status_code=404, detail="; ".join(outcome.reasons))
        return outcome.model_dump(mode="json")

    return app


app = None  # lazily created by uvicorn factory below


def factory() -> FastAPI:
    """Uvicorn entrypoint: ``uvicorn mnemosyne.api.main:factory --factory``."""

    return create_app()

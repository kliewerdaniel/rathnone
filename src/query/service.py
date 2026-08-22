"""Thin HTTP surface for the knowledge-query engine.

This is a SEPARATE FastAPI app from the frozen finance/authorization gateway
(``src.service.app``). The knowledge engine is an additive, dependency-free
substrate; it must not import or mutate the gateway's authz path. An agent
system talks to this service to turn a natural-language request (or a pre-built
``Op`` dict) into a deterministic, attestable ``EvidenceRecord`` without knowing
anything about ``src/query`` internals.

Endpoints
---------
``POST /graphs/load``        load a KnowledgeGraph from an SKC artifact on disk
``POST /query/op``           run a query supplied as an ``Op`` dict
``POST /query/nl``           run a query supplied as natural-language text
``GET  /authority/public-key``  evidence-domain public key (verify off-line)
``POST /query/op/attested``  like /query/op, plus an Ed25519 attestation
``POST /query/nl/attested``  like /query/nl, plus an Ed25519 attestation
``GET  /health``             liveness probe

The "model constructs, engine executes" contract is enforced structurally: the
service only accepts a query *specification* and returns verified evidence. It
never performs retrieval on the caller's behalf beyond executing the submitted
plan deterministically.

State (graph registry + evidence authority) is **per app instance**, created
inside ``create_app()``. Two ``create_app()`` instances in one process are fully
isolated -- important for multi-tenant deployment and for not leaking fixtures
between tests.

A control-plane key gate (``X-Control-Plane-Key``) is wired in only if
``RATHNONE_QUERY_API_KEY`` is set; left open otherwise so local-first single
operator use is frictionless -- mirroring the gateway's `RATHNONE_ENFORCE_AUTH`
posture without touching the frozen authz code.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException, Request, Depends
from pydantic import BaseModel, Field

from .algebra import Op
from .attest import (
    Attestation,
    EvidenceAuthority,
    generate_keypair,
    verify_attestation,
)
from .compiler import compile_query
from .executor import EvidenceRecord, KnowledgeGraph, QueryExecutor
from .loader import graph_from_skc_artifact


# Environment-gated config.
_CONTROL_KEY = os.environ.get("RATHNONE_QUERY_API_KEY")
_EVIDENCE_PEM = os.environ.get("RATHNONE_EVIDENCE_KEY_PEM")


def _bootstrap_authority() -> EvidenceAuthority:
    """Evidence-domain signing authority (ADR 30). SEPARATE from the frozen
    finance gateway's operator keyring. Bootstrapped from
    ``RATHNONE_EVIDENCE_KEY_PEM`` (file path or inline PEM) if set, otherwise an
    ephemeral key for local use."""
    if _EVIDENCE_PEM:
        pem_text = _EVIDENCE_PEM
        if pem_text.strip().startswith("-----BEGIN"):
            pem_bytes = pem_text.encode("utf-8")
        else:
            with open(pem_text, "rb") as fh:
                pem_bytes = fh.read()
        return EvidenceAuthority.from_pem("evidence-authority", pem_bytes)
    sk_pem, _ = generate_keypair()
    return EvidenceAuthority.from_pem("evidence-authority", sk_pem)


def _require_key(request: Request, control_key: str | None) -> None:
    if not control_key:
        return  # auth not enforced
    provided = request.headers.get("X-Control-Plane-Key")
    if provided != control_key:
        raise HTTPException(status_code=401,
                            detail="invalid or missing control-plane key")


# --- request/response models -------------------------------------------


class LoadRequest(BaseModel):
    artifact_path: str
    graph_name: str = "default"


class OpQueryRequest(BaseModel):
    graph_name: str = "default"
    op: dict = Field(..., description="An Op.to_dict() query plan")
    expect_hash: str | None = None
    expect_included: list[str] | None = None
    expect_excluded: list[str] | None = None


class NLQueryRequest(BaseModel):
    graph_name: str = "default"
    text: str
    expect_hash: str | None = None
    expect_included: list[str] | None = None
    expect_excluded: list[str] | None = None


# --- app factory --------------------------------------------------------


def create_app() -> FastAPI:
    app = FastAPI(title="Rathnone Knowledge-Query Engine", version="1.0")

    # Per-instance state (isolated across create_app() calls).
    graphs: dict[str, KnowledgeGraph] = {}
    authority = _bootstrap_authority()
    control_key = _CONTROL_KEY

    def require_key(request: Request) -> None:
        _require_key(request, control_key)

    @app.get("/health")
    def health():
        return {"status": "ok", "graphs": list(graphs.keys())}

    @app.post("/graphs/load")
    def load_graph(req: LoadRequest, _: None = Depends(require_key)):
        try:
            g = graph_from_skc_artifact(req.artifact_path)
        except FileNotFoundError:
            raise HTTPException(status_code=404,
                                detail=f"artifact not found: {req.artifact_path}")
        except Exception as exc:  # noqa: BLE001 -- surface loader errors plainly
            raise HTTPException(status_code=400,
                                detail=f"failed to load artifact: {exc}")
        graphs[req.graph_name] = g
        return {
            "graph_name": req.graph_name,
            "entities": g.entity_count(),
            "edges": g.edge_count(),
        }

    def _run(graph_name: str, op: Op,
             expect_hash, expect_included, expect_excluded) -> dict:
        g = graphs.get(graph_name)
        if g is None:
            raise HTTPException(status_code=404,
                                detail=f"graph not loaded: {graph_name}")
        rec: EvidenceRecord = QueryExecutor(g).execute(op)
        out = rec.as_dict()
        if any(v is not None for v in (expect_hash, expect_included,
                                       expect_excluded)):
            vr = rec.verify(
                expect_hash=expect_hash,
                expect_included=set(expect_included) if expect_included else None,
                expect_excluded=set(expect_excluded) if expect_excluded else None,
            )
            out["verify"] = {"ok": vr.ok, "divergences": vr.divergences}
        return out

    @app.post("/query/op")
    def query_op(req: OpQueryRequest, _: None = Depends(require_key)):
        try:
            op = Op.from_dict(req.op)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400,
                                detail=f"invalid Op specification: {exc}")
        return _run(req.graph_name, op, req.expect_hash,
                    req.expect_included, req.expect_excluded)

    @app.post("/query/nl")
    def query_nl(req: NLQueryRequest, _: None = Depends(require_key)):
        try:
            op = compile_query(req.text)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400,
                                detail=f"could not compile query: {exc}")
        # Echo the compiled plan so the caller can audit what the engine
        # executed (the model constructs, the engine executes).
        out = _run(req.graph_name, op, req.expect_hash,
                   req.expect_included, req.expect_excluded)
        out["compiled_op"] = op.to_dict()
        return out

    # --- attestation (ADR 30) -------------------------------------------

    @app.get("/authority/public-key")
    def authority_public_key():
        """Return the evidence-domain public key so callers can verify
        attestations off-line (independent of the frozen gateway keyring)."""
        return {"signer_id": authority.signer_id,
                "algorithm": "ed25519",
                "public_key_pem": authority.public_pem().decode("utf-8")}

    def _run_attested(graph_name: str, op: Op,
                      expect_hash, expect_included, expect_excluded) -> dict:
        out = _run(graph_name, op, expect_hash,
                   expect_included, expect_excluded)
        rec = EvidenceRecord.from_dict(out)
        att = authority.sign(rec)
        out["attestation"] = att.as_dict()
        return out

    @app.post("/query/op/attested")
    def query_op_attested(req: OpQueryRequest, _: None = Depends(require_key)):
        try:
            op = Op.from_dict(req.op)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400,
                                detail=f"invalid Op specification: {exc}")
        return _run_attested(req.graph_name, op, req.expect_hash,
                             req.expect_included, req.expect_excluded)

    @app.post("/query/nl/attested")
    def query_nl_attested(req: NLQueryRequest, _: None = Depends(require_key)):
        try:
            op = compile_query(req.text)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400,
                                detail=f"could not compile query: {exc}")
        out = _run_attested(req.graph_name, op, req.expect_hash,
                            req.expect_included, req.expect_excluded)
        out["compiled_op"] = op.to_dict()
        return out

    return app


# Import-time app instance (uvicorn rathnone.query.service:app).
app = create_app()


__all__ = ["create_app", "app"]

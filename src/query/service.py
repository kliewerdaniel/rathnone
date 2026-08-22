"""Thin HTTP surface for the knowledge-query engine.

This is a SEPARATE FastAPI app from the frozen finance/authorization gateway
(``src.service.app``). The knowledge engine is an additive, dependency-free
substrate; it must not import or mutate the gateway's authz path. An agent
system talks to this service to turn a natural-language request (or a pre-built
``Op`` dict) into a deterministic ``EvidenceRecord`` without knowing anything
about ``src/query`` internals.

Endpoints
---------
``POST /graphs/load``     load a KnowledgeGraph from an SKC artifact on disk
``POST /query/op``        run a query supplied as an ``Op`` dict
``POST /query/nl``        run a query supplied as natural-language text
``GET  /health``          liveness probe

The "model constructs, engine executes" contract is enforced structurally: the
service only accepts a query *specification* and returns verified evidence. It
never performs retrieval on the caller's behalf beyond executing the submitted
plan deterministically.

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
from .compiler import compile_query
from .executor import EvidenceRecord, KnowledgeGraph, QueryExecutor
from .loader import graph_from_skc_artifact


# Module-level mutable graph registry (single operator, local-first). The
# service is process-scoped; callers load a graph then query it by name.
_GRAPHS: dict[str, KnowledgeGraph] = {}

_CONTROL_KEY = os.environ.get("RATHNONE_QUERY_API_KEY")


def _require_key(request: Request) -> None:
    if not _CONTROL_KEY:
        return  # auth not enforced
    provided = request.headers.get("X-Control-Plane-Key")
    if provided != _CONTROL_KEY:
        raise HTTPException(status_code=401, detail="invalid or missing control-plane key")


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

    @app.get("/health")
    def health():
        return {"status": "ok", "graphs": list(_GRAPHS.keys())}

    @app.post("/graphs/load")
    def load_graph(req: LoadRequest, _: None = Depends(_require_key)):
        try:
            g = graph_from_skc_artifact(req.artifact_path)
        except FileNotFoundError:
            raise HTTPException(status_code=404,
                                detail=f"artifact not found: {req.artifact_path}")
        except Exception as exc:  # noqa: BLE001 -- surface loader errors plainly
            raise HTTPException(status_code=400,
                                detail=f"failed to load artifact: {exc}")
        _GRAPHS[req.graph_name] = g
        return {
            "graph_name": req.graph_name,
            "entities": g.entity_count(),
            "edges": g.edge_count(),
        }

    def _run(graph_name: str, op: Op,
             expect_hash, expect_included, expect_excluded) -> dict:
        g = _GRAPHS.get(graph_name)
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
    def query_op(req: OpQueryRequest, _: None = Depends(_require_key)):
        try:
            op = Op.from_dict(req.op)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400,
                                detail=f"invalid Op specification: {exc}")
        return _run(req.graph_name, op, req.expect_hash,
                    req.expect_included, req.expect_excluded)

    @app.post("/query/nl")
    def query_nl(req: NLQueryRequest, _: None = Depends(_require_key)):
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

    return app


# Import-time app instance (uvicorn rathnone.query.service:app).
app = create_app()


__all__ = ["create_app", "app"]

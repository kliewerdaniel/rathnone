"""ADR 48 — thin HTTP surface for the news evidence surface.

Mirrors ``src.query.service``: a SEPARATE FastAPI app that does not touch the
frozen finance gateway or the knowledge-query service. It accepts operator-fed
news snapshots (or triggers an opt-in live pull) and returns the objective
per-story verdict. Engine + corroboration + witness/attestation are inherited
from ``src.query`` via ``NewsAgent``.

Endpoints
---------
``POST /news/verdict``   submit pre-parsed articles (dict), get the NewsVerdict
``POST /news/pull``      opt-in live pull of operator-configured feeds -> verdict
``GET  /health``         liveness probe

State is per-instance (like the query service), created inside ``create_app()``
so env (RATHNONE_NEWS_ENABLED) is read at call time and instances are isolated.

A control-plane key gate is wired in only if ``RATHNONE_NEWS_API_KEY`` is set;
left open otherwise (local-first single-operator use, mirroring the query
service posture).
"""

from __future__ import annotations

import os
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Depends
from pydantic import BaseModel, Field

from .agent import NewsAgent, NewsSnapshot
from .ingest import NewsArticle, parse_auto


_CONTROL_KEY = None


def _require_key(request: Request, control_key: str | None) -> None:
    if not control_key:
        return
    provided = request.headers.get("X-Control-Plane-Key")
    if provided != control_key:
        raise HTTPException(status_code=401,
                            detail="invalid or missing control-plane key")


class ArticleModel(BaseModel):
    id: str
    title: str
    url: str
    text: str = ""
    source: str = ""
    published: str = ""
    entities: list[str] = Field(default_factory=list)
    claims: list[str] = Field(default_factory=list)


class VerdictRequest(BaseModel):
    articles: list[ArticleModel]
    pulled_at: str = ""


class PullRequest(BaseModel):
    feeds: list[str]


def create_app() -> FastAPI:
    app = FastAPI(title="Rathnone News Evidence Surface", version="1.0")

    global _CONTROL_KEY
    _CONTROL_KEY = os.environ.get("RATHNONE_NEWS_API_KEY")
    enabled = os.environ.get("RATHNONE_NEWS_ENABLED") == "1"
    quorum = int(os.environ.get("RATHNONE_NEWS_QUORUM", "2"))

    # Headless NewsAgent: no live httpx client => verdict computed purely from
    # structural story grouping (reproducible, no attestation round-trip needed).
    agent = NewsAgent(client=None, token=None, quorum=quorum, enabled=enabled)

    def require_key(request: Request) -> None:
        _require_key(request, _CONTROL_KEY)

    @app.get("/health")
    def health():
        return {"status": "ok", "news_enabled": enabled, "quorum": quorum}

    @app.post("/news/verdict")
    def news_verdict(req: VerdictRequest, _: None = Depends(require_key)):
        if not enabled:
            raise HTTPException(
                status_code=503,
                detail="news surface disabled (RATHNONE_NEWS_ENABLED=1)")
        articles = [
            NewsArticle(
                id=a.id, title=a.title, url=a.url, text=a.text,
                source=a.source, published=a.published, entities=a.entities)
            for a in req.articles
        ]
        snap = NewsSnapshot(articles=articles, pulled_at=req.pulled_at or "")
        verdict = agent.verdict(snap)
        return {
            "verdict": verdict.as_dict(),
            "digest": agent.digest(verdict),
        }

    @app.post("/news/pull")
    def news_pull(req: PullRequest, _: None = Depends(require_key)):
        if not enabled:
            raise HTTPException(
                status_code=503,
                detail="news surface disabled (RATHNONE_NEWS_ENABLED=1)")
        try:
            snap = agent.pull(req.feeds)
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        verdict = agent.verdict(snap)
        return {
            "verdict": verdict.as_dict(),
            "digest": agent.digest(verdict),
        }

    return app


# Import-time app instance (uvicorn rathnone.news.service:app).
app = create_app()


__all__ = ["create_app", "app"]

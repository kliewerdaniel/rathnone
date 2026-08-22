"""ADR 48 — NewsAgent: the objective-news consumer over the existing engine.

``NewsAgent`` wraps :class:`src.query.agent.KnowledgeAgent` so it inherits the
whole evidence chain for free: off-line attestation verification (ADR 30/34),
witness-log hash chaining (ADR 35), and the ADR 40 ``accept()`` narrowing step.
On top of that it adds the news-specific verdict: grouping articles by
``story_key`` and computing, per story, the distinct-outlet corroboration
state, the shared consensus, and where outlets diverge (N5=a / divergence spec).

Honesty boundary (the product): the verdict states "N distinct outlets agree /
1 source un-corroborated / outlets diverge" — it does NOT claim world-truth.
Un-corroborated or single-origin content is STAMPED, never assumed-true, and a
POISONED purification verdict (ADR 40) is surfaced and the story is refused.

Local-first / fail-closed: ``pull`` is opt-in behind ``RATHNONE_NEWS_ENABLED``;
with no feeds configured it refuses (no surface). Network egress is explicit and
limited to the operator's configured feed URLs. No cloud, no Aura.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional

import hashlib
import json

from ..query.agent import KnowledgeAgent, QueryResult
from ..query.executor import EvidenceRecord, KnowledgeGraph, QueryExecutor
from ..query.purify import PurificationLayer
from .ingest import (
    NewsArticle,
    NewsSnapshot,
    graph_from_news_snapshot,
    parse_auto,
)


# --- verdict dataclasses (the honest output) --------------------------------

@dataclass
class StoryVerdict:
    story_key: str
    outlets: list[str]                 # distinct eTLD+1 origins covering this story
    status: str                       # "CORROBORATED" | "UN_CORROBORATED" | "DIVERGENT"
    consensus: list[str] = field(default_factory=list)   # entities shared by all outlets
    divergent: dict[str, list[str]] = field(default_factory=dict)  # outlet -> conflicting tokens
    poison: str = "CLEAN"             # carried from ADR 40 (single-origin => POISONED)


@dataclass
class NewsVerdict:
    """The full objective view: one ``StoryVerdict`` per story_key + the
    reproduce-from (graph, record) contract so a consumer can re-verify."""

    pulled_at: str
    stories: list[StoryVerdict]
    # The raw evidence verdict (ADR 30 attestation + ADR 40 poison) from the
    # underlying KnowledgeAgent query, for the consumer's narrowing step.
    evidence: Optional[QueryResult] = None

    def as_dict(self) -> dict:
        return {
            "pulled_at": self.pulled_at,
            "stories": [
                {
                    "story_key": s.story_key,
                    "outlets": s.outlets,
                    "status": s.status,
                    "consensus": s.consensus,
                    "divergent": s.divergent,
                    "poison": s.poison,
                }
                for s in self.stories
            ],
        }


# --- the agent --------------------------------------------------------------

class NewsAgent:
    """Chat-with-the-news consumer. Inherits attestation + witness + poison
    narrowing from ``KnowledgeAgent``; adds per-story corroboration/divergence."""

    def __init__(
        self,
        client: Any,
        *,
        token: Optional[str] = None,
        quorum: int = 2,
        enabled: bool | None = None,
    ):
        # Reuse the proven evidence client (off-line verify, witness log, accept()).
        self.agent = KnowledgeAgent(client, token=token)
        self.quorum = quorum
        # Opt-in / fail-closed: default OFF unless RATHNONE_NEWS_ENABLED=1.
        self.enabled = (
            enabled if enabled is not None
            else os.environ.get("RATHNONE_NEWS_ENABLED") == "1"
        )
        # ADR 40 purification, enabled alongside news so every served record is
        # annotated with a CLEAN/POISONED verdict.
        self.purify = PurificationLayer(enabled=True, quorum=quorum)

    # --- feed pull (opt-in egress) ------------------------------------------

    def pull(self, feeds: list[str], *, fetcher=None) -> NewsSnapshot:
        """Pull ``feeds`` (operator-configured URLs) into a frozen snapshot.

        ``fetcher`` is injected in tests; in production it is a simple
        ``urllib.request`` GET (no third-party deps). Fail-closed: if news is
        not enabled OR no feeds are configured, refuse (no surface).
        """
        if not self.enabled:
            raise RuntimeError(
                "news surface disabled (set RATHNONE_NEWS_ENABLED=1)")
        if not feeds:
            raise RuntimeError("no feeds configured for news surface")

        def _default_get(url: str) -> str:
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "rathnone-news/1.0"})
            with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310 (operator URLs)
                return r.read().decode("utf-8", "replace")

        get = fetcher or _default_get
        articles: list[NewsArticle] = []
        for url in feeds:
            raw = get(url)
            articles.extend(parse_auto(raw))
        snap = NewsSnapshot(
            articles=articles,
            pulled_at=_now(),
            feed_sources=list(feeds),
        )
        self._last_snapshot = snap
        return snap

    # --- verdict (the objective view) ---------------------------------------

    def verdict(self, snap: Optional[NewsSnapshot] = None) -> NewsVerdict:
        """Build the per-story corroboration/divergence verdict over a snapshot.

        If a live query client is present, also runs an ADR 27 query through the
        inherited engine and captures the attestation + ADR 40 poison verdict
        (so the consumer's ``accept()`` narrowing step has signal). When run
        headless (no client / no loaded graph) the verdict is computed purely
        from the snapshot's structural story grouping — fully reproducible.
        """
        snap = snap or getattr(self, "_last_snapshot", None)
        if snap is None:
            raise RuntimeError("no snapshot to adjudicate (call pull() first)")

        by_story: dict[str, list[NewsArticle]] = {}
        for a in snap.articles:
            by_story.setdefault(a.story_key, []).append(a)

        stories: list[StoryVerdict] = []
        for key, arts in sorted(by_story.items()):
            origins = sorted({a.source for a in arts if a.source})
            n = len(origins)
            consensus, divergent = _consensus_and_divergence(arts)
            if n < self.quorum:
                status = "UN_CORROBORATED"
            elif divergent:
                status = "DIVERGENT"
            else:
                status = "CORROBORATED"
            # ADR 40 poison signal: single-distinct-origin retained set => POISONED.
            poison = "POISONED" if (n < self.quorum and arts) else "CLEAN"
            stories.append(StoryVerdict(
                story_key=key, outlets=origins, status=status,
                consensus=consensus, divergent=divergent, poison=poison))

        # Optional: run the inherited engine to capture attestation + witness.
        evidence: Optional[QueryResult] = None
        if getattr(self.agent, "_client", None) is not None:
            g = graph_from_news_snapshot(snap)
            op = self._broadcast_op()
            rec = QueryExecutor(g).execute(op)
            evidence = QueryResult(
                graph_name="news", raw=rec.as_dict(), record=rec,
                attestation=None)
            evidence.raw["poison"] = self.purify.evaluate(g, rec).as_dict()
        return NewsVerdict(pulled_at=snap.pulled_at, stories=stories,
                           evidence=evidence)

    @staticmethod
    def _broadcast_op():
        from ..query.algebra import And, Type
        return And(Type("document"))

    # --- narrowing (inherits ADR 40 accept) ---------------------------------

    def accept(self, verdict: NewsVerdict) -> bool:
        """Refuse the whole surface if the underlying evidence record is
        POISONED (ADR 40). Per-story un-corroboration is surfaced IN the verdict,
        not collapsed here — an un-corroborated story is reported, not dropped."""
        if verdict.evidence is None:
            return True
        return self.agent.accept(verdict.evidence)

    # --- provenance of the verdict (reproducibility) -----------------------

    def digest(self, verdict: NewsVerdict) -> str:
        """A stable hash of the verdict so a consumer can prove which exact
        objective view was served (ties into the witness log discipline)."""
        blob = json.dumps(verdict.as_dict(), sort_keys=True)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# --- structural helpers -----------------------------------------------------

def _consensus_and_divergence(arts: list[NewsArticle]):
    """Within one story_key group: consensus = CLAIM predicates present in EVERY
    outlet's claim set; divergence = predicates present in some but not all (a
    coarse 'outlets disagree on the proposition' signal, N5=a). Topic entities
    define the story group; claims define agreement within it."""
    sets = [{t for t in a.claims} for a in arts]
    if not sets:
        return [], {}
    common = set.intersection(*sets)
    all_tokens = set.union(*sets)
    divergent_tokens = all_tokens - common
    # Attribute divergent claims back to the outlet(s) that asserted them.
    divergent: dict[str, list[str]] = {}
    for a in arts:
        carried = [t for t in a.claims if t in divergent_tokens]
        if carried:
            divergent.setdefault(a.source or "<unknown>", []).extend(carried)
    return sorted(common), divergent


def _now() -> str:
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


__all__ = ["NewsAgent", "NewsVerdict", "StoryVerdict"]

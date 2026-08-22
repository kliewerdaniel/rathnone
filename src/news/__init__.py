"""ADR 48 — News Evidence Surface (objective news corroboration).

A news evidence surface that reuses the existing knowledge-query engine
(ADR 27/30/34/35/40) WITHOUT any new trust logic. News feeds are parsed into
the same ``ConceptGraph`` shape the SKC loader consumes; ``QueryExecutor``,
``PurificationLayer`` (distinct-origin quorum), and the witness/trust logs then
run unchanged.

This submodule is INDEPENDENT of the frozen finance gateway and of the
knowledge-query service. It imports ``src.query`` primitives (executor,
algebra, purify) to reuse the proven corroboration machinery — additive only.

Invariant 1 preserved: never imports or calls ``fleet.epistemic.decide()``.
Local-first: feed fetch is opt-in (RATHNONE_NEWS_ENABLED=0 default), no bundled
feeds, localhost-only if any embedding assist is later added. No new deps
(stdlib ``xml.etree`` / ``urllib`` only).
"""

from .agent import NewsAgent, NewsVerdict
from .ingest import (
    NewsArticle,
    NewsSnapshot,
    graph_from_news_snapshot,
    parse_atom,
    parse_json_feed,
    parse_rss,
)

__all__ = [
    "NewsAgent",
    "NewsVerdict",
    "NewsArticle",
    "NewsSnapshot",
    "graph_from_news_snapshot",
    "parse_rss",
    "parse_atom",
    "parse_json_feed",
]

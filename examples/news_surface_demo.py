"""ADR 48 — runnable News Evidence Surface demo (no network).

Exercises the objective-news verdict over FIXTURE articles so the corroboration
/ variance / divergence logic is proven end-to-end without any live feed fetch.
Run::

    env -u PYTHONPATH -u VIRTUAL_ENV RATHNONE_NEWS_ENABLED=1 \\
        .venv/bin/python examples/news_surface_demo.py

The demo asserts the honest output contract:
  * 3 distinct outlets on one story_key     -> CORROBORATED
  * 1 outlet (sputnik) on another story_key -> UN_CORROBORATED (poison POISONED)
  * 2 outlets sharing a story_key but with a conflicting entity -> DIVERGENT
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.news.agent import NewsAgent, NewsSnapshot, NewsArticle
from src.news.ingest import graph_from_news_snapshot


def _art(id: str, title: str, url: str, source: str, entities: list[str],
         claims: list[str] | None = None, text: str = "") -> NewsArticle:
    return NewsArticle(id=id, title=title, url=url, text=text or title,
                       source=source, entities=entities, claims=claims or [])


def _fixtures() -> list[NewsArticle]:
    # Story A "gaza|israel": 3 distinct outlets, same topic + claim -> CORROBORATED.
    a1 = _art("a1", "Gaza ceasefire holds", "https://ap.org/n1", "ap.org",
              ["gaza", "israel"], ["report ceasefire"])
    a2 = _art("a2", "Gaza ceasefire reported", "https://bbc.com/n2", "bbc.com",
              ["gaza", "israel"], ["report ceasefire"])
    a3 = _art("a3", "Ceasefire in Gaza", "https://reuters.com/n3", "reuters.com",
              ["gaza", "israel"], ["report ceasefire"])
    # Story B "nato": single outlet -> UN_CORROBORATED / POISONED.
    b1 = _art("b1", "NATO to disband", "https://sputnik.com/n4", "sputnik.com",
              ["nato"], ["report disband"])
    # Story C "election|harris": 2 outlets, conflicting claim -> DIVERGENT.
    c1 = _art("c1", "Election certifies", "https://ap.org/n5", "ap.org",
              ["election", "harris"], ["certify election"])
    c2 = _art("c2", "Election contested", "https://bbc.com/n6", "bbc.com",
              ["election", "harris"], ["contest election"])
    return [a1, a2, a3, b1, c1, c2]


def main() -> int:
    os.environ["RATHNONE_NEWS_ENABLED"] = "1"
    agent = NewsAgent(client=None, quorum=2, enabled=True)
    snap = NewsSnapshot(articles=_fixtures(), pulled_at="2026-08-22T00:00:00+00:00")
    verdict = agent.verdict(snap)

    print("\n=== News Evidence Surface — objective view ===")
    checks: dict[str, bool] = {}
    for s in verdict.stories:
        print(f"  {s.status:<16} key={s.story_key!r}")
        print(f"      outlets={s.outlets} poison={s.poison}")
        if s.divergent:
            print(f"      divergent={s.divergent}")

    by_key = {s.story_key: s for s in verdict.stories}

    # Assertions (the honest contract).
    ceas = by_key.get("gaza|israel")
    checks["gaza corroborated (3 distinct outlets)"] = (
        ceas is not None and ceas.status == "CORROBORATED"
        and len(ceas.outlets) == 3)
    nato = by_key.get("nato")
    checks["nato un-corroborated + poisoned (1 outlet)"] = (
        nato is not None and nato.status == "UN_CORROBORATED"
        and nato.poison == "POISONED")
    elec = by_key.get("election|harris")
    checks["election divergent (conflicting claim)"] = (
        elec is not None and elec.status == "DIVERGENT"
        and bool(elec.divergent))

    # Engine reuse: build the graph and run a deterministic query (ADR 27).
    g = graph_from_news_snapshot(snap)
    from src.query.algebra import And, Type
    from src.query.executor import QueryExecutor
    rec = QueryExecutor(g).execute(And(Type("document")))
    checks["graph builds + executor runs"] = len(rec.included) == 6

    passed = sum(1 for v in checks.values() if v)
    print("\n=== Checks ===")
    for name, ok in checks.items():
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"\nSUMMARY: {passed}/{len(checks)} passed")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())

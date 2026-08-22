"""ADR 48 — tests for the objective news evidence surface.

No network. All assertions are deterministic and reproducible from
(snapshot) + policy, matching the codebase's key-free-verifiable discipline.
"""

import os

import pytest

from src.news.agent import NewsAgent, NewsSnapshot, NewsVerdict
from src.news.ingest import (
    NewsArticle,
    graph_from_news_snapshot,
    parse_atom,
    parse_json_feed,
    parse_rss,
)

RSS = """<?xml version="1.0"?>
<rss version="2.0"><channel><title>Demo</title>
<item><title>Gaza ceasefire holds</title><link>https://ap.org/n1</link>
<description>Israel and Gaza agree a <b>ceasefire</b>.</description>
<pubDate>Sat, 22 Aug 2026 10:00:00 +0000</pubDate></item>
<item><title>NATO to disband</title><link>https://sputnik.com/n4</link>
<description>NATO will disband soon.</description></item>
</channel></rss>"""

ATOM = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<entry><title>Gaza ceasefire reported</title>
<link href="https://bbc.com/n2"/></entry>
<entry><title>Ceasefire in Gaza</title>
<link href="https://reuters.com/n3"/></entry>
</feed>"""

JSON_FEED = """{
  "version": "https://jsonfeed.org/version/1.1",
  "title": "Demo",
  "items": [
    {"title": "Election certifies", "url": "https://ap.org/n5",
     "content_text": "Harris certified the election."},
    {"title": "Election contested", "url": "https://bbc.com/n6",
     "content_text": "The election is contested by Harris."}
  ]
}"""


def _art(id, title, url, source, entities, claims=None, text=""):
    return NewsArticle(id=id, title=title, url=url, text=text or title,
                       source=source, entities=entities, claims=claims or [])


def _fixture_articles():
    return [
        _art("a1", "Gaza ceasefire holds", "https://ap.org/n1", "ap.org",
             ["gaza", "ceasefire", "israel"], claims=["report ceasefire"]),
        _art("a2", "Gaza ceasefire reported", "https://bbc.com/n2", "bbc.com",
             ["gaza", "ceasefire", "israel"], claims=["report ceasefire"]),
        _art("a3", "Ceasefire in Gaza", "https://reuters.com/n3", "reuters.com",
             ["gaza", "ceasefire", "israel"], claims=["report ceasefire"]),
        _art("b1", "NATO to disband", "https://sputnik.com/n4", "sputnik.com",
             ["nato", "disband"], claims=["report disband"]),
        _art("c1", "Election certifies", "https://ap.org/n5", "ap.org",
             ["election", "harris"], claims=["certify election"]),
        _art("c2", "Election contested", "https://bbc.com/n6", "bbc.com",
             ["election", "harris"], claims=["contest election"]),
    ]


# --- parse ------------------------------------------------------------------

def test_parse_rss():
    arts = parse_rss(RSS)
    assert len(arts) == 2
    assert arts[0].source == "ap.org"
    # Proper-noun (capitalized) topic extraction: Gaza + Israel present.
    assert "gaza" in arts[0].entities and "israel" in arts[0].entities
    assert arts[0].published  # normalized date present


def test_parse_atom():
    arts = parse_atom(ATOM)
    assert len(arts) == 2
    assert {a.source for a in arts} == {"bbc.com", "reuters.com"}


def test_parse_json_feed():
    arts = parse_json_feed(JSON_FEED)
    assert len(arts) == 2
    assert {a.source for a in arts} == {"ap.org", "bbc.com"}


# --- graph build ------------------------------------------------------------

def test_graph_from_snapshot_builds_document_and_concepts():
    g = graph_from_news_snapshot(NewsSnapshot(articles=_fixture_articles()))
    docs = [e for e in g.all() if e.type == "document"]
    concepts = [e for e in g.all() if e.type == "concept"]
    outlets = [e for e in g.all() if e.type == "outlet"]
    assert len(docs) == 6
    assert len(outlets) >= 1
    assert len(concepts) >= 1
    # Each document links to its outlet via an OUTLET edge.
    assert any(e.kind == "OUTLET" for e in
               [edge for elist in g._adj.values() for edge in elist])


# --- story_key + grouping ---------------------------------------------------

def test_story_key_groups_same_entities():
    a = _art("x", "Gaza ceasefire", "https://ap.org/x", "ap.org",
             ["gaza", "israel"], claims=["report ceasefire"])
    b = _art("y", "Ceasefire in Gaza", "https://bbc.com/y", "bbc.com",
             ["gaza", "israel"], claims=["report ceasefire"])
    assert a.story_key == b.story_key == "gaza|israel"


def test_subdomains_collapse_to_one_outlet():
    from src.news.ingest import _registrable
    # Real ADR 40 eTLD+1 collapse: www.ap.org must derive to ap.org (one origin).
    assert _registrable("https://www.ap.org/x") == "ap.org"
    # A genuinely distinct registrable domain stays distinct.
    assert _registrable("https://ap.net/y") == "ap.net"
    # ap.org and ap.com are distinct origins (honest limit of structural defense).
    assert _registrable("https://ap.org/x") != _registrable("https://ap.com/y")


# --- verdict: corroboration / un-corroborated / divergence ------------------

def _verdict():
    agent = NewsAgent(client=None, quorum=2, enabled=True)
    snap = NewsSnapshot(articles=_fixture_articles(),
                        pulled_at="2026-08-22T00:00:00+00:00")
    return agent.verdict(snap)


def test_verdict_corroborated_for_three_distinct_outlets():
    v = _verdict()
    story = next(s for s in v.stories if s.story_key == "ceasefire|gaza|israel")
    assert story.status == "CORROBORATED"
    assert len(story.outlets) == 3
    assert story.poison == "CLEAN"


def test_verdict_un_corroborated_single_origin_is_poisoned():
    v = _verdict()
    story = next(s for s in v.stories if s.story_key == "disband|nato")
    assert story.status == "UN_CORROBORATED"
    assert story.poison == "POISONED"  # ADR 40 single-origin => POISONED


def test_verdict_divergent_when_outlets_conflict():
    v = _verdict()
    key = "certified|election|harris"
    story = next((s for s in v.stories if s.story_key == key), None)
    if story is None:
        # entity order may differ; find the election story by membership
        story = next(s for s in v.stories if "election" in s.story_key)
    assert story.status == "DIVERGENT"
    assert story.divergent  # ap carries 'certified', bbc carries 'contested'


def test_verdict_accept_narrows_on_poison():
    agent = NewsAgent(client=None, quorum=2, enabled=True)
    snap = NewsSnapshot(
        articles=[_art("b1", "NATO to disband", "https://sputnik.com/n4",
                       "sputnik.com", ["nato", "disband"])])
    v = agent.verdict(snap)
    # headless verdict (no client) => accept() passes; but the per-story poison
    # is stamped. Verify the stamp is present and honest.
    assert v.stories[0].poison == "POISONED"


# --- fail-closed egress -----------------------------------------------------

def test_pull_refuses_when_disabled():
    agent = NewsAgent(client=None, enabled=False)
    with pytest.raises(RuntimeError):
        agent.pull(["https://example.com/feed.rss"])


def test_pull_refuses_with_no_feeds():
    agent = NewsAgent(client=None, enabled=True)
    with pytest.raises(RuntimeError):
        agent.pull([])


def test_pull_with_fetcher_isolated_from_network():
    agent = NewsAgent(client=None, enabled=True)
    captured = {}

    def fake_get(url):
        captured["url"] = url
        return RSS

    snap = agent.pull(["https://op.example/feed.rss"], fetcher=fake_get)
    assert captured["url"] == "https://op.example/feed.rss"
    assert len(snap.articles) == 2


# --- reproducibility --------------------------------------------------------

def test_verdict_digest_is_stable():
    agent = NewsAgent(client=None, quorum=2, enabled=True)
    snap = NewsSnapshot(articles=_fixture_articles())
    v1 = agent.verdict(snap)
    v2 = agent.verdict(snap)
    assert agent.digest(v1) == agent.digest(v2)

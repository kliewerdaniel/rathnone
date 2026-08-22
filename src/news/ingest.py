"""ADR 48 — news feed ingest -> KnowledgeGraph (reuses src.query engine).

Deterministic parsers for RSS 2.0, Atom 1.0, and JSON Feed 1.1 (stdlib only,
no third-party feed lib, no network here). Each parsed article becomes a
``NewsArticle``; a set of articles + the operator's configured source list forms
a ``NewsSnapshot``; ``graph_from_news_snapshot`` freezes it into the same
``Entity`` / ``Edge`` / ``KnowledgeGraph`` shape the SKC loader produces, so the
existing ``QueryExecutor`` / ``PurificationLayer`` run unchanged.

The ONLY news-specific logic added on top of the engine is ``story_key`` — the
deterministic grouping key (ADR 48 fork N5=a) that decides which articles from
different outlets are "the same story" for corroboration/variance.

Local-first / fail-closed:
  * Parsing is pure (no I/O). Network fetch lives in ``NewsAgent.pull`` and is
    opt-in behind ``RATHNONE_NEWS_ENABLED``; with no configured feeds the agent
    refuses to pull (no surface).
  * ``source`` is the *registrable domain* (eTLD+1) of the article URL, collapsed
    via the SAME ``_etld1`` the ADR 40 quorum uses, so ``ap.org``/``ap.com``
    count as one origin. News never invents provenance; it derives it from the
    article's own URL.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from ..query.executor import Edge, Entity, KnowledgeGraph
from ..query.purify import _etld1

# --- article model ----------------------------------------------------------

_NS = {
    "atom": "http://www.w3.org/2005/Atom",
    "dc": "http://purl.org/dc/elements/1.1/",
    "content": "http://purl.org/rss/1.0/modules/content/",
}


@dataclass
class NewsArticle:
    """One parsed article. ``source`` is derived from the URL host (eTLD+1).

    ``entities`` are the TOPIC/SUBJECT entities (people, places, orgs, events)
    used to cluster articles into the same ``story_key``. ``claims`` are the
    proposition predicates each outlet asserts about that story (e.g.
    "certified" vs "contested") — used for DIVERGENCE detection, NOT for
    grouping. Keeping them separate is what lets two outlets on the SAME story
    (same ``entities``) still be flagged DIVERGENT when their ``claims`` disagree
    (ADR 48 fork N5=a + divergence spec).
    """

    id: str
    title: str
    url: str
    text: str
    source: str                  # registrable domain (eTLD+1) of the URL host
    published: str = ""          # ISO-8601-ish; empty if unknown
    entities: list[str] = field(default_factory=list)   # topic -> story_key
    claims: list[str] = field(default_factory=list)     # proposition -> divergence

    @property
    def story_key(self) -> str:
        """Deterministic grouping key (sorted, lowercased, punct-stripped top-N
        TOPIC entities). Articles sharing a story_key are the 'same story' for
        corroboration/variance. Coarse by design (N5=a); embeddings (N5=b) are a
        later opt-in additive that would replace this grouping step."""
        return _story_key(self.entities)


@dataclass
class NewsSnapshot:
    """A frozen pull of configured feeds at time ``pulled_at``."""

    articles: list[NewsArticle]
    pulled_at: str = ""
    # Operator-configured feed URLs (provenance of the pull itself).
    feed_sources: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "pulled_at": self.pulled_at,
            "feed_sources": list(self.feed_sources),
            "articles": [a.__dict__ for a in self.articles],
        }


# --- deterministic parse helpers --------------------------------------------

def _text(el: Optional[ET.Element]) -> str:
    if el is None or el.text is None:
        return ""
    return el.text.strip()


def _html_to_text(html: str) -> str:
    """Drop tags, collapse whitespace — keep it deterministic and dependency-free."""
    txt = re.sub(r"<[^>]+>", " ", html or "")
    return re.sub(r"\s+", " ", txt).strip()


def _registrable(url: str) -> str:
    """Registrable domain (eTLD+1) of a URL — reuse ADR 40's collapse so outlet
    origins match the corroboration quorum's notion of 'distinct origin'."""
    if not url:
        return ""
    host = urlparse(url).hostname or ""
    return _etld1(host)


# Dependency-free subject/claim extraction (deterministic, no model, no
# embeddings). Two streams:
#   * TOPIC tokens -> entities (used for story_key grouping). These are
#     capitalized person/place/org phrases.
#   * CLAIM verbs -> the proposition predicates each outlet asserts (used for
#     divergence). We capture a small set of reporting verbs + their object noun
#     so "certified the election" vs "contested the election" diverge.
_ENTITY_RE = re.compile(r"\b([A-Z][a-z0-9]+(?:\s+[A-Z][a-z0-9]+){0,3})\b")
_QUOTE_RE = re.compile(r'"([^"]{3,120})"')
_CLAIM_VERB_RE = re.compile(
    r"\b(certif\w+|contest\w+|confirm\w+|deny\w+|kill\w+|die\w+|surviv\w+|"
    r"win\w+|lose\w+|agree\w+|reject\w+|sign\w+|veto\w+|arrest\w+)\b",
    re.IGNORECASE)


def _extract_entities(title: str, text: str) -> tuple[list[str], list[str]]:
    """Return (topic_entities, claim_predicates)."""
    blob = f"{title} {text}"
    topics: list[str] = []
    for m in _ENTITY_RE.finditer(blob):
        tok = m.group(1).strip().lower()
        if tok in ("the", "a", "an", "this", "that", "it", "we", "they", "he",
                   "she", "his", "her", "our", "their", "i", "you", "in", "on",
                   "at", "to", "of", "for", "and", "but", "or"):
            continue
        topics.append(tok)
    for m in _QUOTE_RE.finditer(text):
        topics.append(m.group(1).strip().lower())
    seen: list[str] = []
    for f in topics:
        if f not in seen:
            seen.append(f)
    topics = seen[:12]
    # Claim predicates: verb + following object noun phrase (1-2 capitalized or
    # lowercased noun tokens). We keep the (verb, object) pair so divergence is
    # meaningful ("certified election" vs "contested election").
    claims: list[str] = []
    for m in _CLAIM_VERB_RE.finditer(blob):
        start = m.end()
        obj = blob[start:start + 40]
        om = re.match(r"\s+([a-z0-9]+(?:\s+[a-z0-9]+){0,1})", obj)
        pair = (m.group(1).lower() + " " + om.group(1).lower()) if om else m.group(1).lower()
        claims.append(pair.strip())
    cseen: list[str] = []
    for c in claims:
        if c not in cseen:
            cseen.append(c)
    return topics, cseen[:8]


def _story_key(entities: list[str], top_n: int = 4) -> str:
    norm = sorted(
        re.sub(r"[^a-z0-9 ]", " ", e).strip()
        for e in (entities[:top_n] if entities else [])
    )
    return "|".join(norm)


# --- feed format parsers (pure, no I/O) -------------------------------------

def parse_rss(xml_text: str) -> list[NewsArticle]:
    root = ET.fromstring(xml_text)
    out: list[NewsArticle] = []
    for item in root.iter("item"):
        title = _text(item.find("title"))
        link = _text(item.find("link"))
        desc = _text(item.find("description"))
        pub = _text(item.find("pubDate"))
        src = _registrable(link)
        body = _html_to_text(desc)
        ents, claims = _extract_entities(title, body)
        out.append(NewsArticle(
            id=_article_id(link, title),
            title=title, url=link, text=body, source=src,
            published=_normalize_date(pub), entities=ents, claims=claims))
    return out


def parse_atom(xml_text: str) -> list[NewsArticle]:
    out: list[NewsArticle] = []
    for entry in root_iter(xml_text, f"{{{_NS['atom']}}}entry"):
        title = _text(entry.find(f"{{{_NS['atom']}}}title"))
        link = ""
        for link_el in entry.findall(f"{{{_NS['atom']}}}link"):
            href = link_el.get("href")
            if href:
                link = href
                break
        content_el = entry.find(f"{{{_NS['atom']}}}content")
        summary_el = entry.find(f"{{{_NS['atom']}}}summary")
        raw = _text(content_el) or _text(summary_el)
        body = _html_to_text(raw)
        pub = _text(entry.find(f"{{{_NS['atom']}}}updated")) or _text(
            entry.find(f"{{{_NS['atom']}}}published"))
        src = _registrable(link)
        ents, claims = _extract_entities(title, body)
        out.append(NewsArticle(
            id=_article_id(link, title),
            title=title, url=link, text=body, source=src,
            published=_normalize_date(pub), entities=ents, claims=claims))
    return out


def parse_json_feed(json_text: str) -> list[NewsArticle]:
    obj = json.loads(json_text)
    out: list[NewsArticle] = []
    for item in obj.get("items", []) or []:
        title = item.get("title", "") or ""
        url = item.get("url", "") or item.get("external_url", "") or ""
        content = item.get("content_text") or item.get("summary") \
            or _html_to_text(item.get("content_html", "") or "")
        pub = item.get("date_published", "") or ""
        src = _registrable(url)
        ents, claims = _extract_entities(title, content)
        out.append(NewsArticle(
            id=_article_id(url, title),
            title=title, url=url, text=content, source=src,
            published=_normalize_date(pub), entities=ents, claims=claims))
    return out


def root_iter(xml_text: str, tag: str):
    root = ET.fromstring(xml_text)
    return root.iter(tag)


def _article_id(url: str, title: str) -> str:
    """Stable per-article id (URL if present, else hash of title)."""
    if url:
        return url
    return "news:" + hashlib.sha256(title.encode("utf-8")).hexdigest()[:16]


def _normalize_date(s: str) -> str:
    """Best-effort normalize to compact ISO; leave unchanged if unparseable."""
    s = (s or "").strip()
    if not s:
        return ""
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return _dt.datetime.strptime(
                s.replace("Z", "+0000"), fmt).isoformat()
        except ValueError:
            continue
    return s


def parse_auto(raw: str) -> list[NewsArticle]:
    """Detect feed flavor and dispatch. Fail-closed: a non-XML, non-JSON blob
    raises so the caller can quarantine the malformed source rather than silently
    returning zero articles."""
    stripped = raw.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return parse_json_feed(raw)
    if "<rss" in stripped.lower() or "<item" in stripped.lower():
        return parse_rss(raw)
    if "<feed" in stripped.lower():
        return parse_atom(raw)
    raise ValueError("unrecognized feed format (not RSS/Atom/JSON)")


# --- graph builder (reuses engine shape; no new trust) ----------------------

def graph_from_news_snapshot(snap: NewsSnapshot) -> KnowledgeGraph:
    """Freeze a news snapshot into the engine's ``KnowledgeGraph`` shape.

    Produces, per article:
      * a ``document`` Entity (source = eTLD+1 origin, text = title);
      * ``concept`` Entities for each extracted entity token;
      * edges ``COVERS`` (article -> concept) and ``OUTLET`` (article -> source).

    That is the same shape ``graph_from_skc_artifact`` produces, so the existing
    ``QueryExecutor`` and ``PurificationLayer`` (ADR 40 distinct-origin quorum)
    consume it unchanged.
    """
    g = KnowledgeGraph()
    for art in snap.articles:
        doc_id = f"doc:{art.id}"
        g.add(Entity(
            id=doc_id,
            type="document",
            source=art.source,
            text=art.title,
            extra={"url": art.url, "published": art.published,
                   "story_key": art.story_key},
        ))
        g.add(Entity(id=f"src:{art.source}", type="outlet", text=art.source))
        g.link(doc_id, f"src:{art.source}", kind="OUTLET")
        for ent in art.entities:
            cid = f"concept:{ent}"
            g.add(Entity(id=cid, type="concept", text=ent))
            g.link(doc_id, cid, kind="COVERS")
        # Index CLAIM predicates as their own concepts so divergence is
        # inspectable in the graph (and reuses the engine's CORROBORATION on
        # claim nodes if a query targets them).
        for cl in art.claims:
            cid = f"claim:{cl}"
            g.add(Entity(id=cid, type="claim", text=cl))
            g.link(doc_id, cid, kind="ASSERTS")
    return g


__all__ = [
    "NewsArticle",
    "NewsSnapshot",
    "parse_rss",
    "parse_atom",
    "parse_json_feed",
    "parse_auto",
    "graph_from_news_snapshot",
]

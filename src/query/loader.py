"""Load a KnowledgeGraph from a real Sovereign Knowledge Compiler artifact.

The upstream format we consume is the ``research-knowledge-artifact/1.0`` schema
produced by the SKC / research-compiler family (see
``sovereign-knowledge-compiler``, ``research-compiler-agent``). We deliberately
do NOT re-implement knowledge compilation — we only *consume* the compiled
graph and provenance, turning it into something the query executor can run a
deterministic query over.

Mapping (faithful to the real schema, no invented fields):

  artifact.graphs.concept_graph.nodes[]   -> Entity(id, type="concept",
                                                    text=label)
      {id, label, type?}
  artifact.graphs.concept_graph.edges[]   -> typed Edge(src, dst, kind)
      {id, source, target, type, confidence, provenance}
  artifact.documents_index[]              -> Entity(id=doc_id, source=domain,
                                                    score=authority, text=title)
      {doc_id, title, url, domain, authority, ...}
  artifact.claims[]                        -> Entity(id=claim id,
                                                    text=claim text,
                                                    source=doc domain if known,
                                                    score=confidence)
      {id, doc_id, text, type, confidence, ...}

The loader is tolerant: missing keys are skipped, unknown graph names ignored,
so a partial/older artifact still loads. Determinism is preserved — node
insertion order does not affect query results (the executor sorts ids).
"""

from __future__ import annotations

import json
from typing import Optional

from .executor import Edge, Entity, KnowledgeGraph


def graph_from_skc_artifact(path_or_obj) -> KnowledgeGraph:
    """Build a KnowledgeGraph from an SKC artifact JSON file or parsed dict.

    ``path_or_obj`` is either a filesystem path (str) or an already-parsed
    ``dict`` (so callers can feed in-memory artifacts without touching disk).
    """
    if isinstance(path_or_obj, (str, bytes)):
        with open(path_or_obj, "r", encoding="utf-8") as fh:
            art = json.load(fh)
    else:
        art = path_or_obj

    g = KnowledgeGraph()

    graphs = art.get("graphs", {}) or {}
    concept = graphs.get("concept_graph", {}) or {}

    # --- concept / entity nodes ----------------------------------------
    for node in concept.get("nodes", []) or []:
        nid = node.get("id")
        if not nid:
            continue
        g.add(Entity(
            id=nid,
            type=node.get("type", "concept"),
            text=node.get("label", ""),
        ))

    # --- typed edges ----------------------------------------------------
    for edge in concept.get("edges", []) or []:
        src = edge.get("source")
        dst = edge.get("target")
        if not src or not dst:
            continue
        # callers may reference a node not present as a concept node; synthesize.
        if g.get(src) is None:
            g.add(Entity(id=src, type="concept", text=src))
        if g.get(dst) is None:
            g.add(Entity(id=dst, type="concept", text=dst))
        g.link(src, dst, kind=edge.get("type", "related"))

    # --- documents (provenance: domain + authority) --------------------
    docs = {d.get("doc_id"): d for d in art.get("documents_index", []) or []}
    for d in art.get("documents_index", []) or []:
        did = d.get("doc_id")
        if not did:
            continue
        g.add(Entity(
            id=did,
            type="document",
            source=d.get("domain", ""),
            text=d.get("title", ""),
            score=float(d.get("authority", 0.0) or 0.0),
        ))

    # --- claims (content + confidence) ---------------------------------
    doc_domain = {did: d.get("domain", "") for did, d in docs.items()}
    for c in art.get("claims", []) or []:
        cid = c.get("id")
        if not cid:
            continue
        g.add(Entity(
            id=cid,
            type="claim",
            source=doc_domain.get(c.get("doc_id"), ""),
            text=c.get("text", ""),
            score=float(c.get("confidence", 0.0) or 0.0),
        ))

    return g


def load_artifact(path: str) -> dict:
    """Parse an SKC artifact JSON file into a dict (thin helper)."""
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


__all__ = ["graph_from_skc_artifact", "load_artifact"]

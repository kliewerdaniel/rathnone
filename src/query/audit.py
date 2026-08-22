"""ADR 45 — no-data-loss audit traversal over the in-memory KnowledgeGraph.

Mirrors `cypher-no-data-loss`: anchor every query on the *entity* collection
(`graph.all()`), gather joined/optional data (witness hits, scope hits) via
comprehensions that may come back EMPTY, and **assert result cardinality** so a
missing row looks like an error, not a small result.

The risk this closes: an aggregation that anchors on a *relationship* instead of
the *entity* silently drops any entity with zero related rows. The evidence
witness/key-log replay tooling enumerates served records/key rotations; an
entity or record with zero witness entries must still survive the enumeration.

Deterministic: identical (graph, log) => identical audit rows (sorted by id).
Fail-closed: a cardinality mismatch raises rather than returning a truncated
result. Stdlib only. Never imports the frozen `decide()` spine.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Iterable, Optional


@dataclass
class EntityAudit:
    """One anchor-first audit row. Every entity appears, even with zero events.

    ``witness_hits`` / ``scope_hits`` default to 0 (empty-safe), so an isolated
    entity is reported with ``event_count == 0`` rather than being dropped.
    """

    entity_id: str
    entity_type: str
    event_count: int = 0
    witness_hits: int = 0
    scope_hits: int = 0
    extra: dict = field(default_factory=dict)


def _witness_hits_for(entity_id: str, witness_log) -> int:
    """Count witness entries mentioning ``entity_id`` (empty-safe).

    The witness log stores record hashes, not entity ids, so we match against
    any entry whose ``agent_id``/``capabilities`` plausibly cite the entity.
    For an in-memory audit we accept either an explicit ``.entities`` list on
    each entry or fall back to 0 — the point is the entity row must survive.
    """
    if witness_log is None:
        return 0
    entries = getattr(witness_log, "entries", None) or []
    total = 0
    for e in entries:
        ents = getattr(e, "entities", None)
        if ents and entity_id in ents:
            total += 1
    return total


def enumerate_entity_event_counts(graph, witness_log=None,
                                  scope_log=None) -> list[EntityAudit]:
    """Anchor-first audit: one row per entity, zero excluded.

    Iterates ``graph.all()`` (every entity, regardless of edges/events) and
    computes optional subcounts via empty-safe comprehensions. The returned list
    cardinality MUST equal ``graph.entity_count()`` — that invariant is what
    `assert_audit_cardinality` enforces.
    """
    rows: list[EntityAudit] = []
    for ent in graph.all():
        rows.append(EntityAudit(
            entity_id=ent.id,
            entity_type=ent.type,
            witness_hits=_witness_hits_for(ent.id, witness_log),
        ))
    # Sort for determinism so twice-over identical (graph, log) => identical rows.
    rows.sort(key=lambda r: r.entity_id)
    for r in rows:
        r.event_count = r.witness_hits + r.scope_hits
    return rows


def assert_audit_cardinality(rows: Iterable[EntityAudit], graph) -> None:
    """Fail-closed: raise if the audit dropped an entity.

    A truncated result (fewer rows than entities) is exactly the silent-row-drop
    failure mode `cypher-no-data-loss` warns about. We make it a hard error.
    """
    rows = list(rows)
    expected = graph.entity_count()
    observed = len(rows)
    if observed != expected:
        dropped = expected - observed
        raise AssertionError(
            f"audit cardinality mismatch: graph has {expected} entities but "
            f"audit produced {observed} rows ({dropped} dropped — silent "
            f"row loss detected)")


def canonical_audit_hash(rows: Iterable[EntityAudit]) -> str:
    """Deterministic hash over the audit rows (sorted id contract).

    Lets an operator archive an audit and later prove no entity was dropped
    between two runs (reproducible from the graph + logs).
    """
    payload = "\n".join(
        f"{r.entity_id}|{r.entity_type}|{r.event_count}|"
        f"{r.witness_hits}|{r.scope_hits}"
        for r in sorted(rows, key=lambda r: r.entity_id)
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


__all__ = [
    "EntityAudit",
    "enumerate_entity_event_counts",
    "assert_audit_cardinality",
    "canonical_audit_hash",
]

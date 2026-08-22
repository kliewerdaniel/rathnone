"""ADR 45 — no-data-loss audit traversal tests.

Proves the `cypher-no-data-loss` principle holds for the in-memory
``KnowledgeGraph``:
  * an entity with zero edges AND zero witness entries still appears in the
    audit enumeration (cardinality preserved, event_count == 0);
  * ``assert_audit_cardinality`` catches a dropped entity (truncated result
    raises) instead of silently returning a small set.
Stdlib only; no local infra required.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.query.executor import Entity, KnowledgeGraph  # noqa: E402
from src.query.audit import (  # noqa: E402
    assert_audit_cardinality,
    canonical_audit_hash,
    enumerate_entity_event_counts,
)


def _graph_with_isolated_entity() -> KnowledgeGraph:
    g = KnowledgeGraph()
    # e1 and e2 are linked and WOULD survive a relationship-anchored query.
    g.add(Entity(id="e1", type="document", source="arxiv"))
    g.add(Entity(id="e2", type="document", source="arxiv"))
    g.link("e1", "e2")
    # isolated: no edges, never queried, absent from any witness log.
    g.add(Entity(id="orphan", type="claim", source="wikipedia"))
    return g


def test_isolated_entity_survives_enumeration():
    g = _graph_with_isolated_entity()
    rows = enumerate_entity_event_counts(g)
    ids = {r.entity_id for r in rows}
    assert ids == {"e1", "e2", "orphan"}, f"dropped entities: {ids}"
    orphan = next(r for r in rows if r.entity_id == "orphan")
    assert orphan.event_count == 0
    assert orphan.witness_hits == 0


def test_cardinality_assertion_passes_for_full_enumeration():
    g = _graph_with_isolated_entity()
    rows = enumerate_entity_event_counts(g)
    # No raise == pass.
    assert_audit_cardinality(rows, g)


def test_cardinality_assertion_catches_dropped_entity():
    g = _graph_with_isolated_entity()
    rows = enumerate_entity_event_counts(g)
    # Simulate a relationship-anchored query that dropped the orphan (the
    # silent-row-drop failure mode this ADR defends against).
    truncated = [r for r in rows if r.entity_id != "orphan"]
    assert len(truncated) == 2
    with pytest.raises(AssertionError):
        assert_audit_cardinality(truncated, g)


def test_audit_hash_is_deterministic():
    g = _graph_with_isolated_entity()
    h1 = canonical_audit_hash(enumerate_entity_event_counts(g))
    h2 = canonical_audit_hash(enumerate_entity_event_counts(g))
    assert h1 == h2
    assert len(h1) == 64

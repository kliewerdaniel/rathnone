"""Engine step 2: consume a REAL SKC artifact + verify() reconciliation.

These tests prove the engine runs on genuine compiled knowledge (the
research-knowledge-artifact/1.0 schema from the SKC / research-compiler family),
not just fixtures, and that an EvidenceRecord is auditable: it can be verified
against an expected prior and reconciled against a re-run.
"""
import os
import pytest

from src.query import (
    And, Or, Not, Type, Source, Match, ScoreAtLeast, ConnectedTo,
    QueryExecutor, EvidenceRecord, graph_from_skc_artifact, load_artifact,
)

# Real artifact on disk (research-knowledge-artifact/1.0 schema).
_ARTIFACT = os.environ.get(
    "RATHNONE_SKC_FIXTURE",
    "/Users/danielkliewer/Projects/research-compiler-agent/build-research/"
    "research-knowledge-artifact.json")

pytestmark = pytest.mark.skipif(
    not os.path.exists(_ARTIFACT),
    reason=f"SKC fixture not present at {_ARTIFACT}")


@pytest.fixture(scope="module")
def g():
    return graph_from_skc_artifact(_ARTIFACT)


def test_loader_reads_real_artifact(g):
    # Multiple entity kinds coexist in one graph.
    types = {e.type for e in g.all()}
    assert "document" in types
    # The artifact has documents + claims + concept nodes.
    assert len(g.all()) > 10


def test_source_operator_filters_by_document_domain(g):
    # kubernetes.io is a documented source in this artifact.
    q = Source("kubernetes.io")
    rec = QueryExecutor(g).execute(q)
    assert rec.included_ids  # at least the kubernetes.io docs
    assert all(g.get(e).source == "kubernetes.io" for e in rec.included_ids)
    # verify(): the record is internally consistent with its own hash.
    v = rec.verify(expect_hash=rec.deterministic_hash())
    assert v.ok, v.divergences


def test_score_operator_filters_by_authority(g):
    # High-authority (authority>=0.9) documents only.
    q = ScoreAtLeast(0.9)
    rec = QueryExecutor(g).execute(q)
    assert rec.included_ids
    assert all(g.get(e).score >= 0.9 for e in rec.included_ids)


def test_connected_to_runs_on_real_typed_edges(g):
    # concept_graph edges carry a real "type"; CONNECTED_TO tolerates any kind.
    q = ConnectedTo(Match("kubernetes"), depth=2)
    rec = QueryExecutor(g).execute(q)
    # Nothing should crash and the result is reproducible.
    assert rec.deterministic_hash()
    v = rec.verify(expect_included=rec.included_ids)
    assert v.ok


def test_verify_detects_evidence_drift(g):
    # Capture a baseline, then assert verify() fails closed on a wrong expectation.
    rec = QueryExecutor(g).execute(Match("secret"))
    wrong = rec.verify(expect_included={"nonexistent-entity"})
    assert not wrong.ok
    assert wrong.divergences
    # And passes when given its own included set.
    assert rec.verify(expect_included=rec.included_ids).ok


def test_reconcile_two_runs_agree(g):
    # Determinism: two independent runs over the same graph reconcile exactly.
    a = QueryExecutor(g).execute(And(Match("secret"), ScoreAtLeast(0.0)))
    b = QueryExecutor(g).execute(And(Match("secret"), ScoreAtLeast(0.0)))
    r = a.reconcile_with(b)
    assert r.consistent, (r.only_self, r.only_other)
    assert r.self_hash == r.other_hash


def test_excluded_record_carries_provenance(g):
    # A high-score filter excludes low-authority docs; they must still be listed.
    rec = QueryExecutor(g).execute(ScoreAtLeast(0.95))
    # Some docs have authority < 0.95 -> excluded, each with reasons.
    excluded_low = [e for e in rec.excluded
                    if g.get(e.id) is not None
                    and g.get(e.id).type == "document"
                    and g.get(e.id).score < 0.95]
    assert excluded_low, "expected some low-authority docs to be excluded"
    assert all(e.reasons for e in excluded_low)

"""ADR 40 — knowledge-layer source-corroboration tests.

Each structural poison rule must flip a verdict; a clean, diverse corpus must
stay clean. No SKC compile needed — we build raw artifact dicts the loader eats.
"""

from __future__ import annotations

import os
import json
import tempfile

import pytest
from fastapi.testclient import TestClient

from src.query.loader import graph_from_skc_artifact
from src.query.executor import EvidenceRecord, KnowledgeGraph, QueryExecutor
from src.query.algebra import Op, OpKind
from src.query.purify import PurificationLayer, _etld1
from src.query.agent import KnowledgeAgent, QueryResult


def _doc(doc_id, domain, authority=0.5, title="kubernetes secrets"):
    return {"doc_id": doc_id, "title": title, "domain": domain,
            "authority": authority, "url": f"https://{domain}/{doc_id}"}


def _artifact(docs):
    return {
        "schema": "research-knowledge-artifact/1.0",
        "objective": "x",
        "graphs": {"concept_graph": {"nodes": [], "edges": []}},
        "documents_index": docs,
        "claims": [],
    }


def _graph_and_record(domains, title="kubernetes secrets",
                      op_kind=OpKind.TYPE, op_arg="document"):
    docs = [_doc(f"doc-{i}", d, title=title) for i, d in enumerate(domains)]
    g = graph_from_skc_artifact(_artifact(docs))
    rec = QueryExecutor(g).execute(Op(kind=op_kind, arg=op_arg))
    return g, rec


# --- eTLD+1 (sybil grouping) ------------------------------------------------

def test_etld1_groups_subdomains():
    assert _etld1("a.evil.com") == "evil.com"
    assert _etld1("b.evil.com") == "evil.com"
    assert _etld1("evil.com") == "evil.com"
    assert _etld1("evil.net") == "evil.net"
    assert _etld1("news.bbc.co.uk") == "bbc.co.uk"
    assert _etld1("foo.bar.example.com") == "example.com"


# --- distinct-origin quorum (the ADR 24 analogue) ---------------------------

def test_clean_diverse_corpus_stays_clean():
    g, rec = _graph_and_record(
        ["kubernetes.io", "snyk.io", "gitguardian.com", "plural.sh", "dev.to"])
    v = PurificationLayer(enabled=True, quorum=2).evaluate(g, rec)
    assert v.ok is True
    assert v.verdict == "CLEAN"
    assert v.report["n_distinct_origins"] == 5


def test_single_origin_poisoned():
    g, rec = _graph_and_record(["evil.com", "evil.com", "evil.com"])
    v = PurificationLayer(enabled=True, quorum=2).evaluate(g, rec)
    assert v.ok is False
    assert v.verdict == "POISONED"
    assert v.report["n_distinct_origins"] == 1


def test_sybil_subdomains_collapse_to_one_origin():
    g, rec = _graph_and_record(
        ["a.evil.com", "b.evil.com", "c.evil.com", "d.evil.com"])
    v = PurificationLayer(enabled=True, quorum=2).evaluate(g, rec)
    assert v.report["n_distinct_origins"] == 1
    assert v.verdict == "POISONED"


def test_distinct_etld_count_as_separate_origins():
    # honest limit: evil.com + evil.net are genuinely distinct registrations
    g, rec = _graph_and_record(["a.evil.com", "b.evil.com", "evil.net"])
    v = PurificationLayer(enabled=True, quorum=2).evaluate(g, rec)
    assert v.report["n_distinct_origins"] == 2
    assert v.verdict == "CLEAN"


def test_quorum_config_enforced():
    g, rec = _graph_and_record(["kubernetes.io", "snyk.io"])
    v = PurificationLayer(enabled=True, quorum=3).evaluate(g, rec)
    assert v.report["n_distinct_origins"] == 2
    assert v.verdict == "POISONED"


def test_authority_score_is_advisory_not_corroboration():
    # an inflated authority from a single origin must NOT buy a clean verdict
    g, rec = _graph_and_record(["evil.com"])
    for e in g.all():
        e.score = 0.99
    v = PurificationLayer(enabled=True, quorum=2).evaluate(g, rec)
    assert v.verdict == "POISONED"
    assert v.report["scores_treated_as_advisory"] is True


# --- edge cases -------------------------------------------------------------

def test_concept_only_result_is_clean():
    from src.query.executor import Entity
    g = graph_from_skc_artifact(_artifact([_doc("d1", "evil.com")]))
    g.add(Entity(id="c1", type="concept", text="kubernetes"))
    rec = QueryExecutor(g).execute(Op(kind=OpKind.TYPE, arg="concept"))
    v = PurificationLayer(enabled=True, quorum=2).evaluate(g, rec)
    assert v.verdict == "CLEAN"
    assert v.report["retained_doc_claim"] == 0


def test_disabled_layer_passthrough():
    g, rec = _graph_and_record(["evil.com"])
    v = PurificationLayer(enabled=False).evaluate(g, rec)
    assert v.ok is True
    assert v.verdict == "CLEAN"
    assert v.report.get("enabled") is False


def test_total_graph_capture_diagnosed():
    docs = [_doc(f"doc-{i}", "evil.com") for i in range(10)]
    g = graph_from_skc_artifact(_artifact(docs))
    rec = QueryExecutor(g).execute(Op(kind=OpKind.MATCH, arg="kubernetes"))
    v = PurificationLayer(enabled=True, quorum=2).evaluate(g, rec)
    codes = {x.code for x in v.violations}
    assert "insufficient_source_diversity" in codes
    assert "total_graph_capture" in codes


# --- service + agent wiring -------------------------------------------------

def _make_app():
    os.environ["RATHNONE_PURIFY_ENABLED"] = "1"
    os.environ["RATHNONE_PURIFY_QUORUM"] = "2"
    from src.query.service import create_app
    return create_app()


def _load_and_query(app, docs, graph_name, text="find research about kubernetes"):
    c = TestClient(app)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(_artifact(docs), f)
        path = f.name
    c.post("/graphs/load", json={"artifact_path": path, "graph_name": graph_name})
    r = c.post("/query/nl", json={"graph_name": graph_name, "text": text})
    assert r.status_code == 200, r.text
    return r.json()


def test_service_annotates_poison_when_enabled():
    app = _make_app()
    poison = [_doc(f"d{i}", "evil.com") for i in range(3)]
    clean = [_doc(f"d{i}", d) for i, d in enumerate(
        ["kubernetes.io", "snyk.io", "gitguardian.com"])]
    pj = _load_and_query(app, poison, "poison")
    cj = _load_and_query(app, clean, "clean")
    assert pj["poison"]["verdict"] == "POISONED"
    assert cj["poison"]["verdict"] == "CLEAN"


def test_agent_refuses_poisoned_accepts_clean():
    def _qr(verdict):
        return QueryResult(graph_name="g",
                           raw={"poison": {"verdict": verdict}} if verdict else {},
                           record=EvidenceRecord(), attestation=None)
    agent = KnowledgeAgent(client=None)
    assert agent.accept(_qr("CLEAN")) is True
    assert agent.accept(_qr("POISONED")) is False
    assert agent.accept(_qr(None)) is True  # layer not in force


# --- semantic poison (ADR 40 extension): the corpus's OWN signal ------------
# The SKC artifact carries a `contradictions[]` array flagging pairs of
# mutually-opposing claims. The loader indexes each claim's opponents into
# entity.extra["contradicts"]; the PurificationLayer flags a retained set that
# includes BOTH sides. This is SEMANTIC poison the corpus itself diagnosed.

def _claim(cid, text, confidence=0.9, doc_domain=""):
    return {"id": cid, "text": text, "type": "fact",
            "confidence": confidence, "doc_id": f"doc-{cid}"}


def _artifact_with_claims_and_contradictions(domains, claims, contradictions):
    # ensure each claim's doc_id resolves to a document
    for i, c in enumerate(claims):
        c.setdefault("doc_id", f"doc-claim-{i}")
    docs = [_doc(c["doc_id"], domains[i % len(domains)] if domains else "kubernetes.io")
            for i, c in enumerate(claims)]
    return {
        "schema": "research-knowledge-artifact/1.0",
        "objective": "x",
        "graphs": {"concept_graph": {"nodes": [], "edges": []}},
        "documents_index": docs,
        "claims": claims,
        "contradictions": contradictions,
    }


def test_loader_indexes_corpus_contradictions():
    claims = [
        _claim("clm-1", "Kubernetes Secrets store sensitive information"),
        _claim("clm-2", "Kubernetes Secrets reduce the risk of exposure"),
        _claim("clm-3", "Kubernetes Secrets increase the risk of exposure"),
    ]
    contras = [{"claim_a": claims[1]["text"], "claim_b": claims[2]["text"],
                "confidence": 0.8, "dimension": "fact"}]
    g = graph_from_skc_artifact(
        _artifact_with_claims_and_contradictions(
            ["kubernetes.io", "snyk.io", "gitguardian.com"], claims, contras))
    a = g.get("clm-2")
    b = g.get("clm-3")
    assert "clm-3" in (a.extra.get("contradicts") or [])
    assert "clm-2" in (b.extra.get("contradicts") or [])
    assert a.extra.get("contradiction_confidence") == 0.8


def test_retaining_both_sides_of_contradiction_is_poisoned():
    claims = [
        _claim("clm-1", "Kubernetes Secrets store sensitive information"),
        _claim("clm-2", "Kubernetes Secrets reduce the risk of exposure"),
        _claim("clm-3", "Kubernetes Secrets increase the risk of exposure"),
    ]
    contras = [{"claim_a": claims[1]["text"], "claim_b": claims[2]["text"],
                "confidence": 0.8, "dimension": "fact"}]
    g = graph_from_skc_artifact(
        _artifact_with_claims_and_contradictions(
            ["kubernetes.io", "snyk.io", "gitguardian.com"], claims, contras))
    rec = QueryExecutor(g).execute(Op(kind=OpKind.TYPE, arg="claim"))
    v = PurificationLayer(enabled=True, quorum=2).evaluate(g, rec)
    codes = {x.code for x in v.violations}
    assert "internal_contradiction" in codes
    assert v.verdict == "POISONED"
    assert ("clm-2", "clm-3") in v.report["contradicted_pairs"]


def test_retaining_one_side_of_contradiction_stays_clean():
    claims = [
        _claim("clm-1", "Kubernetes Secrets store sensitive information"),
        _claim("clm-2", "Kubernetes Secrets reduce the risk of exposure"),
        _claim("clm-3", "Kubernetes Secrets increase the risk of exposure"),
    ]
    contras = [{"claim_a": claims[1]["text"], "claim_b": claims[2]["text"],
                "confidence": 0.8, "dimension": "fact"}]
    g = graph_from_skc_artifact(
        _artifact_with_claims_and_contradictions(
            ["kubernetes.io", "snyk.io", "gitguardian.com"], claims, contras))
    # Narrow the retained set to ONE side only (kubernetes.io) -> the retained
    # set is not internally contradictory, even though it may still fail the
    # origin quorum on its own. The point tested here is the contradiction flag.
    rec = QueryExecutor(g).execute(Op(kind=OpKind.SOURCE, arg="kubernetes.io"))
    v = PurificationLayer(enabled=True, quorum=2).evaluate(g, rec)
    assert "internal_contradiction" not in {x.code for x in v.violations}


def test_unearned_confidence_flagged():
    claims = [
        _claim("clm-1", "Secrets are encrypted at rest", confidence=0.95),
        _claim("clm-2", "Secrets are encrypted in transit", confidence=0.95),
    ]
    g = graph_from_skc_artifact(
        _artifact_with_claims_and_contradictions(
            ["evil.com", "evil.com"], claims, []))
    rec = QueryExecutor(g).execute(Op(kind=OpKind.TYPE, arg="claim"))
    v = PurificationLayer(enabled=True, quorum=2).evaluate(g, rec)
    codes = {x.code for x in v.violations}
    assert "unearned_confidence" in codes
    assert len(v.report["unearned_confidence"]) == 2


def test_unearned_confidence_not_flagged_when_quorum_met():
    claims = [
        _claim("clm-1", "Secrets are encrypted at rest", confidence=0.95),
        _claim("clm-2", "Secrets are encrypted in transit", confidence=0.9),
    ]
    g = graph_from_skc_artifact(
        _artifact_with_claims_and_contradictions(
            ["kubernetes.io", "snyk.io"], claims, []))
    rec = QueryExecutor(g).execute(Op(kind=OpKind.TYPE, arg="claim"))
    v = PurificationLayer(enabled=True, quorum=2).evaluate(g, rec)
    assert "unearned_confidence" not in {x.code for x in v.violations}
    assert v.verdict == "CLEAN"


def test_service_annotates_semantic_poison_over_wire():
    claims = [
        _claim("clm-1", "Kubernetes Secrets store sensitive information"),
        _claim("clm-2", "Kubernetes Secrets reduce the risk of exposure"),
        _claim("clm-3", "Kubernetes Secrets increase the risk of exposure"),
    ]
    contras = [{"claim_a": claims[1]["text"], "claim_b": claims[2]["text"],
                "confidence": 0.8, "dimension": "fact"}]
    art = _artifact_with_claims_and_contradictions(
        ["kubernetes.io", "snyk.io", "gitguardian.com"], claims, contras)
    app = _make_app()
    c = TestClient(app)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(art, f)
        path = f.name
    c.post("/graphs/load", json={"artifact_path": path, "graph_name": "sem"})
    # Deterministic Op query (TYPE=claim) retains both opposing claims.
    r = c.post("/query/op",
               json={"graph_name": "sem",
                     "op": Op(kind=OpKind.TYPE, arg="claim").to_dict()})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["poison"]["verdict"] == "POISONED"
    codes = {v["code"] for v in body["poison"]["violations"]}
    assert "internal_contradiction" in codes

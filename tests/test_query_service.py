"""HTTP integration for the knowledge-query service (Step 4).

An agent system should be able to load a graph and run queries over HTTP
without knowing anything about src/query internals. This test drives the
real service app with TestClient against the genuine SKC artifact (the same
42KB research-knowledge-artifact/1.0 file used by the loader tests), proving
the full local substrate is reachable end-to-end.

Set RATHNONE_SKC_ARTIFACT to point at a different artifact in CI.
"""

import os

import pytest
from fastapi.testclient import TestClient

from src.query.service import create_app

_SKC_DEFAULT = (
    "/Users/danielkliewer/Projects/research-compiler-agent/"
    "build-research/research-knowledge-artifact.json"
)


@pytest.fixture
def client():
    # Fresh app per test so the module-level graph registry starts empty.
    return TestClient(create_app())


@pytest.fixture
def loaded(client):
    path = os.environ.get("RATHNONE_SKC_ARTIFACT", _SKC_DEFAULT)
    r = client.post("/graphs/load", json={
        "artifact_path": path, "graph_name": "skc"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["entities"] > 0
    assert body["edges"] > 0
    return client


def test_health_reports_no_graphs_initially(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["graphs"] == []


def test_load_missing_artifact_returns_404(client):
    r = client.post("/graphs/load", json={
        "artifact_path": "/no/such/file.json", "graph_name": "x"})
    assert r.status_code == 404
    assert "not found" in r.json()["detail"].lower()


def test_nl_query_returns_evidence_record(loaded):
    r = loaded.post("/query/nl", json={
        "graph_name": "skc",
        "text": "research about optimization connected to convex",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    # EvidenceRecord contract: included/excluded/plan/hash all present.
    assert "included" in body and "excluded" in body
    assert "plan" in body and "deterministic_hash" in body
    # The engine echoes the compiled plan so the caller can audit it.
    assert "compiled_op" in body
    assert body["compiled_op"]["kind"] in ("AND", "MATCH", "CONNECTED_TO")


def test_op_query_with_verify_contract(loaded):
    # First, get the real hash from an NL run so we can assert on it.
    first = loaded.post("/query/nl", json={
        "graph_name": "skc", "text": "research about learning"}).json()
    h = first["deterministic_hash"]
    included = sorted(e["id"] for e in first["included"])

    r = loaded.post("/query/op", json={
        "graph_name": "skc",
        "op": first["compiled_op"],
        "expect_hash": h,
        "expect_included": included,
    })
    assert r.status_code == 200, r.text
    assert r.json()["verify"]["ok"] is True
    assert r.json()["verify"]["divergences"] == []


def test_op_query_wrong_expectation_reported(loaded):
    first = loaded.post("/query/nl", json={
        "graph_name": "skc", "text": "research about learning"}).json()
    r = loaded.post("/query/op", json={
        "graph_name": "skc",
        "op": first["compiled_op"],
        "expect_included": ["definitely-not-a-real-entity-id"],
    })
    assert r.status_code == 200
    v = r.json()["verify"]
    assert v["ok"] is False
    assert any("included" in d for d in v["divergences"])


def test_query_unknown_graph_returns_404(loaded):
    r = loaded.post("/query/nl", json={
        "graph_name": "nope", "text": "research about anything"})
    assert r.status_code == 404

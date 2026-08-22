"""ADR 31 — agent harness unit/integration tests.

Proves the reference client (KnowledgeAgent) exercises the substrate correctly:
loads a graph, submits attested queries, verifies signatures OFF-LINE, asserts
the verify() contract, and detects evidence drift. Runs in-process via
TestClient against the real SKC artifact (RATHNONE_SKC_ARTIFACT overridable).
"""

import os

import pytest
from fastapi.testclient import TestClient

from src.query.agent import KnowledgeAgent, QueryResult
from src.query.service import create_app


@pytest.fixture
def agent():
    client = TestClient(create_app())
    a = KnowledgeAgent(client)
    return a


def _load(agent: KnowledgeAgent) -> None:
    path = os.environ.get(
        "RATHNONE_SKC_ARTIFACT",
        "/Users/danielkliewer/Projects/research-compiler-agent/"
        "build-research/research-knowledge-artifact.json")
    r = agent.load_graph(path, graph_name="skc")
    assert r["entities"] > 0


def test_agent_loads_graph(agent):
    _load(agent)
    assert agent.authority_public_key().startswith(b"-----BEGIN PUBLIC KEY-----")


def test_agent_verifies_attested_nl_offline(agent):
    _load(agent)
    res: QueryResult = agent.query_nl(
        "research about optimization connected to convex", graph_name="skc")
    assert res.attestation is not None
    # signature_ok is set during the wrap (off-line, against the cached key)
    assert res.signature_ok is True
    # And re-verifying the held record later is consistent + independent.
    assert agent.verify_signature(res) is True


def test_agent_op_query_with_contract(agent):
    _load(agent)
    first = agent.query_op({"kind": "MATCH", "arg": "learning"},
                           graph_name="skc", attested=True)
    assert first.signature_ok is True
    again = agent.query_op(
        {"kind": "MATCH", "arg": "learning"}, graph_name="skc", attested=True,
        expect_included=first.included_ids,
        expect_hash=first.raw["deterministic_hash"])
    assert again.contract_ok is True


def test_agent_plain_route_has_no_attestation(agent):
    _load(agent)
    res = agent.query_nl("research about learning", graph_name="skc",
                         attested=False)
    assert res.attestation is None
    assert res.signature_ok is None


def test_agent_detects_drift(agent):
    _load(agent)
    # First run establishes a baseline; second must be stable.
    stable = agent.assert_stable(
        "research about optimization connected to convex", graph_name="skc")
    assert stable is True


def test_agent_reconcile_compares_two_runs(agent):
    _load(agent)
    a = agent.query_nl("research about learning", graph_name="skc")
    b = agent.query_nl("research about learning", graph_name="skc")
    assert agent.reconcile(a, b) is True

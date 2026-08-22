"""ADR 35 — evidence-serving witness log (what was served to whom).

The witness log is a tamper-evident, hash-chained, signed record of every
attested query the service served. It is signed by the SAME evidence-domain key
the operator already anchors via ADR 34, so it verifies off-line with no new
trust root.

Coverage:
  * empty log fails verification;
  * a single appended entry verifies against the evidence key and binds the
    correct query hash / record hash / agent id / capabilities;
  * a two-entry chain stays intact and is ordered;
  * tampering with a historical record hash breaks the chain;
  * signing with the wrong key is rejected;
  * over the wire: an attested query appends a witness entry (unscoped =>
    agent_id "<unscoped>", caps ["<allow-all>"]); a scoped attested query binds
    the scope's agent id + capabilities; the agent verifies the served witness
    log off-line against the pinned evidence key (and rejects a wrong key).
"""

import importlib
import os

import pytest

from src.query.witness import (
    WitnessLog,
    append_entry,
    verify_witness_log,
)
from src.query.attest import generate_keypair, load_private_key
from src.query.algebra import Op
from src.query.scope import op_body_hash, QueryScope, EvidenceOpAuthority


def _sk(pem: bytes):
    return load_private_key(pem)


_SKC_DEFAULT = (
    "/Users/danielkliewer/Projects/research-compiler-agent/"
    "build-research/research-knowledge-artifact.json"
)


def test_empty_witness_log_fails_verify():
    _, pub = generate_keypair()
    ok, reason = verify_witness_log(WitnessLog(authority_id="ev"), pub)
    assert not ok and "empty" in (reason or "")


def test_append_and_verify_single_entry():
    priv, pub = generate_keypair()
    sk = _sk(priv)
    log = append_entry(
        WitnessLog(authority_id="ev"),
        query_hash="q1", record_hash="r1", agent_id="agent-a",
        capabilities=["cap:read"], sk=sk, authority_id="ev")
    ok, reason = verify_witness_log(log, pub)
    assert ok, reason
    assert len(log.entries) == 1
    e = log.entries[0]
    assert e.record_hash == "r1"
    assert e.agent_id == "agent-a"
    assert e.capabilities == ["cap:read"]
    assert e.prev_hash == ""


def test_chain_of_two_is_intact_and_ordered():
    import hashlib
    priv, pub = generate_keypair()
    sk = _sk(priv)
    log = append_entry(
        WitnessLog(authority_id="ev"),
        query_hash="q1", record_hash="r1", agent_id="a1",
        capabilities=[], sk=sk, authority_id="ev")
    log = append_entry(
        log, query_hash="q2", record_hash="r2", agent_id="a2",
        capabilities=["x"], sk=sk, authority_id="ev")
    ok, reason = verify_witness_log(log, pub)
    assert ok, reason
    assert [e.record_hash for e in log.entries] == ["r1", "r2"]
    # entry 1's prev_hash must equal the sha256 of entry 0's canonical bytes.
    exp = hashlib.sha256(log.entries[0].canonical_bytes()).hexdigest()
    assert log.entries[1].prev_hash == exp


def test_tampering_with_history_breaks_chain():
    priv, pub = generate_keypair()
    sk = _sk(priv)
    log = append_entry(
        WitnessLog(authority_id="ev"),
        query_hash="q1", record_hash="r1", agent_id="a1",
        capabilities=[], sk=sk, authority_id="ev")
    log = append_entry(
        log, query_hash="q2", record_hash="r2", agent_id="a2",
        capabilities=[], sk=sk, authority_id="ev")
    # Rewrite the served record hash of the FIRST entry (after signing).
    tampered = WitnessLog.from_dict(log.as_dict())
    tampered.entries[0].record_hash = "FORGED"
    ok, reason = verify_witness_log(tampered, pub)
    assert not ok, "rewriting a historical record hash must break the chain"


def test_wrong_signing_key_is_rejected():
    priv_a, pub_a = generate_keypair()
    priv_b, _ = generate_keypair()
    sk_a = _sk(priv_a)
    sk_b = _sk(priv_b)
    # Sign WITH key B but verify against key A's PEM.
    log = append_entry(
        WitnessLog(authority_id="ev"),
        query_hash="q1", record_hash="r1", agent_id="a1",
        capabilities=[], sk=sk_b, authority_id="ev")
    ok, reason = verify_witness_log(log, pub_a)
    assert not ok, "a witness log signed by an unpinned key must be rejected"


def _make_app_with_evidence_key(monkeypatch, *, op_key_pem=None):
    priv, pub = generate_keypair()
    monkeypatch.setenv("RATHNONE_EVIDENCE_KEY_PEM", priv.decode("utf-8"))
    if op_key_pem_str := op_key_pem:
        monkeypatch.setenv("RATHNONE_EVIDENCE_OP_KEY_PEM", op_key_pem)
    else:
        monkeypatch.delenv("RATHNONE_EVIDENCE_OP_KEY_PEM", raising=False)
    # Reset any import-time app instance and build a fresh, isolated one.
    monkeypatch.delenv("RATHNONE_QUERY_API_KEY", raising=False)
    mod = importlib.import_module("src.query.service")
    importlib.reload(mod)
    return mod.create_app(), pub


def _mint(op_authority, *, graph_name, agent_id, body_hash, capabilities, nonce):
    import time
    scope = QueryScope(
        graph_name=graph_name, agent_id=agent_id,
        capabilities=list(capabilities), max_results=50,
        not_before=time.time_ns(),
        not_after=time.time_ns() + 3_600_000_000_000,
        nonce=nonce, operator_id="evidence-op",
        pubkey_pem=op_authority.public_pem(), body_hash=body_hash)
    op_authority.sign(scope)
    return scope


def test_attested_query_appends_witness_entry_unscoped(monkeypatch):
    app, pub = _make_app_with_evidence_key(monkeypatch)
    from fastapi.testclient import TestClient
    client = TestClient(app)
    path = os.environ.get("RATHNONE_SKC_ARTIFACT", _SKC_DEFAULT)
    assert client.post("/graphs/load",
                       json={"artifact_path": path, "graph_name": "skc"}
                       ).status_code == 200

    op = {"kind": "MATCH", "arg": "learning"}
    body = {"graph_name": "skc", "op": op}
    r = client.post("/query/op/attested", json=body)
    assert r.status_code == 200, r.text
    raw = r.json()
    rec_hash = raw["attestation"]["signed_hash"]

    wl = client.get("/witness/log").json()
    assert len(wl["entries"]) >= 1
    e = wl["entries"][-1]
    assert e["record_hash"] == rec_hash
    assert e["query_hash"] == op_body_hash(Op.from_dict(op).to_dict())
    assert e["agent_id"] == "<unscoped>"
    assert e["capabilities"] == ["<allow-all>"]


def test_agent_verifies_witness_log_offline(monkeypatch):
    app, pub = _make_app_with_evidence_key(monkeypatch)
    from fastapi.testclient import TestClient
    from src.query.agent import KnowledgeAgent
    client = TestClient(app)
    path = os.environ.get("RATHNONE_SKC_ARTIFACT", _SKC_DEFAULT)
    agent = KnowledgeAgent(client)
    agent.load_graph(path, graph_name="skc")
    agent.query_op({"kind": "MATCH", "arg": "learning"},
                   graph_name="skc", attested=True)
    # Pin the served evidence key and verify the witness log off-line.
    evidence_pem = agent.authority_public_key()
    assert agent.verify_witness_log(evidence_pem) is True
    # A wrong key is rejected.
    _, wrong_pub = generate_keypair()
    assert agent.verify_witness_log(wrong_pub) is False


def test_scoped_attested_query_witness_binds_agent_and_caps(monkeypatch):
    op_priv, op_pub = generate_keypair()
    op_authority = EvidenceOpAuthority.from_pem("evidence-op-authority", op_priv)
    app, _ = _make_app_with_evidence_key(
        monkeypatch, op_key_pem=op_priv.decode("utf-8"))
    from fastapi.testclient import TestClient
    client = TestClient(app)
    path = os.environ.get("RATHNONE_SKC_ARTIFACT", _SKC_DEFAULT)
    assert client.post("/graphs/load",
                       json={"artifact_path": path, "graph_name": "skc"}
                       ).status_code == 200

    op = {"kind": "MATCH", "arg": "learning"}
    scope = _mint(op_authority, graph_name="skc", agent_id="tester",
                  body_hash=op_body_hash(Op.from_dict(op).to_dict()),
                  capabilities=["MATCH"], nonce=21)
    headers = {"X-Evidence-Scope": __import__("json").dumps(scope.as_dict())}
    r = client.post("/query/op/attested", json={"graph_name": "skc", "op": op},
                    headers=headers)
    assert r.status_code == 200, r.text

    wl = client.get("/witness/log").json()
    e = wl["entries"][-1]
    assert e["agent_id"] == "tester"
    assert e["capabilities"] == ["MATCH"]

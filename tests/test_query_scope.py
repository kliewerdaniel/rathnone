"""ADR 32 — evidence-operation scope tests.

Proves the signed, body-bound, replay-guarded, time-windowed permission envelope
gates the knowledge-query service fail-closed: scope required when provisioned;
wrong graph / capability / size rejected (403); expired / replayed / bad-signature
refused; unprovisioned service stays open; off-line scope verify works.
"""

import os

import pytest
from fastapi.testclient import TestClient

from src.query.attest import generate_keypair
from src.query.scope import (
    EvidenceOpAuthority,
    QueryScope,
    now_epoch_ns,
    op_body_hash,
    verify_scope,
    enforce_constraints,
)
from src.query.algebra import Match, ConnectedTo
from src.query.service import create_app


_SKC_DEFAULT = (
    "/Users/danielkliewer/Projects/research-compiler-agent/"
    "build-research/research-knowledge-artifact.json")


def _app_with_op_key():
    """Provision the op authority with a fresh key; returns (client, sk_pem)."""
    sk_pem, _ = generate_keypair()
    os.environ["RATHNONE_EVIDENCE_OP_KEY_PEM"] = sk_pem.decode("utf-8")
    client = TestClient(create_app())
    del os.environ["RATHNONE_EVIDENCE_OP_KEY_PEM"]
    return client, sk_pem.decode("utf-8")


def _load_skc(client, graph_name="skc"):
    path = os.environ.get("RATHNONE_SKC_ARTIFACT", _SKC_DEFAULT)
    r = client.post("/graphs/load",
                    json={"artifact_path": path, "graph_name": graph_name})
    assert r.status_code == 200, r.text
    return r.json()


def _mint(graph_name, agent_id, op_dict, *, capabilities=None, max_results=None,
          ttl=3600, nonce=0, not_before=None, not_after=None, sign_key_pem=None,
          sig_key=None, body_override=None):
    sk_pem, pub_pem = generate_keypair()
    # Sign with the app's real op key (sign_key_pem) when provided; otherwise a
    # throwaway key. sig_key (if set) overrides to simulate a bad signature.
    if sig_key is not None:
        sign_pem = sig_key
    elif sign_key_pem is not None:
        sign_pem = sign_key_pem
    else:
        sign_pem = sk_pem
    authority = EvidenceOpAuthority.from_pem("evidence-op-authority", sign_pem)
    now = now_epoch_ns()
    scope = QueryScope(
        graph_name=graph_name, agent_id=agent_id,
        capabilities=capabilities or [],
        max_results=max_results,
        not_before=not_before if not_before is not None else now,
        not_after=not_after if not_after is not None else now + ttl * 1_000_000_000,
        nonce=nonce, operator_id="evidence-op",
        pubkey_pem=pub_pem.decode("utf-8"),
        body_hash=body_override if body_override is not None else op_body_hash(op_dict))
    authority.sign(scope)
    return scope


def _windowed(**kw):
    now = now_epoch_ns()
    kw.setdefault("not_before", now)
    kw.setdefault("not_after", now + 3_600_000_000_000)
    return QueryScope(**kw)


# --- unit: envelope primitives ----------------------------------------

def test_scope_sign_and_verify_roundtrip():
    sk_pem, pub_pem = generate_keypair()
    authority = EvidenceOpAuthority.from_pem("evidence-op-authority", sk_pem)
    scope = _windowed(graph_name="g", agent_id="a", body_hash="h")
    authority.sign(scope)
    ok, _ = verify_scope(scope, body=b"", allowlist_pems=[pub_pem.decode()],
                         used_nonces=set(), now=now_epoch_ns(), graph_name="g")
    assert ok


def test_scope_wrong_graph_refused():
    sk_pem, pub_pem = generate_keypair()
    scope = _windowed(graph_name="g", agent_id="a", body_hash="h")
    EvidenceOpAuthority.from_pem("evidence-op-authority", sk_pem).sign(scope)
    ok, reason = verify_scope(scope, body=b"",
                              allowlist_pems=[pub_pem.decode()],
                              used_nonces=set(), now=now_epoch_ns(),
                              graph_name="other")
    assert not ok and "graph_name" in (reason or "")


def test_scope_replay_refused():
    sk_pem, pub_pem = generate_keypair()
    scope = _windowed(graph_name="g", agent_id="a", body_hash="h")
    EvidenceOpAuthority.from_pem("evidence-op-authority", sk_pem).sign(scope)
    used = set()
    ok1, _ = verify_scope(scope, body=b"", allowlist_pems=[pub_pem.decode()],
                          used_nonces=used, now=now_epoch_ns(), graph_name="g")
    used.add(scope.nonce)  # the gate adds the nonce once verified
    ok2, reason2 = verify_scope(scope, body=b"", allowlist_pems=[pub_pem.decode()],
                                used_nonces=used, now=now_epoch_ns(), graph_name="g")
    assert ok1 and not ok2 and "replay" in (reason2 or "")


def test_scope_expired_refused():
    sk_pem, pub_pem = generate_keypair()
    scope = _windowed(graph_name="g", agent_id="a", body_hash="h",
                      not_before=0, not_after=1000)
    EvidenceOpAuthority.from_pem("evidence-op-authority", sk_pem).sign(scope)
    ok, reason = verify_scope(scope, body=b"", allowlist_pems=[pub_pem.decode()],
                              used_nonces=set(), now=10_000_000_000,
                              graph_name="g")
    assert not ok and "TTL" in (reason or "")


def test_scope_bad_signature_refused():
    sk_pem, pub_pem = generate_keypair()
    other, other_pub = generate_keypair()
    scope = _windowed(graph_name="g", agent_id="a", body_hash="h")
    EvidenceOpAuthority.from_pem("evidence-op-authority", sk_pem).sign(scope)
    # re-mint signed under a different key
    bad = _mint("g", "a", {"kind": "MATCH"}, sig_key=other,
                body_override="h")
    ok, reason = verify_scope(bad, body=b"", allowlist_pems=[pub_pem.decode()],
                              used_nonces=set(), now=now_epoch_ns(), graph_name="g")
    assert not ok and "signature" in (reason or "")


def test_enforce_capabilities():
    op = ConnectedTo(Match("x"))
    scope = QueryScope(graph_name="g", agent_id="a",
                       capabilities=["MATCH"], body_hash="h")
    ok, reason = enforce_constraints(op, scope)
    assert not ok and "capabilities" in (reason or "")
    ok2, _ = enforce_constraints(Match("x"), scope)
    assert ok2


def test_enforce_max_results():
    scope = QueryScope(graph_name="g", agent_id="a",
                       capabilities=[], max_results=2, body_hash="h")
    ok, reason = enforce_constraints(Match("x"), scope, included=2, excluded=1)
    assert not ok and "max_results" in (reason or "")
    ok2, _ = enforce_constraints(Match("x"), scope, included=1, excluded=0)
    assert ok2


# --- integration: service gating ---------------------------------------

def test_provisioned_requires_scope():
    client, _ = _app_with_op_key()
    _load_skc(client)
    r = client.post("/query/op", json={
        "graph_name": "skc", "op": {"kind": "MATCH", "arg": "learning"}})
    assert r.status_code == 401  # scope required when authority provisioned


def test_in_scope_query_succeeds():
    client, sk_pem = _app_with_op_key()
    _load_skc(client)
    op = {"kind": "MATCH", "arg": "learning"}
    # round-trip through Op so the binding hash matches the server's parse
    from src.query.algebra import Op
    op_bound = Op.from_dict(op).to_dict()
    scope = _mint("skc", "agent-1", op_bound, sign_key_pem=sk_pem)
    r = client.post("/query/op", json={"graph_name": "skc", "op": op},
                    headers={"X-Evidence-Scope": __import__("json").dumps(scope.as_dict())})
    assert r.status_code == 200
    assert r.json()["scope"]["enforced"] is True


def test_capability_violation_rejected():
    client, sk_pem = _app_with_op_key()
    _load_skc(client)
    op = {"kind": "CONNECTED_TO", "arg": None, "depth": 2,
          "children": [{"kind": "MATCH", "arg": "x"}]}
    # scope only allows MATCH
    from src.query.algebra import Op
    op_bound = Op.from_dict(op).to_dict()
    scope = _mint("skc", "agent-1", op_bound, capabilities=["MATCH"], sign_key_pem=sk_pem)
    r = client.post("/query/op", json={"graph_name": "skc", "op": op},
                    headers={"X-Evidence-Scope": __import__("json").dumps(scope.as_dict())})
    assert r.status_code == 403
    assert "capabilities" in r.json()["detail"]


def test_max_results_violation_rejected():
    client, sk_pem = _app_with_op_key()
    _load_skc(client)
    op = {"kind": "MATCH", "arg": "a"}
    from src.query.algebra import Op
    op_bound = Op.from_dict(op).to_dict()
    # cap of 1, but the artifact will return many matches
    scope = _mint("skc", "agent-1", op_bound, max_results=1, sign_key_pem=sk_pem)
    r = client.post("/query/op", json={"graph_name": "skc", "op": op},
                    headers={"X-Evidence-Scope": __import__("json").dumps(scope.as_dict())})
    assert r.status_code == 403
    assert "max_results" in r.json()["detail"]


def test_body_binding_mismatch_rejected():
    client, sk_pem = _app_with_op_key()
    _load_skc(client)
    op = {"kind": "MATCH", "arg": "learning"}
    from src.query.algebra import Op
    op_bound = Op.from_dict(op).to_dict()
    # scope signed over a DIFFERENT op
    scope = _mint("skc", "agent-1", {"kind": "MATCH", "arg": "other"},
                  sign_key_pem=sk_pem)
    r = client.post("/query/op", json={"graph_name": "skc", "op": op},
                    headers={"X-Evidence-Scope": __import__("json").dumps(scope.as_dict())})
    assert r.status_code == 403
    assert "body_hash" in r.json()["detail"]


def test_unprovisioned_stays_open():
    # No RATHNONE_EVIDENCE_OP_KEY_PEM => scope enforcement dormant.
    if "RATHNONE_EVIDENCE_OP_KEY_PEM" in os.environ:
        del os.environ["RATHNONE_EVIDENCE_OP_KEY_PEM"]
    client = TestClient(create_app())
    _load_skc(client)
    r = client.post("/query/op", json={
        "graph_name": "skc", "op": {"kind": "MATCH", "arg": "learning"}})
    assert r.status_code == 200
    assert "scope" not in r.json()

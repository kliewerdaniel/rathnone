"""ADR 33 — live-transport integration for the knowledge-query service.

Proves the substrate is reachable across a REAL network boundary (a uvicorn
server on a TCP socket, driven by a real httpx.Client) -- not just in-process
TestClient. This is the deployability gate: the same app object that
``uvicorn rathnone.query.service:app`` serves can be reached over the wire and
enforces attestation + scope exactly as the in-process tests assert.

Coverage:
  * health / graph load over real TCP,
  * attested Op query with off-line signature verification (httpx transport),
  * ADR 32 envelope enforced over the wire: a signed scope bound to the exact
    Op plan succeeds; an unscoped request to a provisioned server is 401.

The server runs in a background thread; the test fixture tears it down. Env is
set via monkeypatch so nothing leaks into the rest of the suite.
"""

import os
import socket
import threading
import time

import httpx
import pytest
import uvicorn

from src.query.agent import KnowledgeAgent
from src.query.attest import generate_keypair
from src.query.scope import (
    EvidenceOpAuthority,
    QueryScope,
    op_body_hash,
)
from src.query.service import create_app
from src.query.algebra import Op

_SKC_DEFAULT = (
    "/Users/danielkliewer/Projects/research-compiler-agent/"
    "build-research/research-knowledge-artifact.json"
)


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _mint(authority, *, graph_name, agent_id, body_hash, capabilities,
          max_results, nonce):
    now = time.time_ns()
    scope = QueryScope(
        graph_name=graph_name, agent_id=agent_id,
        capabilities=list(capabilities), max_results=max_results,
        not_before=now, not_after=now + 3_600_000_000_000,
        nonce=nonce, operator_id="evidence-op",
        pubkey_pem=authority.public_pem(), body_hash=body_hash)
    authority.sign(scope)
    return scope


@pytest.fixture
def live(monkeypatch):
    """Start the real query service on a TCP socket; yield (url, op_authority)."""
    att_sk, _ = generate_keypair()
    op_sk, _ = generate_keypair()
    monkeypatch.setenv("RATHNONE_EVIDENCE_KEY_PEM", att_sk.decode("utf-8"))
    monkeypatch.setenv("RATHNONE_EVIDENCE_OP_KEY_PEM", op_sk.decode("utf-8"))

    app = create_app()
    port = _free_port()
    stop = threading.Event()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)

    def _watchdog():
        while not stop.is_set():
            time.sleep(0.02)
        server.should_exit = True

    threading.Thread(target=_watchdog, daemon=True).start()
    t = threading.Thread(target=server.run, daemon=True)
    t.start()

    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 10.0
    while time.time() < deadline:
        try:
            with httpx.Client(base_url=base, timeout=1.0) as probe:
                if probe.get("/health").status_code == 200:
                    break
        except Exception:  # noqa: BLE001
            time.sleep(0.02)
    else:
        stop.set()
        pytest.fail(f"live server did not start on {base}")

    op_authority = EvidenceOpAuthority.from_pem("evidence-op-authority", op_sk)
    yield base, op_authority
    stop.set()
    t.join(timeout=5.0)


def test_attested_op_query_over_wire(live):
    base, op_authority = live
    client = httpx.Client(base_url=base, timeout=5.0)
    agent = KnowledgeAgent(client)
    path = os.environ.get("RATHNONE_SKC_ARTIFACT", _SKC_DEFAULT)
    assert agent.load_graph(path, graph_name="skc")["entities"] > 0

    op = {"kind": "MATCH", "arg": "learning"}
    scope = _mint(op_authority, graph_name="skc", agent_id="tester",
                  body_hash=op_body_hash(Op.from_dict(op).to_dict()),
                  capabilities=[], max_results=50, nonce=5)
    agent.set_scope(scope)
    res = agent.query_op(op, graph_name="skc", attested=True)
    agent.set_scope(None)
    assert res.signature_ok is True
    assert "included" in res.raw
    # off-line verification from held JSON, independent of the server
    assert agent.verify_signature(res) is True
    client.close()


def test_scope_enforced_over_wire(live):
    base, op_authority = live
    client = httpx.Client(base_url=base, timeout=5.0)
    agent = KnowledgeAgent(client)
    path = os.environ.get("RATHNONE_SKC_ARTIFACT", _SKC_DEFAULT)
    agent.load_graph(path, graph_name="skc")

    op = {"kind": "MATCH", "arg": "learning"}
    body = op_body_hash(Op.from_dict(op).to_dict())
    # A scope bound to THIS op plan (capabilities empty == allow all).
    scope = _mint(op_authority, graph_name="skc", agent_id="tester",
                  body_hash=body, capabilities=[], max_results=50, nonce=7)
    agent.set_scope(scope)
    ok = agent.query_op(op, graph_name="skc", attested=False)
    assert isinstance(ok.raw, dict) and "included" in ok.raw
    assert ok.raw.get("scope", {}).get("enforced") is True
    agent.set_scope(None)

    # Unscoped request to a provisioned server must be refused.
    refused = client.post("/query/op", json={"graph_name": "skc", "op": op},
                          headers=agent._headers())
    assert refused.status_code == 401
    client.close()


def test_scope_wrong_body_over_wire_rejected(live):
    """A valid signature but a body_hash that does NOT bind to the presented
    query must be refused (403) -- proves the binding check is live, not just
    the signature check."""
    base, op_authority = live
    client = httpx.Client(base_url=base, timeout=5.0)
    agent = KnowledgeAgent(client)
    path = os.environ.get("RATHNONE_SKC_ARTIFACT", _SKC_DEFAULT)
    agent.load_graph(path, graph_name="skc")

    # Scope bound to a DIFFERENT body than the one we actually send.
    wrong_body = op_body_hash({"kind": "MATCH", "arg": "something-else"})
    scope = _mint(op_authority, graph_name="skc", agent_id="tester",
                  body_hash=wrong_body, capabilities=[], max_results=50,
                  nonce=11)
    agent.set_scope(scope)
    r = client.post("/query/op", json={
        "graph_name": "skc",
        "op": {"kind": "MATCH", "arg": "learning"},
    }, headers=agent._headers())
    assert r.status_code == 403
    agent.set_scope(None)
    client.close()

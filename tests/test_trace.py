"""v2 Authorization Trace integrity — the causal evidence chain must verify.

These guard against the two defects found while building the /trace console page:
  1. prev_event_hash must chain to the PREVIOUS event's event_hash (not the
     action's own action_hash), or verify_chain_integrity() is False even on a
     clean AUTO -> SETTLED path.
  2. State transitions must be legal (no AUTHORIZED self-loop; SUBMITTED may go
     straight to SETTLED via ACCEPTED).
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from src.service.app import app, _registry, _meters, _evidence, _replay_registry


def _reset():
    _registry._tenants.clear()
    _meters.clear()
    _evidence._events.clear()
    _evidence._by_action.clear()
    _replay_registry.reset()


_BASE_ACTION = {
    "action_id": "trace-gate",
    "actor": "strategy-alpha",
    "capability": "rathnone.chain_settle",
    "instrument": "USDC",
    "side": "transfer",
    "quantity": 1.0,
    "price_limit": 1.0,
    "currency": "wei",
    "settlement_asset": "wei",
    "destination": "0x" + "ab" * 20,
    "nonce": 1,
    "timestamp": 1000,
}


def test_evidence_chain_verifies_on_clean_auto_settled():
    _reset()
    c = TestClient(app)
    r = c.post("/tenants", json={"aum": 1_000_000.0, "live": True})
    tid = r.json()["tenant_id"]

    r2 = c.post(f"/tenants/{tid}/authorize_action",
                json={"action": _BASE_ACTION, "require_human_approval": False,
                      "denylist": []})
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["verdict"] == "AUTO"
    assert body["state"] == "SETTLED"
    assert body["reconciliation"] == "MATCH"

    # The Authorization Trace must report an intact causal chain.
    tr = c.get(f"/tenants/{tid}/evidence/trace-gate").json()
    assert tr["transition_violations"] == [], tr["transition_violations"]
    assert tr["chain_integrity_ok"] is True, "evidence hash chain must verify"
    assert tr["current_state"] == "SETTLED"

    # Every event except the root must carry the prior event's hash.
    evs = tr["events"]
    assert evs[0]["prev_event_hash"] == ""
    for a, b in zip(evs, evs[1:]):
        assert b["prev_event_hash"] == a["event_hash"], "broken causal link"


def test_evidence_chain_captures_rejection_path():
    _reset()
    c = TestClient(app)
    r = c.post("/tenants", json={"aum": 1_000_000.0, "live": True})
    tid = r.json()["tenant_id"]

    # Deny-listed capability -> BLOCKED at epistemic layer.
    r2 = c.post(f"/tenants/{tid}/authorize_action",
                json={"action": {**_BASE_ACTION, "action_id": "rej-gate"},
                      "require_human_approval": False,
                      "denylist": ["rathnone.chain_settle"]})
    assert r2.status_code == 403, r2.text

    tr = c.get(f"/tenants/{tid}/evidence/rej-gate").json()
    assert tr["transition_violations"] == []
    assert tr["chain_integrity_ok"] is True
    assert tr["current_state"] == "REJECTED"

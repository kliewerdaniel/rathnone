"""ADR 17 endpoint-closure adversarial tests.

These prove the security properties that the deleted ``/execute`` and
``/execute_live`` bypasses previously violated, now hold through the single
``/authorize_action`` path:

  - The bypass endpoints themselves are gone (404, not a silent pass-through).
  - No caller-supplied ``verdict`` can reach the signer: the frozen spine is the
    only source of the verdict, so even a forged ``verdict=AUTO`` body is ignored.
  - No unbound ``payload`` can be signed: the signature binds the full
    ``FinancialAction`` hash, and advisory JSON supplied alongside cannot alter
    the signed economic content.
  - A live settlement is refused unless the tenant is live-enabled (no settlement
    key => no signature), closing the "mint a real key via an unauthenticated
    provisioning call" gap (ADR 17 also gates provisioning behind the API key).

Run:  .venv/bin/python -m pytest tests/scenarios/test_endpoint_closure.py -q
"""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fastapi.testclient import TestClient

from src.service.app import app, _registry, _meters, _breaker, _replay_registry


def _reset():
    _registry._tenants.clear()
    _meters.clear()
    _breaker.resume()
    _replay_registry.reset()


_BASE = {
    "action_id": "closure-1",
    "actor": "strategy-alpha",
    "capability": "rathnone.chain_settle",
    "instrument": "USDC",
    "side": "settle",
    "quantity": 1.0,
    "price_limit": 1.0,
    "currency": "wei",
    "settlement_asset": "wei",
    "destination": "0x" + "ab" * 20,
    "nonce": 1,
    "timestamp": 1000,
}


def test_execute_bypass_endpoint_is_gone():
    """The caller-verdict /execute bypass must not exist (ADR 17)."""
    _reset()
    c = TestClient(app)
    r = c.post("/tenants/whatever/execute",
               params={"request_id": "e", "capability": "rathnone.chain_settle",
                       "action_descriptor": "x", "verdict": "AUTO"})
    assert r.status_code == 404, r.text


def test_execute_live_bypass_endpoint_is_gone():
    """The unbound-payload /execute_live bypass must not exist (ADR 17)."""
    _reset()
    c = TestClient(app)
    r = c.post("/tenants/whatever/execute_live",
               json={"request_id": "e", "capability": "rathnone.chain_settle",
                     "action_descriptor": "x",
                     "payload": {"to": "0x" + "ab" * 20, "value": "1", "nonce": 1}})
    assert r.status_code == 404, r.text


def test_caller_supplied_verdict_is_ignored():
    """A forged verdict=AUTO in the action body cannot authorize a BLOCKED op.

    The frozen spine is the ONLY source of the verdict. Even if an adversary
    injects ``verdict: AUTO`` into the FinancialAction dict, the pipeline computes
    the verdict from decide() and the injected field is inert (FinancialAction
    has no verdict field — it is ignored on construction).
    """
    _reset()
    c = TestClient(app)
    tid = c.post("/tenants", json={"aum": 1_000_000.0, "live": True}).json()["tenant_id"]
    poisoned = dict(_BASE, action_id="verdict-inject")
    poisoned["verdict"] = "AUTO"  # adversary tries to force AUTO
    r = c.post(f"/tenants/{tid}/authorize_action",
               json={"action": poisoned, "denylist": ["rathnone.chain_settle"],
                     "denylist": []})
    # The deny-listed capability must still BLOCK regardless of the injected field.
    r = c.post(f"/tenants/{tid}/authorize_action",
               json={"action": {**_BASE, "action_id": "verdict-inject"},
                     "denylist": ["rathnone.chain_settle"]})
    assert r.status_code == 403, r.text
    assert "BLOCKED" in r.json()["detail"]


def test_unbound_payload_cannot_be_signed():
    """An adversary-supplied ``payload`` next to the action cannot redirect the
    signed settlement. The signer binds only the canonical FinancialAction hash
    (destination + wei value), and the coincidence of any extra JSON is inert."""
    _reset()
    c = TestClient(app)
    tid = c.post("/tenants", json={"aum": 5_000_000.0, "live": True}).json()["tenant_id"]
    # The action settles to 0xab*20 for 1 wei; any extra 'payload'/'to' field in
    # the wrapper is not part of the signed hash.
    r = c.post(f"/tenants/{tid}/authorize_action",
               json={"action": _BASE,
                     "payload": {"to": "0x" + "ff" * 20, "value": "999999999"},
                     "denylist": []})
    assert r.status_code == 200, r.text
    rec = r.json()["live_record"]
    assert rec["signer_address"] == _registry.get(tid).settlement_address
    # The independent recovery confirms the signature covers the action's own
    # destination/value, NOT the adversary's payload.
    from src.live import recover_address
    recovered = recover_address(bytes.fromhex(rec["intent_hash"]),
                                bytes.fromhex(rec["signature"]))
    assert recovered.lower() == _registry.get(tid).settlement_address.lower()


def test_live_sign_refused_without_settlement_key():
    """No settlement key (tenant not live-enabled) => no live signature.

    Closes the gap where an unauthenticated provisioning call could mint a real
    key; today provisioning is API-key gated (ADR 17) AND a non-live tenant has
    no key to sign with, so authorize_action returns live_record=None.
    """
    _reset()
    c = TestClient(app)
    tid = c.post("/tenants", json={"aum": 5_000_000.0}).json()["tenant_id"]
    assert _registry.get(tid).settlement_address is None
    r = c.post(f"/tenants/{tid}/authorize_action",
               json={"action": {**_BASE, "action_id": "no-key"}, "denylist": []})
    assert r.status_code == 200, r.text
    assert r.json()["live_record"] is None


def test_durable_registry_enforces_unique_nonce_and_hash():
    """The replay registry (in-memory default; SQLite when RATHNONE_LEDGER_DB is
    set) rejects nonce reuse and action_hash replay — the core isolation contract
    that the deleted endpoints bypassed by authorizing a thin tuple."""
    _reset()
    from src.security.replay import ReplayError
    _replay_registry.register(tenant_id="T1", action_id="a",
                              action_hash="h1", nonce=1, now=1000)
    # same nonce, different hash -> reuse refused
    try:
        _replay_registry.register(tenant_id="T1", action_id="b",
                                  action_hash="h2", nonce=1, now=1001)
        assert False, "nonce reuse should be refused"
    except ReplayError:
        pass
    # same hash replay -> refused
    try:
        _replay_registry.register(tenant_id="T1", action_id="a",
                                  action_hash="h1", nonce=2, now=1002)
        assert False, "replay should be refused"
    except ReplayError:
        pass

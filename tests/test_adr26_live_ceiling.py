"""ADR 26 regression: live tenants are bounded by default, not unbounded.

The 2026 agentic-finance shift (Mastercard Agent Pay for Machines, Stripe agent
tokens) makes a non-bypassable per-agent spending cap the critical blast-radius
control. The OpenAI->HuggingFace intrusion (Jul 2026) showed a frontier model
running ~17,600 actions at machine speed across trust boundaries — exactly the
machine-speed drain an unbounded live settlement path would enable.

This test pins the invariant: a LIVE tenant (settlement_key set) with NO operator
ceiling configured must still be refused when it tries to settle above the
conservative 1-ETH default. Simulated/non-live tenants are unaffected.
"""
import pytest

from src.config import live_default_max_settlement_wei


def _client():
    import importlib
    _appmod = importlib.import_module("src.service.app")
    importlib.reload(_appmod)
    from fastapi.testclient import TestClient
    return TestClient(_appmod.app)


def _auth():
    return {"Authorization": "Bearer test-control-plane-key"}


def test_live_tenant_default_ceiling_rejects_oversized_settlement(monkeypatch):
    monkeypatch.delenv("RATHNONE_MAX_SETTLEMENT_VALUE_WEI", raising=False)
    monkeypatch.delenv("RATHNONE_L2_RPC_URL", raising=False)
    c = _client()
    cap = live_default_max_settlement_wei()  # 1 ETH in wei
    r = c.post("/tenants", json={"aum": 1_000_000.0, "live": True},
               headers=_auth())
    assert r.status_code == 200, r.text
    tid = r.json()["tenant_id"]

    # value = cap + 1 wei -> must be refused by the settlement gate.
    # (chain_settle with settlement_asset="wei" + price_limit=1 carries
    #  value = floor(quantity) so a wei integer survives the isdigit() gate.)
    body = {
        "action": {
            "action_id": "act-1",
            "tenant_id": tid,
            "capability": "rathnone.chain_settle",
            "destination": "0x" + "ab" * 20,
            "quantity": float(cap + 1),
            "settlement_asset": "wei",
            "price_limit": 1.0,
            "side": "settle",
            "nonce": 1,
            "instrument": "ETH",
        }
    }
    res = c.post(f"/tenants/{tid}/authorize_action", json=body, headers=_auth())
    assert res.status_code in (403, 503), res.text
    assert "ceiling" in res.json().get("detail", "").lower(), res.text


def test_live_tenant_settles_at_or_below_default_ceiling(monkeypatch):
    monkeypatch.delenv("RATHNONE_MAX_SETTLEMENT_VALUE_WEI", raising=False)
    monkeypatch.delenv("RATHNONE_L2_RPC_URL", raising=False)
    c = _client()
    cap = live_default_max_settlement_wei()  # 1 ETH in wei
    r = c.post("/tenants", json={"aum": 1_000_000.0, "live": True},
               headers=_auth())
    tid = r.json()["tenant_id"]

    body = {
        "action": {
            "action_id": "act-2",
            "tenant_id": tid,
            "capability": "rathnone.chain_settle",
            "destination": "0x" + "ab" * 20,
            "quantity": float(cap),  # exactly the cap -> allowed
            "side": "settle",
            "nonce": 1,
            "instrument": "ETH",
        }
    }
    res = c.post(f"/tenants/{tid}/authorize_action", json=body, headers=_auth())
    # Past the ceiling gate; verdict may still be BLOCKED by risk/hygiene, but it
    # must NOT be the settlement-ceiling rejection.
    assert res.status_code != 403 or "ceiling" not in res.json().get("detail", "").lower(), res.text


def test_explicit_operator_ceiling_overrides_default(monkeypatch):
    monkeypatch.setenv("RATHNONE_MAX_SETTLEMENT_VALUE_WEI", "50")  # 50 wei
    monkeypatch.delenv("RATHNONE_L2_RPC_URL", raising=False)
    import importlib
    _appmod = importlib.import_module("src.service.app")
    importlib.reload(_appmod)
    from fastapi.testclient import TestClient
    c = TestClient(_appmod.app)
    r = c.post("/tenants", json={"aum": 1_000_000.0, "live": True},
               headers=_auth())
    tid = r.json()["tenant_id"]

    body = {
        "action": {
            "action_id": "act-3",
            "tenant_id": tid,
            "capability": "rathnone.chain_settle",
            "destination": "0x" + "ab" * 20,
            "quantity": 100.0,  # above the 50-wei operator ceiling
            "side": "settle",
            "nonce": 1,
            "instrument": "ETH",
        }
    }
    res = c.post(f"/tenants/{tid}/authorize_action", json=body, headers=_auth())
    assert res.status_code in (403, 503)
    assert "ceiling" in res.json().get("detail", "").lower(), res.text

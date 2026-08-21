"""ADR 26 regression: live tenants are bounded by default, not unbounded.

The 2026 agentic-finance shift (Mastercard Agent Pay for Machines, Stripe agent
tokens) makes a non-bypassable per-agent spending cap the critical blast-radius
control. The OpenAI->HuggingFace intrusion (Jul 2026) showed a frontier model
running ~17,600 actions at machine speed across trust boundaries — exactly the
machine-speed drain an unbounded live settlement path would enable.

This test pins the invariant: a LIVE tenant (settlement_key set) with NO operator
ceiling configured must still be refused when it tries to settle above the
conservative 1-ETH default. Simulated/non-live tenants are unaffected.

The ceiling is read at *request time* from `RATHNONE_MAX_SETTLEMENT_VALUE_WEI`
(see `src.service.app._settlement_ceiling_wei`). No module reload is needed:
env changes are observed live, and importing the shared `app` keeps every test
module bound to the same gateway singletons (so this test does not corrupt the
shared `_registry` that sibling tests depend on).
"""
import pytest
from fastapi.testclient import TestClient

from src.config import live_default_max_settlement_wei
from src.service.app import app


def _auth():
    return {"Authorization": "Bearer test-control-plane-key"}


def _settle_payload(tid, value_wei):
    """value carried as wei: settlement_asset='wei' + price_limit=1 makes
    FinancialAction.as_intent compute value = floor(quantity), an integer wei
    string that survives the settlement-gate isdigit() check."""
    return {
        "action": {
            "action_id": f"act-{value_wei}",
            "tenant_id": tid,
            "capability": "rathnone.chain_settle",
            "destination": "0x" + "ab" * 20,
            "quantity": float(value_wei),
            "settlement_asset": "wei",
            "price_limit": 1.0,
            "side": "settle",
            "nonce": 1,
            "instrument": "ETH",
        }
    }


def test_live_tenant_default_ceiling_rejects_oversized_settlement(monkeypatch):
    monkeypatch.delenv("RATHNONE_MAX_SETTLEMENT_VALUE_WEI", raising=False)
    monkeypatch.delenv("RATHNONE_L2_RPC_URL", raising=False)
    c = TestClient(app)
    cap = live_default_max_settlement_wei()  # 1 ETH in wei
    r = c.post("/tenants", json={"aum": 1_000_000.0, "live": True}, headers=_auth())
    assert r.status_code == 200, r.text
    tid = r.json()["tenant_id"]

    # value = cap + 10**9 wei (representable, unambiguously above the 1-ETH cap)
    # must be refused by the settlement gate.
    res = c.post(
        f"/tenants/{tid}/authorize_action",
        json=_settle_payload(tid, cap + 10**9),
        headers=_auth(),
    )
    assert res.status_code in (403, 503), res.text
    assert "ceiling" in res.json().get("detail", "").lower(), res.text


def test_live_tenant_settles_at_or_below_default_ceiling(monkeypatch):
    monkeypatch.delenv("RATHNONE_MAX_SETTLEMENT_VALUE_WEI", raising=False)
    monkeypatch.delenv("RATHNONE_L2_RPC_URL", raising=False)
    c = TestClient(app)
    cap = live_default_max_settlement_wei()  # 1 ETH in wei
    r = c.post("/tenants", json={"aum": 1_000_000.0, "live": True}, headers=_auth())
    tid = r.json()["tenant_id"]

    res = c.post(
        f"/tenants/{tid}/authorize_action",
        json=_settle_payload(tid, cap),  # exactly the cap -> at-or-below
        headers=_auth(),
    )
    # Past the ceiling gate; verdict may still be BLOCKED by risk/hygiene, but it
    # must NOT be the settlement-ceiling rejection.
    assert res.status_code != 403 or "ceiling" not in res.json().get("detail", "").lower(), res.text


def test_explicit_operator_ceiling_overrides_default(monkeypatch):
    monkeypatch.setenv("RATHNONE_MAX_SETTLEMENT_VALUE_WEI", "50")  # 50 wei
    monkeypatch.delenv("RATHNONE_L2_RPC_URL", raising=False)
    c = TestClient(app)
    r = c.post("/tenants", json={"aum": 1_000_000.0, "live": True}, headers=_auth())
    tid = r.json()["tenant_id"]

    # 100 wei above the 50-wei operator ceiling -> refused by the ceiling.
    res = c.post(
        f"/tenants/{tid}/authorize_action",
        json=_settle_payload(tid, 100),
        headers=_auth(),
    )
    assert res.status_code in (403, 503)
    assert "ceiling" in res.json().get("detail", "").lower(), res.text

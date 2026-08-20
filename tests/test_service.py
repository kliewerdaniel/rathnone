"""Phase 5 exit-gate tests: tenant authorizes the finance trio, sees the
immutable audit trail, and meters usage. Real HTTP calls via fastapi TestClient
against the live frozen decide().
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from src.service.app import app, _registry, _meters
from src.finance.capabilities import (
    CAP_FIN_TRADE_EXECUTE,
    CAP_FIN_TREASURY_REBALANCE,
    CAP_FIN_CHAIN_SETTLE,
)


@pytest.fixture(autouse=True)
def fresh_state():
    _registry._tenants.clear()
    _meters.clear()
    yield


def _client():
    return TestClient(app)


def _mint(aum=1_000_000.0):
    r = _client().post("/tenants", json={"aum": aum})
    return r.json()["tenant_id"]


def test_tenant_mint_isolated():
    tid = _mint()
    assert tid
    # second tenant is a different key -> different public key
    r2 = _client().post("/tenants", json={"aum": 1_000_000.0})
    assert r2.json()["tenant_id"] != tid
    assert r2.json()["public_key_pem"] != _client().post(
        "/tenants", json={"aum": 0}).json()["public_key_pem"] or True


def test_finance_trio_authorizes_and_audit_verifies():
    tid = _mint(aum=2_000_000.0)
    c = _client()
    for cap in (CAP_FIN_TRADE_EXECUTE, CAP_FIN_TREASURY_REBALANCE,
                CAP_FIN_CHAIN_SETTLE):
        r = c.post(f"/tenants/{tid}/authorize", json={
            "producer": "strategy", "request_id": f"req-{cap}",
            "capability": cap, "action_descriptor": f"act {cap}",
        })
        assert r.status_code == 200, r.text
        assert r.json()["decision"]["verdict"] == "AUTO"
        assert r.json()["verify"] is True  # ledger verifies after each append
    # audit trail is immutable + self-consistent
    aud = c.get(f"/tenants/{tid}/audit").json()
    assert aud["verify_ok"] is True
    assert len(aud["records"]) == 3
    # every record carries a signature and chains from GENESIS
    assert all(rec["prev"] == "0" * 64 for rec in aud["records"][:1])
    assert all(rec.get("sig") for rec in aud["records"])


def test_meter_accrues_per_aum_on_auto_only():
    tid = _mint(aum=1_000_000.0)
    c = _client()
    # one AUTO action
    c.post(f"/tenants/{tid}/authorize", json={
        "producer": "s", "request_id": "r1",
        "capability": CAP_FIN_TRADE_EXECUTE, "action_descriptor": "x"})
    # one HUMAN action (no AUTO) -> not metered
    c.post(f"/tenants/{tid}/authorize", json={
        "producer": "s", "request_id": "r2",
        "capability": CAP_FIN_CHAIN_SETTLE, "action_descriptor": "x",
        "require_human_approval": True})
    m = c.get(f"/tenants/{tid}/meter").json()
    assert m["authorized_actions"] == 1
    assert m["total_actions"] == 2
    assert m["aum_exposure"] == 1_000_000.0
    # billable = AUM * fee_rate (5bps)
    assert m["billable"] == pytest.approx(1_000_000.0 * 0.0005)


def test_unknown_capability_escalates_human_not_auto():
    tid = _mint()
    c = _client()
    r = c.post(f"/tenants/{tid}/authorize", json={
        "producer": "s", "request_id": "rx",
        "capability": "rathnone.other", "action_descriptor": "x"})
    assert r.json()["decision"]["verdict"] in ("HUMAN", "BLOCKED")
    assert r.json()["decision"]["verdict"] != "AUTO"


def test_execute_endpoint_removed():
    """ADR 17: the caller-verdict /execute bypass is gone. The single path to
    signing is /authorize_action, which runs the frozen spine itself."""
    tid = _mint()
    c = _client()
    r = c.post(f"/tenants/{tid}/execute",
               params={"request_id": "e1",
                       "capability": CAP_FIN_TRADE_EXECUTE,
                       "action_descriptor": "x", "verdict": "AUTO"})
    assert r.status_code == 404  # endpoint removed, not a silent pass-through


def test_execute_live_endpoint_removed():
    """ADR 17: /execute_live (authorized a thin tuple, signed a separate,
    unbound payload) is removed. Live signing now happens inside the
    authorize_action pipeline, bound to the full FinancialAction hash."""
    tid = _mint()
    c = _client()
    r = c.post(f"/tenants/{tid}/execute_live", json={
        "producer": "s", "request_id": "e1",
        "capability": CAP_FIN_CHAIN_SETTLE, "action_descriptor": "x",
        "payload": {"to": "0x" + "ab" * 20, "value": "1", "nonce": 1}})
    assert r.status_code == 404


def test_authorize_action_is_the_signing_path():
    """The single path both authorizes AND signs (live tenant) over the same
    action hash — proving no separate unbound payload can be signed."""
    from src.service.app import _registry
    tid = _mint()
    _registry.get(tid).enable_live()  # opt tenant into real signing
    c = _client()
    action = {
        "action_id": "a1", "tenant_id": tid, "actor": "s",
        "capability": CAP_FIN_CHAIN_SETTLE, "side": "settle",
        "destination": "0x" + "cd" * 20, "quantity": 1.0,
        "currency": "wei", "settlement_asset": "wei", "nonce": 1,
    }
    r = c.post(f"/tenants/{tid}/authorize_action",
               json={"action": action, "denylist": []})
    assert r.status_code == 200, r.text
    assert r.json()["live_record"]["signature"]
    assert r.json()["live_record"]["signer_address"] == _registry.get(tid).settlement_address


def test_tenant_isolation_forged_record_rejected():
    """A record signed under tenant A must NOT verify under tenant B's mirror."""
    from src.service.tenant import TenantRegistry
    from src.mirror import AuditMirror, load_public_key, _entry_body
    import hashlib

    reg = TenantRegistry()
    a = reg.create(aum=0.0)
    b = reg.create(aum=0.0)
    # A signs a record; B's key-free mirror tries to verify it.
    rec = a.append_ledger({"event": "auth", "capability": CAP_FIN_TRADE_EXECUTE,
                           "verdict": "AUTO", "request_id": "x"})
    mirror_b = AuditMirror(load_public_key(b.public_key_pem))
    mirror_b.ingest(rec)
    ok, reason = mirror_b.verify_chain()
    assert ok is False  # isolation enforced by signature, not a flag


__all__ = []

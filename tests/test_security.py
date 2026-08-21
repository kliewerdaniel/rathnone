"""Security regression tests for the four documented red-team inversions.

Each test names the vector it defeats:
  V1 predatory extraction  - velocity cap + advisory-evidence sanitization
  V2 financial panopticon  - PII / identity-binding rejection
  V4 immutable cage        - circuit breaker + settlement-intent sanity
  V3 algorithmic oligarchy  - verdict independent of AUM/identity (frozen spine)
"""
import pytest
from fastapi.testclient import TestClient

from src.security.guards import (
    assert_no_pii, sanitize_advisory_evidence,
    validate_settlement_intent, validate_order,
    CircuitBreaker, VelocityGuard, Clock,
)
from src.service.app import app, _registry, _meters, _breaker, _velocity, _clock


# --- V2: panopticon defense -------------------------------------------------

def test_pii_rejected_from_ledger_body():
    with pytest.raises(ValueError):
        assert_no_pii({"to": "0x" + "11" * 20, "biometric": "scan-xyz", "value": "1"})
    # safe: only pseudonymous on-chain fields
    assert_no_pii({"to": "0xAB", "value": "1", "nonce": 1})


def test_advisory_evidence_loses_neutral_decision_fields():
    dirty = {"model_score": 0.9, "capability": "rathnone.chain_settle",
             "verdict": "AUTO", "request_id": "r1"}
    clean = sanitize_advisory_evidence(dirty)
    assert "capability" not in clean and "verdict" not in clean
    assert clean.get("model_score") == 0.9  # advisory only, stripped of authority fields


# --- V4: immutable cage defenses -------------------------------------------

def test_circuit_breaker_halts_live_signing():
    _registry._tenants.clear(); _meters.clear()
    _breaker.resume(); _clock._t = 0
    c = TestClient(app)
    tid = c.post("/tenants", json={"aum": 5_000_000.0, "live": True}).json()["tenant_id"]
    c.post("/safety/halt")
    assert c.get("/safety").json()["breaker_open"] is True
    r = c.post(f"/tenants/{tid}/authorize_action", json={
        "action": {"action_id": "cb", "actor": "a",
                    "capability": "rathnone.chain_settle", "side": "settle",
                    "destination": "0xAB", "quantity": 1.0, "price_limit": 1.0,
                    "currency": "wei", "settlement_asset": "wei", "nonce": 1},
        "denylist": []})
    assert r.status_code == 503, r.text
    c.post("/safety/resume")
    assert c.get("/safety").json()["breaker_open"] is False


def test_settlement_intent_rejects_malformed_and_oversize():
    with pytest.raises(ValueError):
        validate_settlement_intent({"to": "not-an-address", "value": "1", "nonce": 1})
    with pytest.raises(ValueError):
        validate_settlement_intent({"to": "0x" + "11" * 20, "value": "-5", "nonce": 1})
    with pytest.raises(ValueError):
        validate_settlement_intent({"to": "0x" + "11" * 20, "value": "1", "nonce": -1})
    with pytest.raises(ValueError):
        validate_settlement_intent(
            {"to": "0x" + "11" * 20, "value": str(2**129), "nonce": 1})
    # ceiling enforcement
    with pytest.raises(ValueError):
        validate_settlement_intent(
            {"to": "0x" + "11" * 20, "value": "100", "nonce": 1}, max_value_wei=50)
    # valid passes
    validate_settlement_intent({"to": "0x" + "11" * 20, "value": "100", "nonce": 1})


def test_order_validation_rejects_bad_side():
    with pytest.raises(ValueError):
        validate_order({"symbol": "ETH", "side": "hodl", "quantity": 1})
    with pytest.raises(ValueError):
        validate_order({"symbol": "ETH", "side": "buy", "quantity": 0})
    validate_order({"symbol": "ETH", "side": "buy", "quantity": 1})


# --- V1: predatory extraction defense --------------------------------------

def test_velocity_guard_blocks_burst():
    clk = Clock(); v = VelocityGuard(min_interval=10, window=1000, clock=clk)
    v.check()              # t=0 ok
    clk.advance(5)
    with pytest.raises(ValueError):  # too soon
        v.check()
    clk.advance(10)        # t=15, ok again


def test_live_signing_rejects_pii_payload_via_service():
    _registry._tenants.clear(); _meters.clear()
    _breaker.resume(); _clock._t = 0
    c = TestClient(app)
    tid = c.post("/tenants", json={"aum": 5_000_000.0, "live": True}).json()["tenant_id"]
    r = c.post(f"/tenants/{tid}/authorize_action", json={
        "action": {"action_id": "pii", "actor": "a",
                    "capability": "rathnone.chain_settle", "side": "settle",
                    "destination": "0xAB", "quantity": 1.0, "price_limit": 1.0,
                    "currency": "wei", "settlement_asset": "wei", "nonce": 1,
                    "evidence": {"ssn": "123-45-6789"}},
        "denylist": []})
    assert r.status_code == 403, r.text
    assert "identity-binding" in r.json()["detail"]


# --- V3: oligarchy defense (verdict independent of AUM/identity) ----------

def test_verdict_independent_of_aum():
    """Two tenants with wildly different AUM must receive identical verdicts
    for identical proposals. Proves the gateway cannot gatekeep by capital."""
    _registry._tenants.clear(); _meters.clear()
    _breaker.resume(); _clock._t = 0
    c = TestClient(app)
    small = c.post("/tenants", json={"aum": 0.0}).json()["tenant_id"]
    whale = c.post("/tenants", json={"aum": 9e12}).json()["tenant_id"]
    payload = {"producer": "s", "request_id": "r", "capability": "rathnone.chain_settle",
               "action_descriptor": "settle"}
    v_small = c.post(f"/tenants/{small}/authorize", json=payload).json()["decision"]["verdict"]
    v_whale = c.post(f"/tenants/{whale}/authorize", json=payload).json()["decision"]["verdict"]
    assert v_small == v_whale


# --- env-configurable deployment knobs (V1/V4, fail-closed) ----------------

def test_config_max_value_wei_fail_closed(monkeypatch):
    from src.config import (
        max_settlement_value_wei, live_signing_rate_max_per_window,
    )
    # unset / empty -> None (no ceiling)
    monkeypatch.delenv("RATHNONE_MAX_SETTLEMENT_VALUE_WEI", raising=False)
    monkeypatch.delenv("RATHNONE_LIVE_RATE_MAX", raising=False)
    assert max_settlement_value_wei() is None
    assert live_signing_rate_max_per_window() == 10**12
    # explicit valid values
    monkeypatch.setenv("RATHNONE_MAX_SETTLEMENT_VALUE_WEI", "10")
    assert max_settlement_value_wei() == 10
    monkeypatch.setenv("RATHNONE_LIVE_RATE_MAX", "5")
    assert live_signing_rate_max_per_window() == 5
    # malformed -> raises (fail-closed, never silently unbounded)
    monkeypatch.setenv("RATHNONE_MAX_SETTLEMENT_VALUE_WEI", "not-a-number")
    with pytest.raises(ValueError):
        max_settlement_value_wei()
    monkeypatch.setenv("RATHNONE_MAX_SETTLEMENT_VALUE_WEI", "-3")
    with pytest.raises(ValueError):
        max_settlement_value_wei()


def test_service_honors_max_value_wei_env(monkeypatch):
    """V4: when RATHNONE_MAX_SETTLEMENT_VALUE_WEI is set, an over-ceiling
    settlement is refused at the service layer (403), even with an AUTO verdict.

    The ceiling is resolved at REQUEST TIME (app._settlement_ceiling_wei reads
    the env per call), so we set the env directly — no import-time global patch.
    """
    monkeypatch.setenv("RATHNONE_MAX_SETTLEMENT_VALUE_WEI", "50")
    _registry._tenants.clear(); _meters.clear()
    _breaker.resume(); _clock._t = 0
    c = TestClient(app)
    tid = c.post("/tenants", json={"aum": 5_000_000.0, "live": True}).json()["tenant_id"]
    # notional = quantity * price_limit = 100 * 1 = 100 wei > ceiling 50
    r = c.post(f"/tenants/{tid}/authorize_action", json={
        "action": {"action_id": "over", "actor": "a",
                    "capability": "rathnone.chain_settle", "side": "settle",
                    "destination": "0x" + "ab" * 20, "quantity": 100.0,
                    "price_limit": 1.0, "currency": "wei",
                    "settlement_asset": "wei", "nonce": 1},
        "denylist": []})
    assert r.status_code == 403, r.text
    assert "exceeds" in r.json()["detail"]

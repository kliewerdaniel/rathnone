"""ADR 17 — P0 security closure tests.

Prove the new control-plane auth gate actually gates:
  - with RATHNONE_ENFORCE_AUTH=1 and RATHNONE_API_KEY set, gated endpoints
    return 401 without the header and 200 (or the expected business status)
    with a valid Bearer/API key.
  - the deleted bypass endpoints (/execute, /execute_live) are gone (404).

The auth module reads env at CALL time, so we toggle it mid-process and restore
it in an autouse fixture teardown to avoid desyncing the shared app module.
"""

import os

import pytest

from fastapi.testclient import TestClient

from src.service.app import app, _registry, _meters, _breaker

_KEY = "test-control-plane-key"
_HEADERS = {"Authorization": f"Bearer {_KEY}"}


@pytest.fixture(autouse=True)
def enforce_auth():
    prev_enforce = os.environ.get("RATHNONE_ENFORCE_AUTH")
    prev_key = os.environ.get("RATHNONE_API_KEY")
    os.environ["RATHNONE_ENFORCE_AUTH"] = "1"
    os.environ["RATHNONE_API_KEY"] = _KEY
    _registry._tenants.clear(); _meters.clear(); _breaker.resume()
    yield
    # restore dev mode so the rest of the suite stays unauthenticated
    _registry._tenants.clear(); _meters.clear(); _breaker.resume()
    if prev_enforce is None:
        os.environ.pop("RATHNONE_ENFORCE_AUTH", None)
    else:
        os.environ["RATHNONE_ENFORCE_AUTH"] = prev_enforce
    if prev_key is None:
        os.environ.pop("RATHNONE_API_KEY", None)
    else:
        os.environ["RATHNONE_API_KEY"] = prev_key


def _client():
    return TestClient(app)


# --- gated endpoints require the control-plane key -------------------------

def test_provisioning_requires_key():
    c = _client()
    r = c.post("/tenants", json={"aum": 1_000_000.0})
    assert r.status_code == 401
    r2 = c.post("/tenants", json={"aum": 1_000_000.0}, headers=_HEADERS)
    assert r2.status_code == 200 and r2.json()["tenant_id"]


def test_safety_halt_requires_key():
    c = _client()
    assert c.post("/safety/halt").status_code == 401
    assert c.post("/safety/halt", headers=_HEADERS).status_code == 200


def test_safety_resume_requires_key():
    c = _client()
    # open the breaker with a key, then prove resume also needs a key
    c.post("/safety/halt", headers=_HEADERS)
    assert c.post("/safety/resume").status_code == 401
    assert c.post("/safety/resume", headers=_HEADERS).status_code == 200


def test_tenant_reads_require_key():
    c = _client()
    # create one authed so the id exists
    tid = c.post("/tenants", json={"aum": 1_000_000.0}, headers=_HEADERS).json()["tenant_id"]
    assert c.get(f"/tenants/{tid}/audit").status_code == 401
    assert c.get(f"/tenants/{tid}/audit", headers=_HEADERS).status_code == 200
    assert c.get(f"/tenants/{tid}/meter", headers=_HEADERS).status_code == 200
    assert c.get(f"/tenants/{tid}/reconciliation", headers=_HEADERS).status_code == 200


def test_bad_key_rejected():
    c = _client()
    r = c.post("/tenants", json={"aum": 1_000_000.0},
               headers={"Authorization": "Bearer wrong-key"})
    assert r.status_code == 401


def test_x_api_key_header_accepted():
    c = _client()
    r = c.post("/tenants", json={"aum": 1_000_000.0},
               headers={"X-API-Key": _KEY})
    assert r.status_code == 200


# --- the unified authorization path does NOT require the control-plane key --

def test_authorize_action_is_open_to_tenant_callers():
    c = _client()
    tid = c.post("/tenants", json={"aum": 1_000_000.0, "live": True},
                 headers=_HEADERS).json()["tenant_id"]
    r = c.post(f"/tenants/{tid}/authorize_action", json={
        "action": {"action_id": "p0", "actor": "a",
                    "capability": "rathnone.chain_settle", "side": "settle",
                    "destination": "0x" + "ab" * 20, "quantity": 1.0,
                    "price_limit": 1.0, "currency": "wei",
                    "settlement_asset": "wei", "nonce": 1},
        "denylist": []})
    assert r.status_code == 200, r.text
    assert r.json()["live_record"]["signature"]


# --- deleted bypass endpoints -----------------------------------------------

def test_execute_endpoint_removed():
    c = _client()
    r = c.post(f"/tenants/whatever/execute",
               params={"request_id": "e", "capability": "rathnone.chain_settle",
                       "action_descriptor": "x", "verdict": "AUTO"})
    assert r.status_code == 404


def test_execute_live_endpoint_removed():
    c = _client()
    r = c.post(f"/tenants/whatever/execute_live", json={
        "request_id": "e", "capability": "rathnone.chain_settle",
        "action_descriptor": "x", "payload": {"to": "0xab", "value": "1"}})
    assert r.status_code == 404

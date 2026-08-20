"""V4 operator safety control surface (the antidote to the immutable cage).

The circuit breaker is an INDEPENDENT halt: it stops live signing/execution
without the frozen fleet.epistemic.decide() agreeing. These tests exercise the
real HTTP endpoints (/safety, /safety/halt, /safety/resume) and assert that:
  - breaker OPEN refuses live signing (503) regardless of the model verdict
  - breaker OPEN refuses authorize_action (503)
  - breaker CLOSED lets AUTO actions sign
  - resume re-opens the path
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from src.service.app import app, _registry, _meters, _breaker


def _reset():
    _registry._tenants.clear()
    _meters.clear()
    _breaker.resume()


_LIVE = {
    "request_id": "r1",
    "capability": "rathnone.chain_settle",
    "action_descriptor": "settle",
    "payload": {"to": "0x" + "ab" * 20, "value": "1000000000000000000", "nonce": 1},
}
_ACTION = {
    "action_id": "x", "actor": "a", "capability": "rathnone.chain_settle",
    "instrument": "USDC", "side": "transfer", "quantity": 1.0, "price_limit": 1.0,
    "currency": "wei", "settlement_asset": "wei",
    "destination": "0x" + "ab" * 20, "nonce": 3, "timestamp": 1000,
}


def test_safety_halt_independent_of_verdict():
    _reset()
    c = TestClient(app)
    r = c.post("/tenants", json={"aum": 5_000_000, "live": True})
    tid = r.json()["tenant_id"]

    # Closed: live signing succeeds on AUTO.
    ok = c.post(f"/tenants/{tid}/execute_live", json=_LIVE)
    assert ok.status_code == 200, ok.text
    assert ok.json()["decision"]["verdict"] == "AUTO"

    # Trip the breaker.
    h = c.post("/safety/halt")
    assert h.status_code == 200 and h.json()["breaker_open"] is True
    s = c.get("/safety").json()
    assert s["breaker_open"] is True and s["live_signing_enabled"] is False

    # Open: live signing is refused regardless of what the model would say.
    blocked = c.post(f"/tenants/{tid}/execute_live", json={**_LIVE, "request_id": "r2",
                                                           "payload": {**_LIVE["payload"], "nonce": 2}})
    assert blocked.status_code == 503, blocked.text

    # Open: authorize_action (full pipeline) is also refused at the breaker.
    au = c.post(f"/tenants/{tid}/authorize_action", json={"action": _ACTION, "denylist": []})
    assert au.status_code == 503, au.text

    # Resume: path reopens.
    res = c.post("/safety/resume")
    assert res.status_code == 200 and res.json()["breaker_open"] is False
    s2 = c.get("/safety").json()
    assert s2["live_signing_enabled"] is True

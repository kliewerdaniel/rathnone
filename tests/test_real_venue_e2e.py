"""End-to-end: RealL2Venue through the actual gateway endpoint.

We do NOT contact any network and invent no credentials. Instead we monkeypatch
``get_venue`` inside the *real* service module so the pipeline runs against a real
``RealL2Venue`` whose JSON-RPC ``Client`` is a fake transport serving canned
responses. Then a real ``/tenants/{id}/authorize_action`` call runs the full
11-layer pipeline -> RealL2Venue.submit/query -> broadcast, and we independently
recover the on-chain signer of the broadcasted raw tx, asserting it equals the
tenant's settlement address (key-free, no private key).

Separately we assert the DEFAULT path stays on SimulatedVenue (no egress, no
creds) — the fail-closed behaviour.

IMPORT NOTE: ``src/service/__init__.py`` does ``from .app import app``, which
binds the name ``app`` in the package namespace to the FastAPI *instance*. As a
result ``import src.service.app`` (and ``sys.modules["src.service.app"]``) yields
the FastAPI object, not the module. To reach the genuine module we grab the
endpoint function's ``__globals__`` dict (which is the real module namespace the
handler closes over) and patch ``get_venue`` there as a dict item.
"""

import sys
import os
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient

import src.service  # __init__ binds src.service.app -> FastAPI instance (shadow)

# The endpoint function's __globals__ IS the real service.app module dict
# (independent of the shadowed package attribute). Use it to patch get_venue
# and reach _registry / _breaker.
_SVC = [r for r in src.service.app.routes
        if getattr(r, "path", "") == "/tenants/{tenant_id}/authorize_action"][0].endpoint.__globals__

from src.venue.l2 import RealL2Venue, _rlp_decode, _rlp_encode, _to_bytes
from src.live.signing import keccak256, recover_address


class _FakeRPC:
    def __init__(self):
        self.last_raw = None
        self.mined = True

    def post(self, url, json=None):
        method = json["method"]
        if method == "eth_sendRawTransaction":
            self.last_raw = json["params"][0]
            result = "0xtxhashfake"
        elif method == "eth_getTransactionReceipt":
            result = (
                None
                if not self.mined
                else {"status": "0x1", "to": "0x" + "ab" * 20,
                      "value": "0x1", "nonce": "0x1"}
            )
        else:
            result = "0x0"
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = {"jsonrpc": "2.0", "id": 1, "result": result}
        return resp


def _recover_signer(raw_hex: str, chain_id: int) -> str:
    raw = bytes.fromhex(raw_hex[2:])
    body, _ = _rlp_decode(raw)
    v = int.from_bytes(body[6], "big")
    r = int.from_bytes(body[7], "big")
    s = int.from_bytes(body[8], "big")
    head = [body[0], body[1], body[2], body[3], body[4], body[5],
            _to_bytes(chain_id), b"", b""]
    digest = keccak256(_rlp_encode(head))
    rec_id = (v - 35 - chain_id * 2) % 2
    return recover_address(digest, r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + rec_id]))


def _action(action_id="actRealE2E", dest="ab"):
    return {"action_id": action_id, "actor": "a",
            "capability": "rathnone.chain_settle", "instrument": "USDC",
            "side": "transfer", "quantity": 1.0, "price_limit": 1.0,
            "currency": "wei", "settlement_asset": "wei",
            "destination": "0x" + dest * 20, "nonce": 1, "timestamp": 1000}


def _build_fake_venue(signer, chain_id, mined=True):
    rpc = _FakeRPC()
    rpc.mined = mined
    venue = RealL2Venue("http://fake-l2", signer, chain_id=chain_id, client=rpc)
    return venue, rpc


def _client():
    # src.service.app is the FastAPI instance (package __init__ shadow).
    return TestClient(src.service.app)


def _with_venue(venue):
    """Context manager: temporarily replace get_venue in the real module globals."""
    class _Ctx:
        def __enter__(self):
            self._orig = _SVC.get("get_venue")
            _SVC["get_venue"] = lambda *a, **k: venue
            return self

        def __exit__(self, *exc):
            _SVC["get_venue"] = self._orig
            return False
    return _Ctx()


def test_real_venue_e2e_through_gateway():
    chain_id = 42161
    _SVC["_registry"]._tenants.clear()
    _SVC["_breaker"].resume()
    c = _client()
    r = c.post("/tenants", json={"aum": 5_000_000, "live": True})
    assert r.status_code == 200, r.text
    tid = r.json()["tenant_id"]
    settlement_address = r.json()["settlement_address"]
    t = _SVC["_registry"]._tenants[tid]

    venue, rpc = _build_fake_venue(t.settlement_key, chain_id)
    with _with_venue(venue):
        au = c.post(f"/tenants/{tid}/authorize_action",
                    json={"action": _action(), "denylist": []})
    assert au.status_code == 200, au.text
    body = au.json()
    # Real venue: submit()=SUBMITTED; reconcile() then queries -> SETTLED/MATCH.
    assert body["venue_state"] == "SUBMITTED", body
    assert body["state"] == "SETTLED", body
    assert body["reconciliation"] == "MATCH", body
    assert body["tx_hash"].startswith("0x")

    # INDEPENDENT recovery: the broadcasted raw tx was signed by the tenant's
    # settlement key — proven key-free from the tx bytes.
    assert rpc.last_raw.startswith("0x")
    signer = _recover_signer(rpc.last_raw, chain_id)
    assert signer == settlement_address, (signer, settlement_address)

    recon = c.get(f"/tenants/{tid}/reconciliation").json()
    assert recon["all_matched"] is True, recon


def test_real_venue_e2e_pending_then_missing_tx():
    chain_id = 10
    _SVC["_registry"]._tenants.clear()
    _SVC["_breaker"].resume()
    c = _client()
    r = c.post("/tenants", json={"aum": 2_000_000, "live": True})
    tid = r.json()["tenant_id"]
    t = _SVC["_registry"]._tenants[tid]

    venue, rpc = _build_fake_venue(t.settlement_key, chain_id, mined=False)
    with _with_venue(venue):
        au = c.post(f"/tenants/{tid}/authorize_action",
                    json={"action": _action("actPending", "cd"), "denylist": []})
    assert au.status_code == 200, au.text
    body = au.json()
    assert body["venue_state"] == "SUBMITTED", body
    # pending -> reconcile sees SUBMITTED (not settled yet) -> MISSING_EXTERNAL_TX
    # -> pipeline marks state FAILED (not yet matched at this instant).
    assert body["state"] == "FAILED", body
    assert body["reconciliation"] == "MISSING_EXTERNAL_TX", body
    assert rpc.last_raw.startswith("0x")


def test_default_env_still_simulator_no_egress():
    """No venue override -> get_venue() stays SimulatedVenue (fail-closed)."""
    _SVC["_registry"]._tenants.clear()
    _SVC["_breaker"].resume()
    c = _client()
    r = c.post("/tenants", json={"aum": 5_000_000, "live": True})
    tid = r.json()["tenant_id"]
    au = c.post(f"/tenants/{tid}/authorize_action",
                json={"action": _action("actSim"), "denylist": []})
    assert au.status_code == 200, au.text
    # simulator submit() returns SETTLED -> MATCH (no network, no creds).
    assert au.json()["state"] == "SETTLED", au.json()
    assert au.json()["reconciliation"] == "MATCH", au.json()

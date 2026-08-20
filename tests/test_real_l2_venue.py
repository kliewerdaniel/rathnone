"""Real L2 venue adapter (v2 P2) — verified WITHOUT network or credentials.

The RealL2Venue is a drop-in behind VenueAdapter. These tests:
  - prove the EIP-155 transaction it builds is signed by the tenant's REAL
    settlement key and that the on-chain signer address is recoverable from the
    raw tx (no private key) via the same recover_address used elsewhere;
  - prove submit()/query() map to the VenueState machine correctly using a
    fake JSON-RPC transport (no egress);
  - prove the fail-closed factory: get_venue() returns SimulatedVenue by default,
    and RealL2Venue refuses to construct without rpc_url/chain_id/key.
"""

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient

from src.service.app import app, _registry, _meters, _breaker
from src.venue.adapter import get_venue, SimulatedVenue
from src.venue.l2 import RealL2Venue, _rlp_encode, _rlp_decode, _to_bytes
from src.live.signing import Secp256k1Signer, keccak256, recover_address
from src.finance.action import FinancialAction


class _FakeRPC:
    """Minimal JSON-RPC transport. Returns canned eth_sendRawTransaction /
    eth_getTransactionReceipt without any network. Records the last raw tx."""

    def __init__(self):
        self.last_raw = None
        self._mined = True  # whether the receipt query returns a mined tx

    def post(self, url, json=None):
        method = json["method"]
        params = json["params"]
        if method == "eth_sendRawTransaction":
            self.last_raw = params[0]
            result = "0xreceiptdeadbeef"
        elif method == "eth_getTransactionReceipt":
            if not self._mined:
                result = None  # still pending
            else:
                result = {
                    "status": "0x1",
                    "to": "0x" + "ab" * 20,
                    "value": "0x" + (1_000_000).to_bytes(4, "big").hex(),
                    "nonce": "0x1",
                }
        else:
            result = "0x0"
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = {"jsonrpc": "2.0", "id": 1, "result": result}
        return resp


def _action(capability="rathnone.chain_settle"):
    return FinancialAction(
        action_id="a1", tenant_id="t1", actor="a", capability=capability,
        instrument="USDC", side="transfer", quantity=1_000_000.0,
        price_limit=1.0, currency="wei", settlement_asset="wei",
        destination="0x" + "ab" * 20, nonce=1, timestamp=1000)


# --- RLP round-trips (the hand-rolled encoder must decode to itself) --------
def test_rlp_roundtrip():
    cases = [[], [b""], [b"\x00", b"abc", [b"", b"ff"]]]
    for c in cases:
        enc = _rlp_encode(c)
        dec = _rlp_decode(enc)[0]
        assert dec == c, (c, dec)


def test_rlp_length_int():
    assert _to_bytes(0) == b""
    assert _to_bytes(255) == b"\xff"
    assert _to_bytes(256) == b"\x01\x00"


# --- RealL2Venue construction is fail-closed --------------------------------
def test_real_venue_refuses_without_rpc():
    signer = Secp256k1Signer(1)
    import pytest
    with pytest.raises(ValueError):
        RealL2Venue(rpc_url="", signer=signer, chain_id=10)
    with pytest.raises(ValueError):
        RealL2Venue(rpc_url="http://x", signer=signer, chain_id=0)
    with pytest.raises(ValueError):
        RealL2Venue(rpc_url="http://x", signer=signer, chain_id=10 ** 40)


def test_factory_defaults_to_simulated():
    v = get_venue(None)
    assert isinstance(v, SimulatedVenue)
    # A live tenant with no rpc_url still gets the simulator (fail-closed).
    class _T:
        live = True
        settlement_key = Secp256k1Signer(7)
    v2 = get_venue(_T())
    assert isinstance(v2, SimulatedVenue)


# --- RealL2Venue submit/query against a fake transport ----------------------
def test_real_venue_submit_and_query():
    signer = Secp256k1Signer(12345)
    rpc = _FakeRPC()
    venue = RealL2Venue("http://fake-l2", signer, chain_id=42161, client=rpc)

    rep = venue.submit(_action())
    assert rep.state.value == "SUBMITTED"
    assert rep.tx_hash.startswith("0x")
    assert rpc.last_raw.startswith("0x")

    # raw tx is EIP-155 signed by the tenant's key -> recoverable address matches.
    raw = bytes.fromhex(rpc.last_raw[2:])
    body, _ = _rlp_decode(raw)
    v = int.from_bytes(body[6], "big")
    r = int.from_bytes(body[7], "big")
    s = int.from_bytes(body[8], "big")
    # Recover the signer from the legacy-eth (pre-EIP-155) digest of the tx body.
    head = [body[0], body[1], body[2], body[3], body[4], body[5],
            _to_bytes(42161), b"", b""]
    digest = keccak256(_rlp_encode(head))
    rec_id = (v - 35 - 42161 * 2) % 2
    rec = recover_address(digest, r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + rec_id]))
    assert rec == signer.address, (rec, signer.address)

    # query after mining -> SETTLED
    rep2 = venue.query("a1")
    assert rep2.state.value == "SETTLED"
    assert rep2.tx_hash == rep.tx_hash

    # query before mining -> still SUBMITTED (pending)
    rpc2 = _FakeRPC()
    rpc2._mined = False
    venue2 = RealL2Venue("http://fake-l2", signer, chain_id=42161, client=rpc2)
    venue2.submit(_action())
    rep3 = venue2.query("a1")
    assert rep3.state.value == "SUBMITTED"


def test_real_venue_revert_query():
    signer = Secp256k1Signer(99)
    rpc = _FakeRPC()
    rpc._mined = True
    # override receipt to a revert
    orig = rpc.post

    def _post(url, json=None):
        r = orig(url, json)
        if json["method"] == "eth_getTransactionReceipt":
            payload = r.json()
            payload["result"] = {"status": "0x0", "to": "0x" + "ab" * 20,
                                  "value": "0x0", "nonce": "0x1"}
        return r

    rpc.post = _post
    venue = RealL2Venue("http://fake-l2", signer, chain_id=42161, client=rpc)
    venue.submit(_action())
    rep = venue.query("a1")
    assert rep.state.value == "REJECTED"


def test_endpoint_still_defaults_to_simulator():
    """With no L2 env, a live action reconciles MATCH via the simulator (no egress)."""
    _reset()
    c = TestClient(app)
    r = c.post("/tenants", json={"aum": 5_000_000, "live": True})
    tid = r.json()["tenant_id"]
    payload = {"action_id": "actL2", "actor": "a", "capability": "rathnone.chain_settle",
               "instrument": "USDC", "side": "transfer", "quantity": 1.0,
               "price_limit": 1.0, "currency": "wei", "settlement_asset": "wei",
               "destination": "0x" + "ab" * 20, "nonce": 1, "timestamp": 1000}
    au = c.post(f"/tenants/{tid}/authorize_action", json={"action": payload, "denylist": []})
    assert au.status_code == 200, au.text
    s = c.get(f"/tenants/{tid}/reconciliation").json()
    assert s["all_matched"] is True


def _reset():
    _breaker.resume()
    _registry._tenants.clear()
    _meters.clear()

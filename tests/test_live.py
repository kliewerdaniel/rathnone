"""Live track verification (opt-in, fail-closed): real keccak256 + real
secp256k1 (Ethereum) / Ed25519 signatures bound to authorized intents."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.live.signing import (
    keccak256,
    Secp256k1Signer,
    recover_address,
)
from src.live import SettlementAuthRecord, OrderAuthRecord
from src.service.tenant import TenantRegistry, Tenant
from src.finance.proposal import RathnoneFinanceProposal


# --- R-LIVE-1: keccak256 matches the Ethereum test vectors -----------------
def test_keccak_empty():
    assert keccak256(b"").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")


def test_keccak_abc():
    assert keccak256(b"abc").hex() == (
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")


def test_keccak_bytes_0_255():
    assert keccak256(bytes(range(256))).hex() == (
        "dc924469b334aed2a19fac7252e9961aea41f8d91996366029dbe0884229bf36")


# --- R-LIVE-2: secp256k1 sign + recover (Ethereum ecrecover-compatible) -----
def test_secp256k1_recover_roundtrip():
    sk = Secp256k1Signer()
    digest = keccak256(b"rathnone-live-intent")
    sig = sk.sign_eth(digest)
    recovered = recover_address(digest, sig)
    assert recovered is not None
    assert recovered.lower() == sk.address.lower()


def test_secp256k1_deterministic_nonce():
    sk = Secp256k1Signer(0x1CB5651B8A1391CDD2158BDF6A1B9282DA7E2D3016BAB83C14CD2F4CF16A4A67)
    d = keccak256(b"x")
    assert sk.sign(d) == sk.sign(d)  # RFC6979 -> same nonce -> same sig


# --- R-LIVE-3: settlement record is on-chain-verifiable by address only ----
def test_settlement_record_live_verify():
    sk = Secp256k1Signer()
    intent = {"to": "0xabc", "value": "1000000000000000000", "nonce": 7}
    rec = SettlementAuthRecord.build(
        decision_ref="dec-1", capability="rathnone.chain_settle",
        intent=intent, verdict="AUTO", signer=sk)
    # Anyone with the address can verify (no private key needed).
    assert rec.verify(intent) is True
    # Tampered executor calldata must fail.
    tampered = dict(intent); tampered["value"] = "2000000000000000000"
    assert rec.verify(tampered) is False
    # Wrong signer address -> false.
    rec.signer_address = "0x0000000000000000000000000000000000000000"
    assert rec.verify(intent) is False


def test_settlement_record_refuses_non_auto():
    sk = Secp256k1Signer()
    intent = {"to": "0xabc", "value": "1"}
    try:
        SettlementAuthRecord.build(
            decision_ref="dec", capability="rathnone.chain_settle",
            intent=intent, verdict="BLOCKED", signer=sk)
        assert False, "non-AUTO should refuse"
    except ValueError:
        pass


# --- R-LIVE-4: order record Ed25519 binding --------------------------------
def test_order_record_live_verify():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    k = Ed25519PrivateKey.generate()
    order = {"symbol": "ETH-USD", "side": "buy", "qty": 10}
    rec = OrderAuthRecord.build(
        decision_ref="dec-2", capability="rathnone.trade_execute",
        order=order, verdict="AUTO", signing_key=k)
    pub = serialization.load_pem_public_key(k.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    assert rec.verify(order, pub) is True
    bad = dict(order); bad["qty"] = 999
    assert rec.verify(bad, pub) is False


# --- R-LIVE-5: service fail-closed + live binding end-to-end ---------------
def _fresh_registry():
    reg = TenantRegistry()
    reg._tenants.clear()
    return reg


def test_service_live_refused_when_not_enabled():
    from fastapi.testclient import TestClient
    from src.service.app import app, _registry, _meters
    _registry._tenants.clear()
    _meters.clear()
    c = TestClient(app)
    r = c.post("/tenants", json={"aum": 5_000_000.0})  # not live
    tid = r.json()["tenant_id"]
    assert r.json()["settlement_address"] is None
    r2 = c.post(f"/tenants/{tid}/execute_live", json={
        "request_id": "r1", "capability": "rathnone.chain_settle",
        "action_descriptor": "settle", "payload": {"to": "0x" + "ab" * 20, "value": "1"}})
    assert r2.status_code == 403  # live not enabled


def test_service_live_settle_signs_when_auto():
    from fastapi.testclient import TestClient
    from src.service.app import app, _registry, _meters, _breaker, _clock
    _registry._tenants.clear(); _meters.clear(); _breaker.resume(); _clock._t = 0
    c = TestClient(app)
    r = c.post("/tenants", json={"aum": 5_000_000.0, "live": True})
    j = r.json()
    tid, addr = j["tenant_id"], j["settlement_address"]
    assert addr is not None and addr.startswith("0x")
    r2 = c.post(f"/tenants/{tid}/execute_live", json={
        "request_id": "r1", "capability": "rathnone.chain_settle",
        "action_descriptor": "settle",
        "payload": {"to": "0x" + "ab" * 20, "value": "1000000000000000000", "nonce": 1}})
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["decision"]["verdict"] == "AUTO"
    rec = body["live_record"]
    assert rec["signature"] and rec["signer_address"].lower() == addr.lower()
    # Independent re-verify using the public recovery (no private key).
    from src.live import recover_address as _rec
    sig = bytes.fromhex(rec["signature"])
    recovered = _rec(bytes.fromhex(rec["intent_hash"]), sig)
    assert recovered is not None and recovered.lower() == addr.lower()


def test_service_live_refused_on_blocked():
    from fastapi.testclient import TestClient
    from src.service.app import app, _registry, _meters
    _registry._tenants.clear()
    _meters.clear()
    c = TestClient(app)
    r = c.post("/tenants", json={"aum": 5_000_000.0, "live": True})
    tid = r.json()["tenant_id"]
    # Deny-list the capability -> BLOCKED -> live signing refused.
    r2 = c.post(f"/tenants/{tid}/execute_live", json={
        "request_id": "r1", "capability": "rathnone.chain_settle",
        "action_descriptor": "settle", "denylist": ["rathnone.chain_settle"],
        "payload": {"to": "0x" + "ab" * 20, "value": "1"}})
    assert r2.status_code == 403
    assert "verdict=BLOCKED" in r2.json()["detail"]


def test_service_live_signature_lands_in_immutable_ledger():
    from fastapi.testclient import TestClient
    from src.service.app import app, _registry, _meters
    _registry._tenants.clear()
    _meters.clear()
    c = TestClient(app)
    r = c.post("/tenants", json={"aum": 5_000_000.0, "live": True})
    tid = r.json()["tenant_id"]
    intent = {"to": "0x" + "AB" * 20, "value": "1000000000000000000", "nonce": 1}
    r2 = c.post(f"/tenants/{tid}/execute_live", json={
        "request_id": "r2", "capability": "rathnone.chain_settle",
        "action_descriptor": "settle", "payload": intent})
    body = r2.json()
    assert body["verify"] is True, "ledger must stay valid after live sign"
    # The live signature is independently recoverable straight from the ledger
    # record (intent_hash + signature), proving on-chain verifiability with no key.
    from src.live import recover_address
    live_rows = [x for x in c.get(f"/tenants/{tid}/audit").json()["records"]
                 if x.get("event") == "live_sign"]
    assert live_rows, "live_sign entry missing from ledger"
    row = live_rows[0]
    recovered = recover_address(bytes.fromhex(row["intent_hash"]),
                                bytes.fromhex(row["live_signature"]))
    assert recovered is not None and recovered.lower() == row["settlement_address"].lower()

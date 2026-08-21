"""ADR 20 — signed operator commands for authorize_action (live settlement).

Extends the ADR 19 signed-command gate to the fund-moving verb
`POST /tenants/{tid}/authorize_action`. For a tenant whose `operator_allowlist`
is configured, the live-settlement *transport* requires a signed OperatorCommand
(verb="authorize") binding the exact request body. Dormant until the tenant opts
into operator authority; non-gated tenants stay on the ADR 17 static-key path
(console-compatible).

Covers:
  - operator-gated tenant without a signed command -> refused (401).
  - valid signed command settles and is attributed (operator_command ledger event).
  - replayed nonce -> refused (401).
  - command whose body_hash does not bind the request -> refused (401).
  - non-gated tenant still settles without a signed command (console-compatible).
"""
import base64
import json
import os
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from src.security.operator import OperatorCommand, body_hash_of, OperatorKeyRing
from src.service.app import app, _registry, _meters, _breaker, _clock


def _pem(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _action(tid: str, action_id: str = "a1") -> dict:
    return {
        "action_id": action_id, "tenant_id": tid, "actor": "console",
        "capability": "rathnone.chain_settle", "side": "settle",
        "destination": "0x" + "ab" * 20, "quantity": 1.0,
        "currency": "wei", "settlement_asset": "wei", "nonce": 1,
    }


def _canonical_body(action: dict, **extra) -> bytes:
    """Mirror app.authorize_action's body canonicalization exactly.

    Gateway: json.dumps(body.model_dump(), sort_keys=True, separators=(",",":")).
    The _AuthorizeActionIn model has fields: action, approval, downgrade,
    require_human_approval, denylist. We replicate model_dump() ordering here.
    """
    payload = {
        "action": action,
        "approval": extra.get("approval"),
        "downgrade": extra.get("downgrade"),
        "require_human_approval": extra.get("require_human_approval", False),
        "denylist": extra.get("denylist", []),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _sign_authorize(key: Ed25519PrivateKey, *, tid: str, body: bytes,
                    nonce: int = 0, operator_id: str = "op-1") -> OperatorCommand:
    # F5: timestamp in the epoch-nanosecond domain (int(time.time()*1e9)) so it
    # matches the gateway's _command_clock verification domain across processes.
    cmd = OperatorCommand(
        verb="authorize", tenant_id=tid, body_hash=body_hash_of(body),
        nonce=nonce, timestamp=int(time.time() * 1_000_000_000),
        operator_id=operator_id, pubkey_pem=_pem(key),
    )
    cmd.sig = key.sign(cmd.canonical_bytes()).hex()
    return cmd


def _cmd_header(cmd: OperatorCommand) -> dict:
    raw = base64.b64encode(json.dumps({
        k: getattr(cmd, k) for k in (
            "verb", "tenant_id", "body_hash", "nonce", "timestamp",
            "operator_id", "pubkey_pem", "sig",
        )
    }).encode()).decode()
    return {"X-Operator-Command": raw}


@pytest.fixture
def gated_tenant():
    """A live, operator-gated tenant on the gateway's real registry."""
    _registry._tenants.clear()
    _meters.clear()
    _breaker.resume()
    _clock._t = 0
    op = Ed25519PrivateKey.generate()
    c = TestClient(app)
    r = c.post("/tenants", json={"aum": 5_000_000.0, "live": True})
    tid = r.json()["tenant_id"]
    t = _registry.get(tid)
    t.operator_keys = OperatorKeyRing.from_pems([_pem(op)])
    yield c, tid, op
    _registry._tenants.clear()
    _meters.clear()


def test_gated_tenant_requires_signed_command(gated_tenant):
    c, tid, op = gated_tenant
    # No X-Operator-Command header -> refused (401).
    r = c.post(f"/tenants/{tid}/authorize_action",
               json={"action": _action(tid), "denylist": []})
    assert r.status_code == 401
    assert "operator-signed command required" in r.text


def test_gated_tenant_valid_command_settles_and_is_attributed(gated_tenant):
    c, tid, op = gated_tenant
    action = _action(tid)
    body = _canonical_body(action)
    cmd = _sign_authorize(op, tid=tid, body=body, nonce=1)
    r = c.post(f"/tenants/{tid}/authorize_action",
               json={"action": action, "denylist": []},
               headers=_cmd_header(cmd))
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["verdict"] == "AUTO"
    assert j["live_record"] is not None  # actually settled
    # The settlement is attributed: an operator_command ledger event is recorded.
    audit = c.get(f"/tenants/{tid}/audit").json()
    events = [e for e in audit["records"] if e.get("event") == "operator_command"]
    assert events, "no operator_command event recorded"
    assert events[0]["operator_id"] == "op-1"
    assert events[0]["verb"] == "authorize"
    assert events[0]["nonce"] == 1


def test_gated_tenant_replayed_nonce_refused(gated_tenant):
    c, tid, op = gated_tenant
    action = _action(tid)
    body = _canonical_body(action)
    cmd = _sign_authorize(op, tid=tid, body=body, nonce=7)
    r1 = c.post(f"/tenants/{tid}/authorize_action",
                json={"action": action, "denylist": []},
                headers=_cmd_header(cmd))
    assert r1.status_code == 200
    # Replay the same nonce -> refused.
    r2 = c.post(f"/tenants/{tid}/authorize_action",
                json={"action": action, "denylist": []},
                headers=_cmd_header(cmd))
    assert r2.status_code == 401
    assert "already used" in r2.text or "replay" in r2.text.lower()


def test_gated_tenant_wrong_body_binding_refused(gated_tenant):
    c, tid, op = gated_tenant
    action = _action(tid)
    # Command is signed over a DIFFERENT body than the one sent -> binding fails.
    other = _canonical_body(_action(tid, action_id="different"))
    cmd = _sign_authorize(op, tid=tid, body=other, nonce=3)
    r = c.post(f"/tenants/{tid}/authorize_action",
               json={"action": action, "denylist": []},
               headers=_cmd_header(cmd))
    assert r.status_code == 401
    assert "body_hash" in r.text


def test_non_gated_tenant_still_static_key_only():
    """Console-compatible: a tenant without an operator allowlist does not need a
    signed command for authorize_action (ADR 17 path unchanged)."""
    _registry._tenants.clear()
    _meters.clear()
    _breaker.resume()
    _clock._t = 0
    c = TestClient(app)
    r = c.post("/tenants", json={"aum": 5_000_000.0, "live": True})
    tid = r.json()["tenant_id"]
    action = _action(tid)
    r2 = c.post(f"/tenants/{tid}/authorize_action",
                json={"action": action, "denylist": []})
    assert r2.status_code == 200, r2.text
    assert r2.json()["live_record"] is not None
    _registry._tenants.clear()
    _meters.clear()

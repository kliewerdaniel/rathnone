"""ADR 21 — operator key lifecycle (provision / rotate / revoke / expire).

The operator authority (used by both the safety scope and tenant settlement
authority) was a bare list[str] of PEMs in ADR 19/20. ADR 21 replaces it with
an OperatorKeyRing: each authorized key is a metadata-bearing entry carrying an
operator_id, an optional expiry, and a revoked flag. The signed-command gate
verifies against *active* keys only, so:

  - revoke() is an immediate kill-switch (key leaves the active set at once),
  - expiry is a graceful rotation window (a lapsed key falls out of the active
    set; the scope reverts to the ADR 17 shared-key path — consistent with the
    "dormant when no active allowlist" fail-closed default),
  - rotate() adds a new key and (optionally) gives the old key a short grace
    period before retiring it.

Covers:
  - adding a key makes it active and present in active_pems().
  - revoke() by key_id removes it from the active set immediately.
  - revoke() by full PEM works too.
  - a revoked key's command is refused (end-to-end via the gateway).
  - an expired key drops out of the active set; an unexpired one stays.
  - rotate() with a grace window keeps the old key active until it lapses.
  - empty keyring => not active => signed-command layer dormant (fail-closed).
"""

import time as _time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fastapi.testclient import TestClient

from src.security.operator import (
    OperatorCommand, body_hash_of, OperatorKeyRing, OperatorKeyEntry,
)
from src.service.app import app, _SAFETY_TENANT, _clock


def _pem(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _sign(verb: str, key: Ed25519PrivateKey, *,
          tenant_id: str = "__safety__", body: bytes = b"halt",
          nonce: int = 0, operator_id: str = "op-1") -> OperatorCommand:
    cmd = OperatorCommand(
        verb=verb, tenant_id=tenant_id, body_hash=body_hash_of(body),
        nonce=nonce, timestamp=_clock.now(), operator_id=operator_id,
        pubkey_pem=_pem(key),
    )
    cmd.sig = key.sign(cmd.canonical_bytes()).hex()
    return cmd


def _hdr(cmd: OperatorCommand) -> dict:
    import base64, json
    raw = base64.b64encode(json.dumps({
        k: getattr(cmd, k) for k in (
            "verb", "tenant_id", "body_hash", "nonce", "timestamp",
            "operator_id", "pubkey_pem", "sig",
        )
    }).encode()).decode()
    return {"X-Operator-Command": raw}


@pytest.fixture(autouse=True)
def reset_safety():
    saved = _SAFETY_TENANT.operator_keys
    saved_nonces = set(_SAFETY_TENANT._used_command_nonces)
    _SAFETY_TENANT.operator_keys = OperatorKeyRing()
    _SAFETY_TENANT._used_command_nonces.clear()
    yield
    _SAFETY_TENANT.operator_keys = saved
    _SAFETY_TENANT._used_command_nonces.clear()
    _SAFETY_TENANT._used_command_nonces.update(saved_nonces)


# --- unit: keyring active-set semantics -------------------------------------

def test_add_then_active():
    k = Ed25519PrivateKey.generate()
    ring = OperatorKeyRing()
    ring.add(_pem(k), operator_id="op-1")
    assert ring.active_pems() == [_pem(k)]
    assert ring.is_authorized(_pem(k)) is True


def test_revoke_by_key_id_removes_from_active():
    k = Ed25519PrivateKey.generate()
    ring = OperatorKeyRing.from_pems([_pem(k)], operator_id="op-1")
    entry = ring.lookup(_pem(k))
    assert ring.revoke(entry.key_id) is True
    assert ring.active_pems() == []   # immediate kill-switch
    assert ring.is_authorized(_pem(k)) is False
    # entry is retained (audit), just inactive
    assert len(ring) == 1 and ring.lookup(_pem(k)).revoked is True


def test_revoke_by_pem_works():
    k = Ed25519PrivateKey.generate()
    ring = OperatorKeyRing.from_pems([_pem(k)])
    assert ring.revoke(_pem(k)) is True
    assert ring.active_pems() == []


def test_revoke_missing_returns_false():
    ring = OperatorKeyRing()
    assert ring.revoke("deadbeefdeadbeef") is False


def test_expiry_drops_key():
    k = Ed25519PrivateKey.generate()
    now = int(_time.time())
    ring = OperatorKeyRing.from_pems([_pem(k)])
    # no expiry yet -> active
    assert ring.active_pems() == [_pem(k)]
    # set expiry in the past and re-check
    ring.lookup(_pem(k)).expires_at = now - 10
    assert ring.active_pems(now_epoch_s=now) == []
    assert ring.is_authorized(_pem(k), now_epoch_s=now) is False


def test_unexpired_key_stays_active():
    k = Ed25519PrivateKey.generate()
    now = int(_time.time())
    ring = OperatorKeyRing.from_pems([_pem(k)])
    ring.lookup(_pem(k)).expires_at = now + 3600
    assert ring.active_pems(now_epoch_s=now) == [_pem(k)]


def test_rotate_grace_window_keeps_old_key():
    old = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate()
    now = int(_time.time())
    ring = OperatorKeyRing.from_pems([_pem(old)], operator_id="op-1")
    ring.rotate(_pem(new), old_pem=_pem(old), operator_id="op-1",
                expire_old_in_s=600, now_epoch_s=now)
    # both active during the grace window
    assert set(ring.active_pems(now_epoch_s=now)) == {_pem(old), _pem(new)}
    # after the window lapses, only the new key remains
    later = now + 600
    assert ring.active_pems(now_epoch_s=later) == [_pem(new)]


def test_rotate_immediate_revoke_when_no_grace():
    old = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate()
    now = int(_time.time())
    ring = OperatorKeyRing.from_pems([_pem(old)], operator_id="op-1")
    ring.rotate(_pem(new), old_pem=_pem(old), operator_id="op-1",
                expire_old_in_s=0, now_epoch_s=now)
    assert ring.active_pems(now_epoch_s=now) == [_pem(new)]


def test_empty_ring_not_active():
    ring = OperatorKeyRing()
    assert ring.active_pems() == []
    assert ring.is_authorized("anything") is False


# --- integration: revoked key is refused at the gateway ----------------------

def test_revoking_last_key_reverts_layer_to_dormant():
    """Revoking the only active operator key is a kill-switch on the
    signed-command layer: the safety scope reverts to the ADR 17 static-key
    path (dormant), never an auth bypass. Fail-closed."""
    c = TestClient(app)
    op = Ed25519PrivateKey.generate()
    _SAFETY_TENANT.operator_keys = OperatorKeyRing.from_pems([_pem(op)])
    # With an active key, a halt WITHOUT a signed command is refused (401).
    r0 = c.post("/safety/halt")
    assert r0.status_code == 401
    # Revoke the only key -> layer dormant -> plain halt succeeds on static key.
    entry = _SAFETY_TENANT.operator_keys.lookup(_pem(op))
    assert _SAFETY_TENANT.operator_keys.revoke(entry.key_id) is True
    r1 = c.post("/safety/halt")
    assert r1.status_code == 200 and r1.json()["breaker_open"] is True


def test_command_signed_by_revoked_key_refused_while_layer_in_force():
    """When at least one key stays active (layer in force), a command signed
    by a revoked key is refused (401) — it is not in the active set."""
    c = TestClient(app)
    active = Ed25519PrivateKey.generate()
    revoked = Ed25519PrivateKey.generate()
    ring = OperatorKeyRing.from_pems([_pem(active)], operator_id="active")
    ring.add(_pem(revoked), operator_id="revoked")
    ring.revoke(_pem(revoked))   # kill the second; first stays active
    _SAFETY_TENANT.operator_keys = ring
    # Command signed by the revoked key -> layer in force but key not active.
    cmd = _sign("halt", revoked, body=b"halt", nonce=1)
    r = c.post("/safety/halt", headers=_hdr(cmd))
    assert r.status_code == 401

"""ADR 19 — signed operator commands for safety-critical verbs.

Prove the gate actually gates halt/resume once a global operator allowlist is
configured, while staying console-compatible (no allowlist => static-key path
only). Covers:

  - with no allowlist: halt/resume still succeed under the ADR 17 static key
    (the console never holds a signing key, so it must keep working).
  - with allowlist configured: a halt WITHOUT a signed command is refused (401).
  - a valid signed command trips the breaker and is attributed in the audit.
  - a replayed nonce is refused.
  - a command whose body_hash does not match the request is refused (binding).
  - OperatorCommand.verify / verify_command fail-closed on bad sig.
"""

import base64
import json
import os
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fastapi.testclient import TestClient

from src.security.operator import (
    OperatorCommand, verify_command, body_hash_of,
    OperatorAuthority, OperatorKeyRing,
)
from src.service.app import app, _SAFETY_TENANT, _safety_audit, _clock


def _pem(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _sign_cmd(key: Ed25519PrivateKey, *, verb: str, tenant_id: str = "__safety__",
              body: bytes = b"", nonce: int = 0, timestamp: int = None,
              operator_id: str = "op-1", second_key=None,
              second_operator_id: str = "") -> OperatorCommand:
    if timestamp is None:
        timestamp = int(time.time() * 1_000_000_000)  # F5: epoch-ns, matches gateway
    cmd = OperatorCommand(
        verb=verb, tenant_id=tenant_id, body_hash=body_hash_of(body),
        nonce=nonce, timestamp=timestamp, operator_id=operator_id,
        pubkey_pem=_pem(key),
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


@pytest.fixture(autouse=True)
def reset_safety_scope():
    saved = _SAFETY_TENANT.operator_keys
    _SAFETY_TENANT.operator_keys = OperatorKeyRing()
    _safety_audit.clear()
    yield
    _SAFETY_TENANT.operator_keys = saved
    _safety_audit.clear()


def _client():
    # Dev mode: no static auth gate, so the test exercises only the ADR 19 layer.
    prev = os.environ.get("RATHNONE_ENFORCE_AUTH")
    os.environ["RATHNONE_ENFORCE_AUTH"] = "0"
    yield TestClient(app)
    if prev is None:
        os.environ.pop("RATHNONE_ENFORCE_AUTH", None)
    else:
        os.environ["RATHNONE_ENFORCE_AUTH"] = prev


# --- console-compatible: no allowlist => static-key path only -----------------

def test_no_allowlist_still_allows_halt_on_static_key():
    c = next(_client())
    r = c.post("/safety/halt")
    assert r.status_code == 200 and r.json()["breaker_open"] is True
    r2 = c.post("/safety/resume")
    assert r2.status_code == 200 and r2.json()["breaker_open"] is False


# --- with allowlist configured: signed command is mandatory ------------------

def test_halt_without_command_refused():
    c = next(_client())
    op = Ed25519PrivateKey.generate()
    _SAFETY_TENANT.operator_keys = OperatorKeyRing.from_pems([_pem(op)])
    r = c.post("/safety/halt")
    assert r.status_code == 401
    assert "operator-signed command required" in r.text


def test_halt_with_valid_command_attributed():
    c = next(_client())
    op = Ed25519PrivateKey.generate()
    _SAFETY_TENANT.operator_keys = OperatorKeyRing.from_pems([_pem(op)])
    # F2b: the gateway binds the command to the ACTUAL request body, which for an
    # empty POST is b"". The command must be signed over b"" to verify.
    cmd = _sign_cmd(op, verb="halt", body=b"", nonce=1)
    r = c.post("/safety/halt", headers=_cmd_header(cmd))
    assert r.status_code == 200 and r.json()["breaker_open"] is True
    # The command is attributed in the safety audit trail (Inv 3: pubkey recorded).
    assert any(e["event"] == "operator_command" and e["verb"] == "halt"
               for e in _safety_audit)
    assert _safety_audit[-1]["operator_pubkey_pem"] == _pem(op)


def test_replayed_nonce_refused():
    c = next(_client())
    op = Ed25519PrivateKey.generate()
    _SAFETY_TENANT.operator_keys = OperatorKeyRing.from_pems([_pem(op)])
    cmd = _sign_cmd(op, verb="resume", body=b"", nonce=7)
    r1 = c.post("/safety/resume", headers=_cmd_header(cmd))
    assert r1.status_code == 200
    # Replay the same nonce -> refused.
    r2 = c.post("/safety/resume", headers=_cmd_header(cmd))
    assert r2.status_code == 401
    assert "replay" in r2.text


def test_wrong_body_binding_refused():
    c = next(_client())
    op = Ed25519PrivateKey.generate()
    _SAFETY_TENANT.operator_keys = OperatorKeyRing.from_pems([_pem(op)])
    # Command signed over a NON-empty body, but the endpoint verifies against the
    # actual request body (b""). The mismatch must be refused (F2b binding).
    cmd = _sign_cmd(op, verb="resume", body=b"halt", nonce=3)
    r = c.post("/safety/resume", headers=_cmd_header(cmd))
    assert r.status_code == 401
    assert "body_hash" in r.text


def test_bad_signature_refused():
    c = next(_client())
    op = Ed25519PrivateKey.generate()
    _SAFETY_TENANT.operator_keys = OperatorKeyRing.from_pems([_pem(op)])
    cmd = _sign_cmd(op, verb="halt", body=b"", nonce=4)
    cmd.sig = "deadbeef"  # corrupt signature
    r = c.post("/safety/halt", headers=_cmd_header(cmd))
    assert r.status_code == 401
    assert "does not verify" in r.text


# --- unit-level: OperatorCommand / verify_command fail-closed ----------------

def test_verify_command_unit():
    # F5: commands are signed in the epoch-nanosecond domain (int(time.time()*1e9)),
    # so verify against an epoch-ns `now` (not the monotonic _clock).
    now_ns = int(time.time() * 1_000_000_000)
    op = Ed25519PrivateKey.generate()
    cmd = _sign_cmd(op, verb="halt", body=b"", nonce=0)
    ok, _ = verify_command(
        cmd, body=b"", allowlist_pems=[_pem(op)],
        used_nonces=set(), now=now_ns)
    assert ok is True
    # wrong body
    ok2, why = verify_command(
        cmd, body=b"different", allowlist_pems=[_pem(op)],
        used_nonces=set(), now=now_ns)
    assert ok2 is False and "body_hash" in why
    # replay
    ok3, why3 = verify_command(
        cmd, body=b"", allowlist_pems=[_pem(op)],
        used_nonces={0}, now=now_ns)
    assert ok3 is False and "replay" in why3
    # no allowlist
    ok4, why4 = verify_command(
        cmd, body=b"", allowlist_pems=[], used_nonces=set(), now=now_ns)
    assert ok4 is False and "allowlist" in why4
    # expired timestamp (signed ~61s before the verification time)
    stale = _sign_cmd(op, verb="halt", body=b"", nonce=1,
                     timestamp=(now_ns - 61_000_000_000))
    ok5, why5 = verify_command(
        stale, body=b"", allowlist_pems=[_pem(op)],
        used_nonces=set(), now=now_ns, max_age_s=60)
    assert ok5 is False and "timestamp" in why5

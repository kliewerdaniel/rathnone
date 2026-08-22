"""ADR 41/42/43 — harness authority gate over REAL TCP (uvicorn + httpx).

The in-process unit suite (test_harness_gate.py) proves the gate fn is
fail-closed. This file proves the *endpoint* honors that gate across a real
network boundary: a uvicorn server on a TCP socket, driven by a real
httpx.Client — not TestClient. This closes ADR 41 §7/§9's promise of a
live-transport (ADR 33 discipline) test and a demonstrable live halt.

ADR 43: once harness operators are provisioned, `apply` requires a SIGNED
OperatorCommand (verb="harness_apply") bound to the exact POST body. We prove
that over the wire: apply without a command => 401; apply with a valid signed
command => 200 ALLOW; a replayed command => 401; and a live /safety/halt still
overrides a signed-command apply to BLOCKED.
"""
import base64
import json
import os
import socket
import threading
import time

import httpx
import pytest
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.service.harness_auth import sign_harness_command


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _pem(key):
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _cmd_header(key, body):
    cmd = sign_harness_command(body, key)
    return base64.b64encode(json.dumps({
        "verb": cmd.verb, "tenant_id": cmd.tenant_id, "body_hash": cmd.body_hash,
        "nonce": cmd.nonce, "timestamp": cmd.timestamp, "operator_id": cmd.operator_id,
        "pubkey_pem": cmd.pubkey_pem, "sig": cmd.sig,
    }).encode()).decode()


@pytest.fixture
def live_harness():
    """Boot the real gateway over TCP with auth ENFORCED + a key set.

    Saves and restores the auth-related env vars so the rest of the suite is
    not polluted by the enforced-auth setting, and resets the shared breaker/
    registry state so each test is isolated.
    """
    _saved = {
        "RATHNONE_ENFORCE_AUTH": os.environ.get("RATHNONE_ENFORCE_AUTH"),
        "RATHNONE_API_KEY": os.environ.get("RATHNONE_API_KEY"),
    }
    os.environ["RATHNONE_ENFORCE_AUTH"] = "1"
    os.environ["RATHNONE_API_KEY"] = "testkey"
    os.environ.setdefault("RATHNONE_KEY_OPS", "keyops")

    from src.service.app import (
        app as gw_app, _registry, _meters, _breaker, _clock,
        configure_harness_operators, _HARNESS_USED_NONCES,
    )
    _registry._tenants.clear()
    _meters.clear()
    _breaker.resume()
    _clock._t = 0
    _HARNESS_USED_NONCES.clear()

    # Provision a harness operator so apply requires a signed command.
    op_key = Ed25519PrivateKey.generate()
    configure_harness_operators([_pem(op_key)])

    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    stop = threading.Event()
    config = uvicorn.Config(gw_app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)

    def _run():
        server.run()

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    deadline = time.time() + 10.0
    ready = False
    while time.time() < deadline:
        try:
            with httpx.Client(base_url=base, timeout=1.0) as probe:
                if probe.get("/operator/public-key").status_code == 200:
                    ready = True
                    break
        except Exception:  # noqa: BLE001
            time.sleep(0.1)
    if not ready:
        stop.set()
        server.should_exit = True
        t.join(timeout=5.0)
        for k, v in _saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        pytest.fail("gateway did not become ready over TCP")

    yield base, op_key

    stop.set()
    server.should_exit = True
    t.join(timeout=5.0)
    _breaker.resume()
    _registry._tenants.clear()
    _meters.clear()
    _HARNESS_USED_NONCES.clear()
    for k, v in _saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def test_harness_endpoint_rejects_without_key_over_tcp(live_harness):
    """Enforced auth: no key => 401, never a verdict."""
    base, _key = live_harness
    with httpx.Client(base_url=base, timeout=5.0) as c:
        r = c.post("/harness/authorize", json={"policy_allow": True})
    assert r.status_code == 401


def test_harness_endpoint_explore_allows_with_key_over_tcp(live_harness):
    """Enforced auth + valid key + AUTO policy (explore) => 200 ALLOW (shape)."""
    base, _key = live_harness
    with httpx.Client(base_url=base, timeout=5.0) as c:
        r = c.post(
            "/harness/authorize",
            headers={"Authorization": "Bearer testkey"},
            json={"policy_allow": True, "kind": "explore"},
        )
    assert r.status_code == 200
    body = r.json()
    assert {"decision", "reason", "breaker_open", "dormant"} <= set(body.keys())
    assert body["decision"] == "ALLOW"
    assert body["dormant"] is False


def test_harness_endpoint_apply_requires_signed_command_over_tcp(live_harness):
    """ADR 43: consequential apply REQUIRES a signed operator command over the wire."""
    base, op_key = live_harness
    headers = {"Authorization": "Bearer testkey"}
    body = {"policy_allow": True, "kind": "apply", "action": "git commit -m wip"}
    with httpx.Client(base_url=base, timeout=5.0) as c:
        # Without a command => 200 DENY_OPEN (application-level refusal; the
        # API key is present, so transport auth 401 does not apply).
        no_cmd = c.post("/harness/authorize", headers=headers, json=body)
        assert no_cmd.status_code == 200
        assert no_cmd.json()["decision"] == "DENY_OPEN"
        assert "operator-signed command required" in no_cmd.json()["reason"]
        # With a valid signed command => 200 ALLOW.
        signed = c.post(
            "/harness/authorize",
            headers={**headers, "X-Operator-Command": _cmd_header(op_key, body)},
            json=body,
        )
        assert signed.status_code == 200
        assert signed.json()["decision"] == "ALLOW"


def test_harness_endpoint_apply_replay_rejected_over_tcp(live_harness):
    """ADR 43: replaying a used command nonce => 200 DENY_OPEN (already used)."""
    base, op_key = live_harness
    headers = {"Authorization": "Bearer testkey"}
    body = {"policy_allow": True, "kind": "apply", "action": "git push"}
    h = _cmd_header(op_key, body)
    with httpx.Client(base_url=base, timeout=5.0) as c:
        first = c.post("/harness/authorize", headers={**headers, "X-Operator-Command": h}, json=body)
        assert first.status_code == 200
        assert first.json()["decision"] == "ALLOW"
        second = c.post("/harness/authorize", headers={**headers, "X-Operator-Command": h}, json=body)
        assert second.status_code == 200
        assert second.json()["decision"] == "DENY_OPEN"
        assert "already used" in second.json()["reason"]


def test_harness_endpoint_blocks_on_live_operator_halt_over_tcp(live_harness):
    """ADR 41 §9: a live /safety/halt flips the breaker the harness consults.

    We trip the breaker OVER THE WIRE (POST /safety/halt with the key), then
    re-query /harness/authorize and prove the harness gate now BLOCKS — even a
    signed-command apply is stopped by the operator panic button (not just in
    unit tests).
    """
    base, op_key = live_harness
    with httpx.Client(base_url=base, timeout=5.0) as c:
        headers = {"Authorization": "Bearer testkey"}
        # Pre-halt: explore would be allowed (AUTO).
        before = c.post(
            "/harness/authorize", headers=headers,
            json={"policy_allow": True, "kind": "explore"}
        )
        assert before.status_code == 200
        assert before.json()["decision"] == "ALLOW"

        # Trip the operator circuit breaker over the wire.
        halt = c.post("/safety/halt", headers=headers)
        assert halt.status_code == 200
        assert halt.json().get("breaker_open") is True

        # Post-halt: the SAME harness endpoint must now BLOCK over the wire
        # (explore or apply — breaker overrides everything).
        after = c.post(
            "/harness/authorize", headers=headers,
            json={"policy_allow": True, "kind": "explore"}
        )
        assert after.status_code == 200
        assert after.json()["decision"] == "BLOCKED"
        assert after.json()["breaker_open"] is True

        # A signed-command apply is ALSO stopped by the breaker.
        apply_body = {"policy_allow": True, "kind": "apply", "action": "git push"}
        apply_h = _cmd_header(op_key, apply_body)
        after_apply = c.post(
            "/harness/authorize", headers={**headers, "X-Operator-Command": apply_h},
            json=apply_body)
        assert after_apply.status_code == 200
        assert after_apply.json()["decision"] == "BLOCKED"
        assert after_apply.json()["breaker_open"] is True

        # Resume restores the harness to ALLOW.
        c.post("/safety/resume", headers=headers)
        restored = c.post(
            "/harness/authorize", headers=headers,
            json={"policy_allow": True, "kind": "explore"}
        )
        assert restored.json()["decision"] == "ALLOW"

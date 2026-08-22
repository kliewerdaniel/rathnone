"""ADR 41 — harness authority gate over REAL TCP (uvicorn + httpx).

The in-process unit suite (test_harness_gate.py) proves the gate fn is
fail-closed. This file proves the *endpoint* honors that gate across a real
network boundary: a uvicorn server on a TCP socket, driven by a real
httpx.Client — not TestClient. This closes ADR 41 §7/§9's promise of a
live-transport (ADR 33 discipline) test and a demonstrable live halt.

Because the uvicorn server runs in a thread in THIS process, it shares the live
_breaker object that the /harness/authorize route reads. Tripping /safety/halt
over the wire therefore flips the same breaker the harness endpoint consults —
the honest way to show "operator halt stops the harness loop" without faking the
verdict.
"""
import os
import socket
import threading
import time

import httpx
import pytest
import uvicorn


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def live_harness():
    """Boot the real gateway over TCP with auth ENFORCED + a key set.

    Saves and restores the auth-related env vars so the rest of the suite is
    not polluted by the enforced-auth setting, and resets the shared breaker/
    registry state so each test is isolated.
    """
    # --- save env so we don't leak ENFORCE_AUTH into later tests -----------
    _saved = {
        "RATHNONE_ENFORCE_AUTH": os.environ.get("RATHNONE_ENFORCE_AUTH"),
        "RATHNONE_API_KEY": os.environ.get("RATHNONE_API_KEY"),
    }
    os.environ["RATHNONE_ENFORCE_AUTH"] = "1"
    os.environ["RATHNONE_API_KEY"] = "testkey"
    os.environ.setdefault("RATHNONE_KEY_OPS", "keyops")

    from src.service.app import (
        app as gw_app, _registry, _meters, _breaker, _clock)
    # Reset shared state for isolation before the run.
    _registry._tenants.clear()
    _meters.clear()
    _breaker.resume()
    _clock._t = 0

    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    stop = threading.Event()
    config = uvicorn.Config(gw_app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)

    def _run():
        server.run()

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    # Wait for readiness via the ungated public-key endpoint (ADR 37).
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
        # restore env before failing
        for k, v in _saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        pytest.fail("gateway did not become ready over TCP")

    yield base

    stop.set()
    server.should_exit = True
    t.join(timeout=5.0)
    # --- restore env + reset shared state so the rest of the suite is clean -
    _breaker.resume()
    _registry._tenants.clear()
    _meters.clear()
    for k, v in _saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def test_harness_endpoint_rejects_without_key_over_tcp(live_harness):
    """Enforced auth: no key => 401, never a verdict."""
    base = live_harness
    with httpx.Client(base_url=base, timeout=5.0) as c:
        r = c.post("/harness/authorize", json={"policy_allow": True})
    assert r.status_code == 401


def test_harness_endpoint_allows_with_key_over_tcp(live_harness):
    """Enforced auth + valid key + AUTO policy => 200 ALLOW (documented shape)."""
    base = live_harness
    with httpx.Client(base_url=base, timeout=5.0) as c:
        r = c.post(
            "/harness/authorize",
            headers={"Authorization": "Bearer testkey"},
            json={"policy_allow": True},
        )
    assert r.status_code == 200
    body = r.json()
    assert {"decision", "reason", "breaker_open", "dormant"} <= set(body.keys())
    assert body["decision"] == "ALLOW"
    assert body["dormant"] is False


def test_harness_endpoint_blocks_on_live_operator_halt_over_tcp(live_harness):
    """ADR 41 §9: a live /safety/halt flips the breaker the harness consults.

    We trip the breaker OVER THE WIRE (POST /safety/halt with the key), then
    re-query /harness/authorize and prove the harness gate now BLOCKS — the
    operator panic button genuinely stops the harness, not just in unit tests.
    """
    base = live_harness
    with httpx.Client(base_url=base, timeout=5.0) as c:
        headers = {"Authorization": "Bearer testkey"}
        # Pre-halt: harness would be allowed.
        before = c.post(
            "/harness/authorize", headers=headers, json={"policy_allow": True}
        )
        assert before.status_code == 200
        assert before.json()["decision"] == "ALLOW"

        # Trip the operator circuit breaker over the wire.
        halt = c.post("/safety/halt", headers=headers)
        assert halt.status_code == 200
        assert halt.json().get("breaker_open") is True

        # Post-halt: the SAME harness endpoint must now BLOCK over the wire.
        after = c.post(
            "/harness/authorize", headers=headers, json={"policy_allow": True}
        )
        assert after.status_code == 200
        assert after.json()["decision"] == "BLOCKED"
        assert after.json()["breaker_open"] is True

        # Resume restores the harness to ALLOW.
        c.post("/safety/resume", headers=headers)
        restored = c.post(
            "/harness/authorize", headers=headers, json={"policy_allow": True}
        )
        assert restored.json()["decision"] == "ALLOW"

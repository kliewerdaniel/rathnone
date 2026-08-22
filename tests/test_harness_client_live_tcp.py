"""ADR 41 — HarnessAuthorizer consumer glue, verified over REAL TCP.

This is the missing half of ADR 41: the *client* a local agent harness
(Hermes/Codex) imports and calls before applying a consequential action. It
boots the real gateway over a uvicorn socket and drives HarnessAuthorizer
against the live /harness/authorize endpoint with a real httpx.Client.

Fail-closed assertions:
  * no control plane / wrong URL => may_apply False (refuse, not run open)
  * valid key + AUTO => may_apply True
  * live /safety/halt over the wire => may_apply False (operator panic stops it)
  * /safety/resume => may_apply True again
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
def live_planar():
    """Boot the real gateway over TCP with auth enforced; yield (base, authz)."""
    _saved = {
        "RATHNONE_ENFORCE_AUTH": os.environ.get("RATHNONE_ENFORCE_AUTH"),
        "RATHNONE_API_KEY": os.environ.get("RATHNONE_API_KEY"),
    }
    os.environ["RATHNONE_ENFORCE_AUTH"] = "1"
    os.environ["RATHNONE_API_KEY"] = "testkey"
    os.environ.setdefault("RATHNONE_KEY_OPS", "keyops")

    from src.service.app import (
        app as gw_app, _registry, _meters, _breaker, _clock)
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

    from src.service.harness_client import HarnessAuthorizer
    authz = HarnessAuthorizer(base_url=base, api_key="testkey")

    yield base, authz, "testkey"

    stop.set()
    server.should_exit = True
    t.join(timeout=5.0)
    _breaker.resume()
    _registry._tenants.clear()
    _meters.clear()
    for k, v in _saved.items():
        os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


def test_harness_authorizer_allows_with_key(live_planar):
    # Read-only research (explore) is silent AUTO -> allow.
    _base, authz, _key = live_planar
    assert authz.may_apply("read src/x.py", kind="explore") is True
    assert authz.last_verdict is not None
    assert authz.last_verdict.decision == "ALLOW"


def test_harness_authorizer_explore_is_silent_auto(live_planar):
    """ADR 42: read-only research needs no operator prompt -> True."""
    _base, authz, _key = live_planar
    assert authz.may_apply("read src/x.py", kind="explore") is True
    assert authz.last_verdict is not None
    assert authz.last_verdict.decision == "ALLOW"


def test_harness_authorizer_apply_requires_operator(live_planar):
    """ADR 42: consequential apply defaults to HUMAN -> refuse until approved."""
    _base, authz, _key = live_planar
    assert authz.may_apply("commit -m wip", kind="apply") is False
    assert authz.last_verdict is not None
    assert "HUMAN" in authz.last_verdict.reason
    # Operator acknowledges -> re-verified by control plane -> allow.
    assert authz.may_apply("commit -m wip", kind="apply", pre_approved=True) is True


def test_harness_authorizer_blocks_on_live_operator_halt(live_planar):
    """ADR 41 end-to-end: a live /safety/halt must stop the harness consumer."""
    base, authz, key = live_planar
    headers = {"Authorization": f"Bearer {key}"}
    # Pre-halt: consequential apply, operator pre-approved -> allowed.
    assert authz.may_apply("commit -m wip", kind="apply", pre_approved=True) is True
    # Trip the operator circuit breaker over the wire.
    with httpx.Client(base_url=base, timeout=5.0) as c:
        halt = c.post("/safety/halt", headers=headers)
    assert halt.status_code == 200
    assert halt.json().get("breaker_open") is True
    # Post-halt: even a pre-approved apply MUST refuse.
    assert authz.may_apply("commit -m wip", kind="apply", pre_approved=True) is False
    assert authz.last_verdict is not None
    assert authz.last_verdict.breaker_open is True
    # Resume restores the consumer to allow (pre-approved apply).
    with httpx.Client(base_url=base, timeout=5.0) as c:
        c.post("/safety/resume", headers=headers)
    assert authz.may_apply("commit -m wip", kind="apply", pre_approved=True) is True


def test_harness_authorizer_refuses_invalid_key(live_planar):
    base, _authz, _key = live_planar
    from src.service.harness_client import HarnessAuthorizer
    bad = HarnessAuthorizer(base_url=base, api_key="wrong-key")
    assert bad.may_apply("rm -rf /") is False
    assert bad.last_verdict is not None
    assert bad.last_verdict.decision in ("DENY_OPEN", "BLOCKED")


def test_harness_authorizer_refuses_when_plane_unreachable():
    """Fail-closed: an unreachable control plane => refuse, never run open."""
    from src.service.harness_client import HarnessAuthorizer
    # Port 1 is privileged/reserved; nothing listens there -> connection refused.
    authz = HarnessAuthorizer(base_url="http://127.0.0.1:1", api_key="testkey",
                              timeout=0.5, retries=0)
    assert authz.may_apply("destructive") is False
    assert authz.last_verdict is not None
    assert authz.last_verdict.reason.startswith("control-plane unreachable")

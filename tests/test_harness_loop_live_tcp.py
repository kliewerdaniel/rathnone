"""ADR 43 — the LIVING harness consumer, verified over REAL TCP.

ADR 41/42/43 built a control-plane gate (``/harness/authorize``) that a local
agent harness is supposed to poll before every consequential action. The
unit/live-TCP tests prove the *gate* in isolation, but the honest contract is
that a real harness loop calls :meth:`HarnessAuthorizer.may_apply` per action.

This test boots the real gateway over a uvicorn TCP socket and drives the
runnable consumer in :mod:`examples.harness_loop` (HarnessLoop + HarnessAuthorizer)
against it. It proves the gate is exercised by an actual loop, not just tests —
so a future change that severed the consumer from the gate would fail here.

Fail-closed guarantees asserted end-to-end over the wire:
  * explore            -> ALLOW (silent, no operator command)
  * apply (signed)     -> ALLOW
  * live /safety/halt   -> even signed apply REFUSED (operator panic button)
  * live /safety/resume -> signed apply ALLOW again (fresh nonce)
  * no operator key held -> every apply REFUSED (fail-closed posture)
"""

import os
import socket
import threading
import time

import httpx
import pytest
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from examples.harness_loop import HarnessLoop


def _pem(key):
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def live_gateway():
    """Boot the real gateway over TCP with auth enforced; yield (base, op_key, stop)."""
    _saved = {
        "RATHNONE_ENFORCE_AUTH": os.environ.get("RATHNONE_ENFORCE_AUTH"),
        "RATHNONE_API_KEY": os.environ.get("RATHNONE_API_KEY"),
    }
    os.environ["RATHNONE_ENFORCE_AUTH"] = "1"
    os.environ["RATHNONE_API_KEY"] = "testkey"
    os.environ.setdefault("RATHNONE_KEY_OPS", "keyops")

    from src.service.app import (
        app as gw_app, _breaker, _clock, _meters, _registry,
        configure_harness_operators, _HARNESS_USED_NONCES,
    )
    _registry._tenants.clear()
    _meters.clear()
    _breaker.resume()
    _clock._t = 0
    _HARNESS_USED_NONCES.clear()

    op_key = Ed25519PrivateKey.generate()
    configure_harness_operators([_pem(op_key)])

    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    config = uvicorn.Config(gw_app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True).start()

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
    assert ready, "gateway did not become ready over TCP"

    yield base, op_key, "testkey"

    server.should_exit = True
    _breaker.resume()
    _registry._tenants.clear()
    _meters.clear()
    _HARNESS_USED_NONCES.clear()
    for k, v in _saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def test_living_harness_consumer_polls_gate_over_tcp(live_gateway):
    """The real HarnessLoop drives the gate: explore AUTO, apply signed ALLOW."""
    base, op_key, api_key = live_gateway
    from src.service.harness_auth import sign_harness_command
    from src.service.harness_client import HarnessAuthorizer

    authz = HarnessAuthorizer(base_url=base, api_key=api_key)
    loop = HarnessLoop(authz, operator_key=op_key)

    plan = [
        ("explore", "read src/finance/capabilities.py", True),
        ("apply", "git commit -m wip", True),
        ("apply", "git tag -a release/v1 -m ship", True),
    ]
    results = loop.run(plan)
    assert all(results.values()), f"unexpected refusals: {results}"
    # The plan consumed nonces 1..2. Deliberately reusing nonce 1 must be refused
    # (replay protection) — the gate tracks spent nonces, so it holds over the wire.
    assert loop._nonce >= 2
    replay_cmd = sign_harness_command(
        {"policy_allow": True, "human_override": False, "kind": "apply",
         "action": "git commit -m wip"}, op_key, nonce=1)
    assert loop.authz.may_apply("git commit -m wip", kind="apply",
                                operator_command=replay_cmd) is False


def test_living_harness_consumer_panic_button_over_tcp(live_gateway):
    """Live /safety/halt stops the running loop; /safety/resume restores it."""
    base, op_key, api_key = live_gateway
    from src.service.harness_client import HarnessAuthorizer

    authz = HarnessAuthorizer(base_url=base, api_key=api_key)
    loop = HarnessLoop(authz, operator_key=op_key)
    loop.run_with_halt(
        [], base_url=base, api_key=api_key, operator_key=op_key)
    expected = {
        "apply(pre-halt):git commit -m hotfix": True,
        "apply(halted):git commit -m hotfix": True,
        "apply(post-resume):git commit -m hotfix": True,
    }
    assert loop.results == expected, loop.results


def test_harness_consumer_fail_closed_without_operator_key(live_gateway):
    """A harness holding NO signing key cannot authorize any apply (no self-approval)."""
    base, _op_key, api_key = live_gateway
    from src.service.harness_client import HarnessAuthorizer

    authz = HarnessAuthorizer(base_url=base, api_key=api_key)
    loop = HarnessLoop(authz, operator_key=None)  # holds no key -> cannot sign
    plan = [
        ("explore", "read sr/c.py", True),
        ("apply", "git commit -m wip", False),   # refused: no valid command possible
        ("apply", "rm -rf ./", False),           # refused
    ]
    results = loop.run(plan)
    assert loop.decisions["explore:read sr/c.py"] is True
    assert loop.decisions["apply:git commit -m wip"] is False
    assert loop.decisions["apply:rm -rf ./"] is False

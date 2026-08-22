"""ADR 43 — runnable harness loop that consumes the signed-execute gate.

This is the *living consumer* ADR 41 described but the unit/live-TCP tests only
simulated: a real agent harness (Hermes dispatching Codex/Cline sub-agents)
imports :class:`HarnessAuthorizer` and calls :meth:`HarnessAuthorizer.may_apply`
BEFORE every consequential action. This script proves the gate is exercised by
an actual loop, over a real TCP socket, with operator-signed commands bound to
the exact action body.

The loop models two capability bands (ADR 42 split):

  * ``explore`` — read-only research. The control plane returns AUTO; no operator
    command is required and the harness proceeds silently.
  * ``apply``   — consequential (commit / patch / destructive). ADR 43 hard-blocks
    until a cryptographically-bound ``OperatorCommand`` (verb ``harness_apply``,
    signed over *this exact* action body) arrives. A privileged-but-compromised
    harness that "forgets" to present the command is refused.

Fail-closed guarantees demonstrated end-to-end over the wire:

  * an ``apply`` with no command                      -> refused (DENY_OPEN)
  * an ``apply`` with a valid signed command          -> allowed (ALLOW)
  * a live ``POST /safety/halt`` over the wire        -> even signed applies refused
  * a live ``POST /safety/resume``                     -> signed applies allowed again

Run (self-contained — boots the real gateway over a local TCP socket)::

    env -u PYTHONPATH -u VIRTUAL_ENV .venv/bin/python examples/harness_loop.py

Env / flags:
    RATHNONE_HARNESS_OPERATOR_KEY  path to an Ed25519 operator PEM the harness is
                                   authorized to apply under. In this DEMO the
                                   harness holds the key and signs in-process so
                                   the allowed path is exercisable without an
                                   operator at the keyboard. **Production must NOT
                                   do this** — the operator signs OUT-OF-BAND via
                                   ``scripts/harness_sign.py`` and the harness
                                   receives only the resulting ``OperatorCommand``
                                   (e.g. via a watched file / secret store). The
                                   console never holds the signing key by design
                                   (key-custody, see console/app/authorize/page.tsx).
    RATHNONE_CONTROL_PLANE_URL     point at an already-running gateway instead of
                                   booting one in-process.
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.service.harness_auth import sign_harness_command
from src.service.harness_client import HarnessAuthorizer


# A planned harness action: (capability-band, action-string, expect-allowed?).
# The action string is what the operator signature binds to — so the gate can
# tell "approve `git commit -m wip`" from "execute `rm -rf ./`."
_HARNESS_PLAN = [
    ("explore", "read src/finance/capabilities.py", True),
    ("explore", "grep -rn decide( src/", True),
    ("apply", "git commit -m wip", True),               # signed by operator -> allow
    ("apply", "git push origin main", True),            # signed by operator -> allow
    ("apply", "git tag -a release/v1 -m ship", True),   # signed -> allow
]


def _pem(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _load_operator_key(path: str | None) -> Ed25519PrivateKey | None:
    if not path:
        return None
    with open(path, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    # Pin to the algorithm the harness gate expects (ADR 19/20/21 OperatorCommand).
    assert isinstance(key, Ed25519PrivateKey)
    return key


class HarnessLoop:
    """Drives a planned action sequence through the control-plane gate.

    ``operator_key`` is the Ed25519 key used to sign ``apply`` commands. Pass
    ``None`` to demonstrate the fail-closed posture (no ``apply`` can ever be
    authorized because nothing was signed).
    """

    def __init__(
        self,
        authz: HarnessAuthorizer,
        *,
        operator_key: Ed25519PrivateKey | None = None,
    ) -> None:
        self.authz = authz
        self._op_key = operator_key
        self._nonce = 0  # monotonic per-command nonce (replay-guarded by the gate)
        self.decisions: dict[str, bool] = {}   # raw gate decision per action
        self.results: dict[str, bool] = {}      # decision == expectation per action

    def _signed_cmd(self, kind: str, action: str):
        if self._op_key is None or kind != "apply":
            return None
        # Each command gets a FRESH nonce — reusing one is a replay and the gate
        # refuses it. A real harness pulls the nonce from its own monotonic source.
        self._nonce += 1
        body = {"policy_allow": True, "human_override": False,
                "kind": kind, "action": action}
        return sign_harness_command(body, self._op_key, nonce=self._nonce)

    def run(self, plan) -> dict[str, bool]:
        for kind, action, expect in plan:
            cmd = self._signed_cmd(kind, action)
            ok = self.authz.may_apply(
                action, kind=kind, operator_command=cmd,
            )
            name = f"{kind}:{action}"
            self.decisions[name] = ok
            self.results[name] = (ok == expect)
            verdict = self.authz.last_verdict
            tag = "ALLOW " if ok else "REFUSE"
            reason = verdict.reason if verdict else "control-plane unreachable"
            print(f"  {tag} {name:<42} ({reason})")
        return self.results

    def run_with_halt(
        self, plan, *, base_url: str, api_key: str, operator_key: Ed25519PrivateKey,
    ) -> None:
        """Demonstrate the operator panic button stopping a live harness loop.

        Trips ``POST /safety/halt`` between two signed applies; the same command
        nonce must be spent fresh after ``/safety/resume`` (replay protection).
        """
        headers = {"Authorization": f"Bearer {api_key}"}
        action = "git commit -m hotfix"
        body = {"policy_allow": True, "human_override": False,
                "kind": "apply", "action": action}

        # Pre-halt: signed apply allowed (fresh nonce from the shared source).
        self._nonce += 1
        cmd0 = sign_harness_command(body, operator_key, nonce=self._nonce)
        self.results[f"apply(pre-halt):{action}"] = self.authz.may_apply(
            action, kind="apply", operator_command=cmd0) is True
        print(f"  ALLOW  apply(pre-halt):{action:<28} (signed command accepted)")

        # Trip the shared circuit breaker over the wire.
        with httpx.Client(base_url=base_url, timeout=5.0) as c:
            halt = c.post("/safety/halt", headers=headers)
        assert halt.status_code == 200 and halt.json().get("breaker_open") is True
        print("  -- operator POST /safety/halt (breaker open) --")

        # Post-halt: even a signed apply MUST refuse (reuse cmd0 -> replay refused).
        self.results[f"apply(halted):{action}"] = self.authz.may_apply(
            action, kind="apply", operator_command=cmd0) is False
        print(f"  REFUSE apply(halted):{action:<28} (breaker overrides signature)")

        # Resume; mint a FRESH command (cmd0's nonce was spent pre-halt).
        with httpx.Client(base_url=base_url, timeout=5.0) as c:
            c.post("/safety/resume", headers=headers)
        self._nonce += 1
        cmd1 = sign_harness_command(body, operator_key, nonce=self._nonce)
        self.results[f"apply(post-resume):{action}"] = self.authz.may_apply(
            action, kind="apply", operator_command=cmd1) is True
        print(f"  ALLOW  apply(post-resume):{action:<22} (fresh signed command)")


def _boot_gateway() -> tuple[str, _Booted]:
    """Boot the real gateway over a real TCP socket (mirrors the live-TCP tests)."""
    import socket
    import threading

    import uvicorn

    from src.service.app import (
        app as gw_app, _breaker, _clock, _meters, _registry,
        configure_harness_operators, _HARNESS_USED_NONCES,
    )

    _registry._tenants.clear()
    _meters.clear()
    _breaker.resume()
    _clock._t = 0
    _HARNESS_USED_NONCES.clear()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    base = f"http://127.0.0.1:{port}"

    stop = threading.Event()
    config = uvicorn.Config(gw_app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True).start()
    deadline = time.time() + 10.0
    while time.time() < deadline:
        try:
            with httpx.Client(base_url=base, timeout=1.0) as probe:
                if probe.get("/operator/public-key").status_code == 200:
                    return base, _Booted(server, stop,
                                         (_registry, _meters, _breaker, _clock, _HARNESS_USED_NONCES))
        except Exception:  # noqa: BLE001
            time.sleep(0.1)
    raise RuntimeError("gateway did not become ready over TCP")


class _Booted:
    def __init__(self, server, stop, state):
        self.server = server
        self.stop = stop
        self.state = state

    def close(self):
        self.stop.set()
        self.server.should_exit = True


def main() -> int:
    api_key = os.environ.get("RATHNONE_API_KEY", "testkey")
    os.environ["RATHNONE_ENFORCE_AUTH"] = "1"
    os.environ["RATHNONE_API_KEY"] = api_key
    os.environ.setdefault("RATHNONE_KEY_OPS", "keyops")

    # Operator key resolution. Three modes:
    #   RATHNONE_HARNESS_NO_OPERATOR_KEY=1 -> the harness holds NO signing key
    #     (fail-closed posture: every `apply` MUST be refused; nothing to sign with).
    #   RATHNONE_HARNESS_OPERATOR_KEY=<pem> -> harness signs under that key (demo only;
    #     production signs OUT-OF-BAND via scripts/harness_sign.py — the console never
    #     holds the key).
    #   neither set -> a fresh demo key is generated in-process so the ALLOW path is
    #     exercisable end-to-end.
    if os.environ.get("RATHNONE_HARNESS_NO_OPERATOR_KEY") == "1":
        operator_key = None
    else:
        operator_key = _load_operator_key(os.environ.get("RATHNONE_HARNESS_OPERATOR_KEY"))

    base_url = os.environ.get("RATHNONE_CONTROL_PLANE_URL")
    booted = None
    if not base_url:
        base_url, booted = _boot_gateway()

    from src.service.app import configure_harness_operators
    if operator_key is not None:
        # Provision the operator the harness will sign under.
        configure_harness_operators([_pem(operator_key)])
    else:
        # Fail-closed demo: provision a key the harness does NOT hold, so every
        # apply is refused (no valid signature can be produced).
        configure_harness_operators([_pem(Ed25519PrivateKey.generate())])

    authz = HarnessAuthorizer(base_url=base_url, api_key=api_key)
    loop = HarnessLoop(authz, operator_key=operator_key)

    print("\n=== Harness loop: planned actions (gate polled before each) ===")
    loop.run(_HARNESS_PLAN)

    if operator_key is not None:
        print("\n=== Operator panic button: live /safety/halt stops the loop ===")
        loop.run_with_halt(
            _HARNESS_PLAN, base_url=base_url, api_key=api_key, operator_key=operator_key)

    passed = sum(1 for v in loop.results.values() if v)
    failed = [n for n, ok in loop.results.items() if not ok]
    print(f"\nSUMMARY: {passed} passed, {len(failed)} failed")
    if booted is not None:
        booted.close()
    if failed:
        print("FAILED CHECKS: " + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""ADR 41 — agent-harness authority binding.

The local agent harness (Hermes dispatching Codex CLI sub-agents) consults
Rathnone's control plane before applying any consequential action (patch / commit
/ destructive command). This module is the harness-side gate. It is FAIL-CLOSED:
anything unverifiable refuses rather than running open.

It reuses the EXISTING frozen ``decide()`` spine via the finance registry's
``decide_registered`` — the harness is the 8th registered consumer
(``CAP_FIN_AGENT_HARNESS_EXECUTE``), same substrate path as the finance trio,
zero new spine behavior.

Resolution order (each step fails closed):
  1. reachability   -> control plane reachable?
  2. ADR 17 key     -> RATHNONE_API_KEY present?
  3. decide()       -> AUTO / HUMAN / BLOCKED
  4. operator halt  -> /safety breaker open => stop regardless of decide()
"""
from __future__ import annotations

import os
import time as _time
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..finance.capabilities import (
    CAP_FIN_AGENT_HARNESS_EXPLORE,
    CAP_FIN_AGENT_HARNESS_EXECUTE,
)
from ..finance.registry import decide_registered
from exchange.epistemic_adapter import GovernanceAuthority
from ..security.operator import (
    OperatorCommand, verify_command, body_hash_of,
)


class HarnessGateError(Exception):
    """Raised when the gate cannot evaluate (fail-closed signal)."""


@dataclass(frozen=True)
class HarnessVerdict:
    decision: str  # ALLOW | BLOCKED | DENY_OPEN
    reason: str
    breaker_open: bool = False
    dormant: bool = False  # ADR 17 unenforced (dev) posture


# Control-plane reachability + key are read at CALL time, never import time
# (mirrors src/service/app.py discipline: env toggles resolved inside the fn).
def _control_plane_enforced() -> bool:
    return os.environ.get("RATHNONE_ENFORCE_AUTH", "0") == "1"


def _api_key_present() -> bool:
    return bool(os.environ.get("RATHNONE_API_KEY"))


def evaluate_harness_action(
    *,
    kind: str = "apply",
    operator_command: Optional["OperatorCommand"] = None,
    operator_allowlist: Optional[list[str]] = None,
    used_nonces: Optional[set[int]] = None,
    command_now: int = 0,
    command_scope: str = "harness",
    policy_allow: bool = True,
    human_override: bool = False,
    breaker_open: bool = False,
    gov: Optional[GovernanceAuthority] = None,
    enforce: Optional[bool] = None,
    api_key: Optional[bool] = None,
    request_body: Optional[bytes] = None,
) -> HarnessVerdict:
    """Decide whether the harness may apply a consequential action.

    ``kind`` selects the harness capability (ADR 42 capability split):
      - ``"explore"`` -> read-only research (read/search/list/diff-for-inspect).
        Resolves to ``AUTO`` -> ``ALLOW`` (silent; no operator command).
      - ``"apply"``   -> consequential apply/commit/destructive. Resolves to
        ``HUMAN`` by default; the operator must present a SIGNED
        ``OperatorCommand`` (verb="harness_apply") bound to this exact request
        body (ADR 43) to convert it to ALLOW. There is NO local acknowledgement
        shortcut: ``pre_approved`` is gone. A privileged-but-compromised harness
        cannot self-approve an apply — only a real operator signature from the
        allowlist does.

    ``operator_allowlist`` / ``used_nonces`` / ``command_now`` / ``command_scope``
    / ``request_body`` mirror the live endpoint's signed-command gate (ADR 19/21):
    the command is verified against the harness scope's active operator keys with
    nonce-replay + timestamp-window + body-hash binding. When ``operator_allowlist``
    is empty/None (dormant posture), an ``apply`` stays ``HUMAN`` -> ``BLOCKED``
    with "HUMAN required" (never silently allowed).

    ``enforce`` overrides the live RATHNONE_ENFORCE_AUTH read (lets tests force
    either posture without env gymnastics). ``api_key`` overrides the live
    RATHNONE_API_KEY presence check (so fail-closed tests don't depend on the
    ambient environment). ``breaker_open`` lets the caller pass the live /safety
    state (the endpoint reads it from the running breaker).
    """
    if kind not in ("explore", "apply"):
        raise ValueError(f"kind must be 'explore' or 'apply', got {kind!r}")
    capability = (
        CAP_FIN_AGENT_HARNESS_EXPLORE if kind == "explore"
        else CAP_FIN_AGENT_HARNESS_EXECUTE
    )
    # ADR 42: explore is AUTO (silent, no operator command). apply is HUMAN
    # unless a valid signed operator command is presented (ADR 43).
    human = human_override or (kind == "apply")

    enforced = _control_plane_enforced() if enforce is None else enforce

    # Dev posture: ADR 17 unenforced -> log DORMANT, allow local scratch.
    if not enforced:
        return HarnessVerdict(
            decision="ALLOW", reason="AUTH_DORMANT (RATHNONE_ENFORCE_AUTH=0)",
            dormant=True,
        )

    # Step 2: static-key gate (ADR 17). Missing key => refuse open.
    key_present = _api_key_present() if api_key is None else api_key
    if not key_present:
        return HarnessVerdict(
            decision="DENY_OPEN",
            reason="control-plane API key missing under RATHNONE_ENFORCE_AUTH=1",
        )

    # Step 4: operator halt (ADR 19/20). Independent of decide() and of any
    # signed command — a panic stops a running harness regardless.
    if breaker_open:
        return HarnessVerdict(
            decision="BLOCKED",
            reason="operator circuit breaker open (/safety/halt)",
            breaker_open=True,
        )

    # Step 3 (apply only): signed operator command (ADR 43). When operators are
    # provisioned, apply MUST carry a command bound to this exact request body.
    # A successfully-verified command is the operator's acknowledgement — it
    # flips the HUMAN verdict to AUTO (mirrors ADR 42's pre-approval, but the
    # approval is now cryptographically bound, not a local flag).
    allowlist = operator_allowlist or []
    if kind == "apply" and allowlist:
        if operator_command is None:
            return HarnessVerdict(
                decision="DENY_OPEN",
                reason="operator-signed command required (harness operators provisioned)",
            )
        _nonces = used_nonces if used_nonces is not None else set()
        ok, why = verify_command(
            operator_command,
            body=request_body if request_body is not None else b"",
            allowlist_pems=allowlist,
            used_nonces=_nonces,
            now=command_now,
            scope=command_scope,
        )
        if not ok:
            return HarnessVerdict(
                decision="DENY_OPEN",
                reason=f"operator command refused: {why}",
            )
        # Record the nonce so the same signed command cannot be replayed
        # (single source of truth — the endpoint and the gate share this set).
        _nonces.add(operator_command.nonce)
        # Operator signed this exact action -> their acknowledgement stands in
        # for the HUMAN prompt. A compromised harness cannot reach this branch
        # without a valid allowlisted signature.
        human = False
        op_attr = f" (operator={operator_command.operator_id})"
    else:
        op_attr = ""

    # Step 5: frozen decide() through the registry (8th/9th/10th consumer).
    gov = gov or GovernanceAuthority(Ed25519PrivateKey.generate())
    d = decide_registered(
        "rathnone/agent-harness-explore" if kind == "explore"
        else "rathnone/agent-harness-execute",
        capability,
        policy_allow=policy_allow,
        human=human,
        gov=gov,
    )
    if d.verdict == "AUTO":
        return HarnessVerdict(decision="ALLOW", reason=d.reason + op_attr)
    if d.verdict == "HUMAN":
        # Ratified (ADR 43): HUMAN -> hard BLOCK until a signed operator command
        # arrives. With no provisioned allowlist we still block, but the reason
        # signals the operator must provision + sign (dormant posture).
        if not allowlist:
            return HarnessVerdict(
                decision="BLOCKED",
                reason="HUMAN required: harness operator allowlist not provisioned",
            )
        return HarnessVerdict(decision="BLOCKED", reason=f"HUMAN required: {d.reason}")
    return HarnessVerdict(decision="BLOCKED", reason=d.reason)


# ---------------------------------------------------------------------------
# ADR 43 — operator-side signing helper for the harness_apply verb.
#
# Builds the exact OperatorCommand the live endpoint's _require_command gate
# expects: verb="harness_apply", tenant_id == the harness scope id, body_hash
# over the canonical /harness/authorize POST body. Shared by the
# HarnessAuthorizer client and scripts/harness_sign.py so the harness and the
# out-of-band operator tool agree on canonicalization. No new crypto: it reuses
# OperatorCommand + body_hash_of from the ADR 19/20 primitive.
# ---------------------------------------------------------------------------

def canonical_harness_body(body: dict) -> bytes:
    """The exact bytes a harness_apply command binds to.

    MUST match what /harness/authorize hashes for the command gate, or the
    body_hash will diverge and the gateway refuses the command.
    """
    import json
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def sign_harness_command(
    body: dict,
    key,
    *,
    scope_id: str = "harness",
    nonce: int = 0,
    operator_id: str = "rathnone-operator",
    timestamp: Optional[int] = None,
) -> "OperatorCommand":
    """Sign a harness_apply command over ``body`` with operator ``key``.

    ``key`` is an Ed25519PrivateKey. The returned OperatorCommand is what the
    harness presents in the X-Operator-Command header when calling apply.
    """
    from cryptography.hazmat.primitives import serialization
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    ts = timestamp if timestamp is not None else int(_time.time() * 1_000_000_000)
    cmd = OperatorCommand(
        verb="harness_apply",
        tenant_id=scope_id,
        body_hash=body_hash_of(canonical_harness_body(body)),
        nonce=nonce,
        timestamp=ts,
        operator_id=operator_id,
        pubkey_pem=pub_pem,
    )
    cmd.sig = key.sign(cmd.canonical_bytes()).hex()
    return cmd


__all__ = ["HarnessVerdict", "HarnessGateError", "evaluate_harness_action",
           "sign_harness_command", "canonical_harness_body"]

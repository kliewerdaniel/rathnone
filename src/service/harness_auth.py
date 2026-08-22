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
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..finance.capabilities import (
    CAP_FIN_AGENT_HARNESS_EXPLORE,
    CAP_FIN_AGENT_HARNESS_EXECUTE,
)
from ..finance.registry import decide_registered
from exchange.epistemic_adapter import GovernanceAuthority


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
    pre_approved: bool = False,
    policy_allow: bool = True,
    human_override: bool = False,
    breaker_open: bool = False,
    gov: Optional[GovernanceAuthority] = None,
    enforce: Optional[bool] = None,
    api_key: Optional[bool] = None,
) -> HarnessVerdict:
    """Decide whether the harness may apply a consequential action.

    ``kind`` selects the harness capability (ADR 42 capability split):
      - ``"explore"`` -> read-only research (read/search/list/diff-for-inspect).
        Resolves to ``AUTO`` -> ``ALLOW`` (silent; no operator prompt).
      - ``"apply"``   -> consequential apply/commit/destructive. Resolves to
        ``HUMAN`` unless the operator has acknowledged it via ``pre_approved``,
        in which case it is re-requested as ``AUTO`` -> ``ALLOW``.

    ``pre_approved`` is NOT a local bypass: it re-requests the verdict with
    ``require_human_approval=False`` so the control plane re-verifies the
    operator's acknowledgement. Fail-closed default is ``pre_approved=False``.

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
    # ADR 42: explore is AUTO; apply is HUMAN unless the operator pre-approved
    # (re-requested through the control plane, not honored locally). Pre-approval
    # flips only the HUMAN acknowledgement; it never overrides a policy DENY
    # (a capability outside the allowlist stays HUMAN/BLOCKED).
    human = human_override or (kind == "apply" and not pre_approved)

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

    # Step 4: operator halt (ADR 19/20). Independent of decide().
    if breaker_open:
        return HarnessVerdict(
            decision="BLOCKED",
            reason="operator circuit breaker open (/safety/halt)",
            breaker_open=True,
        )

    # Step 3: frozen decide() through the registry (8th/9th/10th consumer).
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
        return HarnessVerdict(decision="ALLOW", reason=d.reason)
    if d.verdict == "HUMAN":
        # Ratified: HUMAN -> prompt the operator in this terminal.
        return HarnessVerdict(decision="BLOCKED", reason=f"HUMAN required: {d.reason}")
    return HarnessVerdict(decision="BLOCKED", reason=d.reason)


__all__ = ["HarnessVerdict", "HarnessGateError", "evaluate_harness_action"]

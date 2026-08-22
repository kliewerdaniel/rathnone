"""ADR 41 — harness-side consumer client for the control-plane gate.

The server gate lives in :mod:`src.service.harness_auth` (and the
``/harness/authorize`` route in :mod:`src.service.app`). This module is the
*other half*: the glue the ADR promises but never shipped. A local agent
harness (Hermes dispatching Codex/Cline sub-agents) imports :class:`HarnessAuthorizer`
and calls :meth:`HarnessAuthorizer.may_apply` BEFORE applying any consequential
action (patch / commit / destructive command). It polls ``/harness/authorize``
over real HTTP, so it exercises the same fail-closed decision the live gateway
enforces — not an in-process shortcut.

Fail-closed contract (anything ambiguous => refuse):
  * control plane unreachable / network error -> BLOCKED
  * response missing the expected shape    -> BLOCKED
  * decision != "ALLOW"                    -> BLOCKED
  * operator circuit breaker open          -> BLOCKED (breaker_open True)
A ``DORMANT`` verdict (control plane unenforced, dev posture) is treated as a
soft-allow *only* when the operator explicitly opts in via ``allow_dormant``;
default refuses, so a misconfigured dev surface cannot silently run open.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Optional

import httpx

from .harness_auth import HarnessVerdict


class HarnessAuthorizer:
    """Client that gates a harness apply-action against the control plane.

    Usage::

        auth = HarnessAuthorizer(base_url="http://127.0.0.1:8765",
                                 api_key=os.environ["RATHNONE_API_KEY"])
        if auth.may_apply("patch main.py"):
            apply_patch(...)
        else:
            refuse(reason=auth.last_reason)
    """

    def __init__(
        self,
        *,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 5.0,
        retries: int = 1,
        backoff: float = 0.2,
        allow_dormant: bool = False,
    ) -> None:
        """Resolve connection settings at call time (mirrors app.py discipline).

        ``base_url`` defaults to ``RATHNONE_CONTROL_PLANE_URL`` (or
        ``http://127.0.0.1:8765``). ``api_key`` defaults to ``RATHNONE_API_KEY``.
        """
        self.base_url = (
            base_url
            or os.environ.get("RATHNONE_CONTROL_PLANE_URL")
            or "http://127.0.0.1:8765"
        ).rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("RATHNONE_API_KEY")
        self.timeout = timeout
        self.retries = max(0, retries)
        self.backoff = backoff
        self.allow_dormant = allow_dormant
        self.last_verdict: Optional[HarnessVerdict] = None
        self.last_reason: str = ""

    # -- public API ---------------------------------------------------------

    def may_apply(self, action: str, *, human_override: bool = False) -> bool:
        """Return True only if the control plane grants an unqualified ALLOW.

        Every other outcome (unreachable, malformed, BLOCKED, DENY_OPEN,
        breaker-open, or DORMANT-without-opt-in) returns False and records the
        reason on :attr:`last_reason`.
        """
        verdict = self._query(policy_allow=True, human_override=human_override)
        self.last_verdict = verdict
        self.last_reason = verdict.reason if verdict else self.last_reason
        if verdict is None:
            return False  # unreachable / malformed -> refuse
        if verdict.decision == "ALLOW" and not verdict.dormant:
            return True
        if verdict.decision == "ALLOW" and verdict.dormant and self.allow_dormant:
            return True
        return False

    # -- internals ----------------------------------------------------------

    def _query(self, *, policy_allow: bool, human_override: bool) -> Optional[HarnessVerdict]:
        """Call /harness/authorize; translate to a HarnessVerdict (None = refuse)."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = {"policy_allow": policy_allow, "human_override": human_override}
        attempt = 0
        last_err: Optional[str] = None
        while attempt <= self.retries:
            attempt += 1
            try:
                with httpx.Client(base_url=self.base_url, timeout=self.timeout) as c:
                    r = c.post("/harness/authorize", json=body, headers=headers)
                if r.status_code == 401:
                    # Missing/invalid key under enforced auth => refuse open.
                    return HarnessVerdict(
                        decision="DENY_OPEN",
                        reason="control-plane 401: API key rejected",
                    )
                if r.status_code != 200:
                    last_err = f"control-plane returned HTTP {r.status_code}"
                    if attempt <= self.retries:
                        time.sleep(self.backoff)
                        continue
                    return HarnessVerdict(decision="BLOCKED", reason=last_err)
                return self._to_verdict(r.json())
            except (httpx.HTTPError, ValueError) as exc:  # network or JSON error
                last_err = f"control-plane unreachable: {exc}"
                if attempt <= self.retries:
                    time.sleep(self.backoff)
                    continue
                # Fail-closed: unreachable => refuse, never run open.
                return HarnessVerdict(decision="BLOCKED", reason=last_err)
        return None

    @staticmethod
    def _to_verdict(payload: dict) -> Optional[HarnessVerdict]:
        """Coerce a response body to HarnessVerdict; malformed => None (refuse)."""
        try:
            decision = str(payload["decision"])
            if decision not in ("ALLOW", "BLOCKED", "DENY_OPEN"):
                raise KeyError("decision")
            return HarnessVerdict(
                decision=decision,
                reason=str(payload.get("reason", "")),
                breaker_open=bool(payload.get("breaker_open", False)),
                dormant=bool(payload.get("dormant", False)),
            )
        except (KeyError, TypeError):
            return None


__all__ = ["HarnessAuthorizer"]

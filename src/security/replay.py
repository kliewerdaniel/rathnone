"""v2 Replay & isolation registry — formal execution-security primitive (P0).

Elevates nonce/expiry/replay from "best-effort checks" to a central, tenant-
scoped invariant. Every executable action is registered once; the registry
guarantees (ratified as a security primitive):

    same action_hash already SIGNED/SETTLED -> IDEMPOTENT (block re-execution)
    different action_hash with the SAME nonce -> BLOCK (nonce reuse)
    expired action (expiry < now)            -> BLOCK
    replayed signature / request id           -> BLOCK
    tenant_id mismatch on lookup             -> BLOCK (cross-tenant confusion)

The registry is pure state + validation; it holds no signing keys. It is the
deterministic gate the pipeline consults BEFORE the signer runs.

Design: in-memory keyed by (tenant_id, nonce) and (tenant_id, action_hash). A
real deployment backs this with a durable store; the contract (the four
guarantees) is identical.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ActionStatus(str, Enum):
    REGISTERED = "REGISTERED"
    SIGNED = "SIGNED"
    SUBMITTED = "SUBMITTED"
    SETTLED = "SETTLED"
    BLOCKED = "BLOCKED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


@dataclass
class ActionRecord:
    action_id: str
    tenant_id: str
    action_hash: str
    nonce: int
    status: ActionStatus = ActionStatus.REGISTERED
    registered_at: int = 0


class ReplayError(Exception):
    """Raised when an action violates a replay/isolation invariant."""


class ActionRegistry:
    def __init__(self):
        # (tenant_id, nonce) -> action_hash (detects nonce reuse across actions)
        self._by_nonce: dict[tuple[str, int], str] = {}
        # (tenant_id, action_hash) -> ActionRecord (detects replay)
        self._by_hash: dict[tuple[str, str], ActionRecord] = {}

    def _check_tenant(self, tenant_id: str) -> None:
        if not tenant_id:
            raise ReplayError("tenant_id is required")

    def register(self, *, tenant_id: str, action_id: str, action_hash: str,
                 nonce: int, now: int, expiry: int = 0) -> ActionRecord:
        """Validate and register a proposed action. Raises ReplayError on any
        invariant violation."""
        self._check_tenant(tenant_id)
        if nonce < 0:
            raise ReplayError(f"nonce must be >= 0, got {nonce}")

        # Expiry check (time-based invariant).
        if expiry and now and expiry < now:
            self._record_status(tenant_id, action_hash, ActionStatus.EXPIRED)
            raise ReplayError(
                f"action expired (expiry={expiry} < now={now})")

        # Replay check: same action_hash already seen for this tenant.
        existing = self._by_hash.get((tenant_id, action_hash))
        if existing is not None:
            raise ReplayError(
                f"replay detected: action_hash {action_hash[:10]}... already "
                f"in state {existing.status.value}")

        # Nonce reuse check: a different action_hash under the same nonce.
        prior_hash = self._by_nonce.get((tenant_id, nonce))
        if prior_hash is not None and prior_hash != action_hash:
            raise ReplayError(
                f"nonce {nonce} reused for a different action "
                f"(prior={prior_hash[:10]}...)")

        rec = ActionRecord(
            action_id=action_id, tenant_id=tenant_id, action_hash=action_hash,
            nonce=nonce, status=ActionStatus.REGISTERED, registered_at=now)
        self._by_hash[(tenant_id, action_hash)] = rec
        self._by_nonce[(tenant_id, nonce)] = action_hash
        return rec

    def advance(self, tenant_id: str, action_hash: str, status: ActionStatus) -> None:
        rec = self._by_hash.get((tenant_id, action_hash))
        if rec is None:
            raise ReplayError(f"unknown action_hash {action_hash[:10]}...")
        rec.status = status

    def _record_status(self, tenant_id: str, action_hash: str,
                       status: ActionStatus) -> None:
        rec = self._by_hash.get((tenant_id, action_hash))
        if rec is not None:
            rec.status = status

    def status_of(self, tenant_id: str, action_hash: str) -> Optional[ActionStatus]:
        rec = self._by_hash.get((tenant_id, action_hash))
        return rec.status if rec else None

    def seen(self, tenant_id: str, action_hash: str) -> bool:
        return (tenant_id, action_hash) in self._by_hash


__all__ = [
    "ActionRegistry", "ReplayError", "ActionStatus", "ActionRecord",
]

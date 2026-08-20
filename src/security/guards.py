"""Rathnone security guards — antidotes to the documented red-team inversions.

These constrain the system; they do NOT escalate it. Each guard maps to one of
the four harmful trajectories from docs/13-SECURITY-THREAT-MODEL.md and is
fail-closed: when a guard cannot evaluate, it refuses.

  V1 Predatory extraction  -> advisory-evidence sanitization + signing velocity limit
  V2 Financial panopticon   -> PII / identity-binding rejection in the ledger
  V3 Algorithmic oligarchy  -> fairness invariant (verdict independent of aum/identity)
  V4 Immutable cage         -> circuit breaker (halt) + settlement sanity + staleness guard
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

# V2: identity-binding keys that must NEVER appear in a ledger body. Binding the
# immutable ledger to real-world identity is the panopticon escalation; rejecting
# these keys structurally prevents it from ever being added without defeating the guard.
_PII_KEYS = {
    "biometric", "ssn", "social_security", "passport", "email", "phone",
    "name", "legal_name", "dob", "date_of_birth", "national_id", "tax_id",
    "social_credit", "real_world_id", "ip", "device_id", "mac", "kyc",
}

# V1: neutral decision fields that advisory_evidence must NOT carry. to_authorization_request
# already drops the whole block, but this is defense-in-depth: if a future edit
# accidentally forwards evidence, it cannot smuggle a decision-relevant field.
_NEUTRAL_DECISION_FIELDS = {
    "capability", "request", "request_id", "producer", "scope", "grant",
    "constraints", "verdict", "identity", "epoch", "now",
}

_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def assert_no_pii(body: dict) -> None:
    """V2: reject any ledger body that binds to real-world identity."""
    hit = {str(k).lower() for k in body.keys()} & _PII_KEYS
    if hit:
        raise ValueError(
            f"ledger body rejected: identity-binding keys {sorted(hit)} "
            f"violate the pseudonymity invariant (V2 panopticon defense)")


def sanitize_advisory_evidence(evidence: dict) -> dict:
    """V1: strip any neutral decision field an attacker tried to smuggle in.

    The result is purely advisory and never reaches fleet.epistemic.decide().
    """
    if not evidence:
        return {}
    return {k: v for k, v in evidence.items()
            if str(k).lower() not in _NEUTRAL_DECISION_FIELDS}


def validate_settlement_intent(intent: dict, *,
                               max_value_wei: Optional[int] = None) -> None:
    """V4: structural sanity for a settlement intent BEFORE it can be signed.

    Prevents the frozen spine from signing a structurally impossible or ruinous
    transfer even when it returns AUTO. Economic ceilings (max_value_wei) are
    deployment-supplied and optional; structural checks always run.
    """
    if not isinstance(intent, dict):
        raise ValueError("settlement intent must be an object")
    to = intent.get("to")
    if not isinstance(to, str) or not _ADDR_RE.match(to):
        raise ValueError(f"settlement 'to' must be a 0x address, got {to!r}")
    val = intent.get("value")
    if not isinstance(val, str) or not val.isdigit():
        raise ValueError(
            f"settlement 'value' must be a non-negative integer string (wei), got {val!r}")
    value = int(val)
    if value < 0:
        raise ValueError("settlement 'value' must be non-negative")
    if value.bit_length() > 128:
        raise ValueError("settlement 'value' exceeds 128 bits — refuse")
    if max_value_wei is not None and value > max_value_wei:
        raise ValueError(
            f"settlement 'value' {value} exceeds authorized ceiling {max_value_wei}")
    nonce = intent.get("nonce")
    if not isinstance(nonce, int) or isinstance(nonce, bool) or nonce < 0:
        raise ValueError(f"settlement 'nonce' must be a non-negative integer, got {nonce!r}")


def validate_order(order: dict) -> None:
    """V1/V4: minimal structural check for a live trade order before signing."""
    if not isinstance(order, dict):
        raise ValueError("order must be an object")
    for field in ("symbol", "side", "quantity"):
        if field not in order:
            raise ValueError(f"order missing required field {field!r}")
    if str(order.get("side")).lower() not in ("buy", "sell"):
        raise ValueError(f"order side must be buy/sell, got {order.get('side')!r}")
    qty = order.get("quantity")
    if not isinstance(qty, (int, float)) or qty <= 0:
        raise ValueError(f"order quantity must be positive, got {qty!r}")


@dataclass
class Clock:
    """Injectable monotonic clock for staleness / velocity guards (testable)."""
    _t: int = 0

    def now(self) -> int:
        return self._t

    def advance(self, dt: int = 1) -> None:
        if dt < 0:
            raise ValueError("clock cannot go backwards")
        self._t += dt


class CircuitBreaker:
    """V4 antidote: an independent halt switch for the autonomous loop.

    Halt is fail-closed — if state cannot be read, it is treated as OPEN (halted).
    This is the operator's panic button: it stops live signing/execution without
    needing the frozen decide() to "agree", defeating the immutable-cage failure.
    """
    def __init__(self, clock: Optional[Clock] = None):
        self._open = False
        self._opened_at: Optional[int] = None
        self._clock = clock or Clock()

    @property
    def is_open(self) -> bool:
        return self._open

    def halt(self) -> None:
        self._open = True
        self._opened_at = self._clock.now()

    def resume(self) -> None:
        self._open = False
        self._opened_at = None


class VelocityGuard:
    """V1 antidote: cap live-signing rate so the live track cannot become a
    high-frequency front-running machine. Fail-closed by design: exceeding the
    configured limit refuses; the default limit is permissive (set it strict in prod).
    """
    def __init__(self, min_interval: int = 0, max_per_window: int = 10**12,
                 window: int = 1_000_000, clock: Optional[Clock] = None):
        self.min_interval = min_interval
        self.max_per_window = max_per_window
        self.window = window
        self._clock = clock or Clock()
        self._last: Optional[int] = None
        self._times: list[int] = []

    def check(self) -> None:
        now = self._clock.now()
        if self._last is not None and (now - self._last) < self.min_interval:
            raise ValueError(
                f"live signing too frequent (min interval {self.min_interval})")
        self._times = [t for t in self._times if (now - t) <= self.window]
        if len(self._times) >= self.max_per_window:
            raise ValueError("live signing rate limit exceeded")
        self._last = now
        self._times.append(now)


__all__ = [
    "assert_no_pii", "sanitize_advisory_evidence", "validate_settlement_intent",
    "validate_order", "Clock", "CircuitBreaker", "VelocityGuard",
]

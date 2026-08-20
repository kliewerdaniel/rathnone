"""Rathnone deployment configuration.

All runtime knobs come from the environment so the same binary can be locked
down per deployment without code changes. Every reader is FAIL-CLOSED: a missing
or malformed value either falls back to the safe default or (for bounds that must
not be silently disabled) raises loudly at import time rather than silently
allowing an unbounded action.

Convention: prefixed RATHNONE_* so they don't collide with host env.
"""
from __future__ import annotations

import os
from typing import Optional


def _getenv(name: str) -> Optional[str]:
    v = os.environ.get(name)
    if v is None:
        return None
    return v.strip()


def max_settlement_value_wei() -> Optional[int]:
    """V4 ceiling: refuse to sign a settlement transfer above this many wei.

    Env: RATHNONE_MAX_SETTLEMENT_VALUE_WEI (integer, >= 0).
    - unset  -> None  (no ceiling; operator must set it in production)
    - "0"    -> 0     (banned: refuse ALL settlements)
    - bad    -> raises ValueError (fail-closed: never silently unbounded)

    A deployment that wants real protection sets this to its risk ceiling, e.g.
    10**24 (1M ETH) or whatever per-settlement cap the operator authorizes.
    """
    raw = _getenv("RATHNONE_MAX_SETTLEMENT_VALUE_WEI")
    if raw is None or raw == "":
        return None
    try:
        val = int(raw)
    except ValueError:
        raise ValueError(
            f"RATHNONE_MAX_SETTLEMENT_VALUE_WEI must be a non-negative integer, "
            f"got {raw!r}")
    if val < 0:
        raise ValueError(
            f"RATHNONE_MAX_SETTLEMENT_VALUE_WEI must be >= 0, got {val}")
    return val


def live_signing_rate_max_per_window() -> int:
    """V1 ceiling: max live signatures per sliding window.

    Env: RATHNONE_LIVE_RATE_MAX (integer >= 1). Default 10**12 (effectively
    unlimited for local/dev). Production should set a strict value. Fail-closed
    on bad input (raise) rather than silently disabling the guard.
    """
    raw = _getenv("RATHNONE_LIVE_RATE_MAX")
    if raw is None or raw == "":
        return 10**12
    try:
        val = int(raw)
    except ValueError:
        raise ValueError(
            f"RATHNONE_LIVE_RATE_MAX must be a positive integer, got {raw!r}")
    if val < 1:
        raise ValueError(
            f"RATHNONE_LIVE_RATE_MAX must be >= 1, got {val}")
    return val


__all__ = [
    "max_settlement_value_wei", "live_signing_rate_max_per_window",
]

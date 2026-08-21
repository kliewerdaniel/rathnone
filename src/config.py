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
from dataclasses import dataclass
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


# Conservative DEFAULT live ceiling. See ADR 26: 2026 agentic-finance rails
# (Mastercard AP4M, Stripe agent tokens) treat a non-bypassable per-agent
# spending cap as the critical blast-radius control. A deployed rathnone with
# no operator-supplied ceiling must NOT silently fall back to "unbounded" for a
# LIVE tenant — that is precisely the machine-speed drain the OpenAI->HuggingFace
# intrusion demonstrated. This is a deliberately small safe default (1 ETH),
# overridden by RATHNONE_MAX_SETTLEMENT_VALUE_WEI when the operator sets one.
_LIVE_DEFAULT_MAX_SETTLEMENT_WEI = 10**18


def live_default_max_settlement_wei() -> int:
    """Conservative per-settlement ceiling for a LIVE tenant with no env set.

    ADR 26: live tenants are bounded by default, not unbounded. The operator
    MUST raise this via RATHNONE_MAX_SETTLEMENT_VALUE_WEI in production; the
    default is intentionally small so a forgotten config fails safe (small cap)
    instead of open-ended (no cap).
    """
    return _LIVE_DEFAULT_MAX_SETTLEMENT_WEI


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


# ---------------------------------------------------------------------------
# v2 Risk-engine limits (fail-closed env knobs)
# ---------------------------------------------------------------------------
# Each reader falls back to a SAFE DEFAULT when unset, but RAISES on malformed
# input (never silently disabling the guard). A deployment that wants real
# protection sets these per its risk appetite. None means "no bound" for
# max_* (operator must set), but velocity/concentration defaults are concrete
# safe values.

def _int_env(name: str, default: int) -> int:
    raw = _getenv(name)
    if raw is None or raw == "":
        return default
    try:
        val = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}")
    return val


def risk_max_order_notional() -> Optional[float]:
    """RATHNONE_RISK_MAX_ORDER_NOTIONAL: max single-order notional (USD).
    None = no bound (operator must set)."""
    raw = _getenv("RATHNONE_RISK_MAX_ORDER_NOTIONAL")
    if raw is None or raw == "":
        return None
    try:
        val = float(raw)
    except ValueError:
        raise ValueError(f"RATHNONE_RISK_MAX_ORDER_NOTIONAL must be a number, got {raw!r}")
    if val < 0:
        raise ValueError(f"RATHNONE_RISK_MAX_ORDER_NOTIONAL must be >= 0, got {val}")
    return val


def risk_max_position_size() -> Optional[float]:
    """RATHNONE_RISK_MAX_POSITION: max position size (USD). None = no bound."""
    raw = _getenv("RATHNONE_RISK_MAX_POSITION")
    if raw is None or raw == "":
        return None
    try:
        val = float(raw)
    except ValueError:
        raise ValueError(f"RATHNONE_RISK_MAX_POSITION must be a number, got {raw!r}")
    if val < 0:
        raise ValueError(f"RATHNONE_RISK_MAX_POSITION must be >= 0, got {val}")
    return val


def risk_max_daily_loss() -> Optional[float]:
    """RATHNONE_RISK_MAX_DAILY_LOSS: max realized+unrealized daily loss (USD)."""
    raw = _getenv("RATHNONE_RISK_MAX_DAILY_LOSS")
    if raw is None or raw == "":
        return None
    try:
        val = float(raw)
    except ValueError:
        raise ValueError(f"RATHNONE_RISK_MAX_DAILY_LOSS must be a number, got {raw!r}")
    if val < 0:
        raise ValueError(f"RATHNONE_RISK_MAX_DAILY_LOSS must be >= 0, got {val}")
    return val


def risk_max_portfolio_exposure() -> Optional[float]:
    """RATHNONE_RISK_MAX_EXPOSURE: max gross portfolio exposure (USD)."""
    raw = _getenv("RATHNONE_RISK_MAX_EXPOSURE")
    if raw is None or raw == "":
        return None
    try:
        val = float(raw)
    except ValueError:
        raise ValueError(f"RATHNONE_RISK_MAX_EXPOSURE must be a number, got {raw!r}")
    if val < 0:
        raise ValueError(f"RATHNONE_RISK_MAX_EXPOSURE must be >= 0, got {val}")
    return val


def risk_concentration_limit() -> float:
    """RATHNONE_RISK_CONCENTRATION: max fraction (0..1) of AUM in one instrument.
    Default 0.5 (50%)."""
    return _int_env("RATHNONE_RISK_CONCENTRATION", 50) / 100.0


def risk_velocity_max_per_window() -> int:
    """RATHNONE_RISK_VELOCITY: max executable actions per sliding window.
    Default 1000 (safe; tighten per deployment)."""
    return _int_env("RATHNONE_RISK_VELOCITY", 1000)


# ---------------------------------------------------------------------------
# v3 Epistemic-hygiene corroboration sources (ADR 24, fail-closed env knobs)
# ---------------------------------------------------------------------------
# ADR 24 makes fork F7's "N=2 independent feeds" REAL: quorum is satisfied only
# by DISTINCT, independently-originated sources. These are still locally-configured
# values (no network egress by default — the "no egress by default" principle
# holds). A deployment lists each source under its own id; two quotes sharing an
# id count once. Missing/malformed => fail-closed (raises) rather than silently
# trusting a single source.

def hygiene_enabled() -> bool:
    """RATHNONE_HYGIENE_ENABLED: opt-in knowledge-poisoning gate (default off)."""
    return _getenv("RATHNONE_HYGIENE_ENABLED") == "1"


def hygiene_price_band_bps() -> int:
    """RATHNONE_HYGIENE_BAND_BPS: allowed price deviation band (default 50)."""
    return _int_env("RATHNONE_HYGIENE_BAND_BPS", 50)


def hygiene_quorum() -> int:
    """RATHNONE_HYGIENE_QUORUM: min DISTINCT price sources (default 2, F7)."""
    v = _int_env("RATHNONE_HYGIENE_QUORUM", 2)
    if v < 1:
        raise ValueError(f"RATHNONE_HYGIENE_QUORUM must be >= 1, got {v}")
    return v


def hygiene_price_sources() -> dict[str, dict[str, float]]:
    """RATHNONE_HYGIENE_PRICE_SOURCES: JSON {source_id: {INSTRUMENT: price}}.

    Each top-level key is a DISTINCT origin; quorum counts distinct keys, not
    repeated values. Unset => empty (so hygiene BLOCKS any priced claim by
    default — fail-closed, never assumes a price is true). Malformed JSON or a
    non-dict body => raise (fail-closed).
    """
    raw = _getenv("RATHNONE_HYGIENE_PRICE_SOURCES")
    if raw is None or raw == "":
        return {}
    import json as _json
    try:
        parsed = _json.loads(raw)
    except Exception as e:
        raise ValueError(
            f"RATHNONE_HYGIENE_PRICE_SOURCES must be JSON, got: {e}") from e
    if not isinstance(parsed, dict):
        raise ValueError(
            "RATHNONE_HYGIENE_PRICE_SOURCES must be a JSON object "
            "{source_id: {instrument: price}}")
    out: dict[str, dict[str, float]] = {}
    for src_id, quotes in parsed.items():
        if not isinstance(quotes, dict):
            raise ValueError(
                f"RATHNONE_HYGIENE_PRICE_SOURCES source {src_id!r} must map "
                f"instrument->price")
        out[str(src_id)] = {str(k): float(v) for k, v in quotes.items()}
    return out


@dataclass
class TenantLimits:
    """Per-tenant risk bounds. Sourced from env by default; may be overridden
    per tenant (e.g. tighter for a small AUM). None = no bound for max_*."""
    max_order_notional: Optional[float] = None
    max_position_size: Optional[float] = None
    max_daily_loss: Optional[float] = None
    max_portfolio_exposure: Optional[float] = None
    concentration_limit: float = 0.5
    velocity_max_per_window: int = 1000

    @classmethod
    def from_env(cls) -> "TenantLimits":
        return cls(
            max_order_notional=risk_max_order_notional(),
            max_position_size=risk_max_position_size(),
            max_daily_loss=risk_max_daily_loss(),
            max_portfolio_exposure=risk_max_portfolio_exposure(),
            concentration_limit=risk_concentration_limit(),
            velocity_max_per_window=risk_velocity_max_per_window(),
        )

    def with_overrides(self, **overrides) -> "TenantLimits":
        cur = dict(
            max_order_notional=self.max_order_notional,
            max_position_size=self.max_position_size,
            max_daily_loss=self.max_daily_loss,
            max_portfolio_exposure=self.max_portfolio_exposure,
            concentration_limit=self.concentration_limit,
            velocity_max_per_window=self.velocity_max_per_window,
        )
        cur.update(overrides)
        return TenantLimits(**cur)


__all__ = [
    "max_settlement_value_wei", "live_signing_rate_max_per_window",
    "risk_max_order_notional", "risk_max_position_size", "risk_max_daily_loss",
    "risk_max_portfolio_exposure", "risk_concentration_limit",
    "risk_velocity_max_per_window", "TenantLimits",
    "hygiene_enabled", "hygiene_price_band_bps", "hygiene_quorum",
    "hygiene_price_sources",
]

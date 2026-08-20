"""v2 Financial Risk Engine — deterministic, narrowing-only (P0).

This is the first layer AFTER the frozen spine. It receives an already-decided
action (AUTO/HUMAN/BLOCKED) plus a FinancialAction and a set of TenantLimits, and
returns a RiskVerdict.

CRITICAL ASYMMETRY (the core thesis, ratified Fork 2):
    The risk engine can only NARROW a verdict (AUTO -> BLOCKED).
    It can NEVER WIDEN one (BLOCKED -> AUTO, or HUMAN -> AUTO).
    The model's AUTO is necessary-but-not-sufficient. The deterministic authority
    layer is the final word. This preserves Invariant 1 (ModelOutput !=
    Authorization): nothing here feeds decide(), it only constrains what AUTO
    already permitted.

The engine is a pure function of (action, limits, observable state). It holds NO
epistemic state and produces NO probabilities. It is the opposite of a model.

v2 seeds ~6 checks; the set is intentionally extensible (add a method, append to
_CHECKS) without touching the orchestrator.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from ..finance.action import FinancialAction
from ..config import TenantLimits


@dataclass
class RiskViolation:
    code: str
    message: str
    detail: Optional[dict] = None


@dataclass
class RiskVerdict:
    """The risk engine's verdict. `ok=False` means AUTO->BLOCKED."""
    ok: bool
    verdict: str  # always "BLOCKED" when ok is False, else unchanged
    input_verdict: str
    violations: list[RiskViolation] = field(default_factory=list)
    checks_run: int = 0

    @property
    def reasons(self) -> list[str]:
        return [f"{v.code}: {v.message}" for v in self.violations]


# Observable state the engine may read (deterministic position/velocity view).
@dataclass
class RiskState:
    """A point-in-time, deterministic view of tenant state the engine reads.

    Populated by the pipeline from the tenant's position ledger + action registry.
    Defaults are permissive (empty) so the engine runs even with no history.
    """
    current_position_by_instrument: dict[str, float] = field(default_factory=dict)
    gross_exposure: float = 0.0
    realized_daily_loss: float = 0.0
    actions_in_window: int = 0
    aum: float = 0.0


# ---------------------------------------------------------------------------
# Individual checks. Each: (action, limits, state) -> Optional[RiskViolation]
# Returning a violation NARROWS the verdict to BLOCKED. Returning None = pass.
# ---------------------------------------------------------------------------

def _check_order_notional(a: FinancialAction, lim: TenantLimits, s: RiskState):
    if lim.max_order_notional is None:
        return None
    n = a.notional_value
    if n > lim.max_order_notional:
        return RiskViolation(
            "MAX_ORDER_NOTIONAL",
            f"order notional {n:.2f} exceeds cap {lim.max_order_notional:.2f}",
            {"notional": n, "cap": lim.max_order_notional})
    return None


def _check_position_size(a: FinancialAction, lim: TenantLimits, s: RiskState):
    if lim.max_position_size is None:
        return None
    proj = s.current_position_by_instrument.get(a.instrument, 0.0) + a.notional_value
    if proj > lim.max_position_size:
        return RiskViolation(
            "MAX_POSITION_SIZE",
            f"projected position {proj:.2f} exceeds cap {lim.max_position_size:.2f}",
            {"projected": proj, "cap": lim.max_position_size})
    return None


def _check_daily_loss(a: FinancialAction, lim: TenantLimits, s: RiskState):
    if lim.max_daily_loss is None:
        return None
    # Conservative: a new buy adds to potential loss exposure.
    proj = s.realized_daily_loss + (a.notional_value if a.side == "buy" else 0.0)
    if proj > lim.max_daily_loss:
        return RiskViolation(
            "MAX_DAILY_LOSS",
            f"projected daily loss {proj:.2f} exceeds cap {lim.max_daily_loss:.2f}",
            {"projected": proj, "cap": lim.max_daily_loss})
    return None


def _check_portfolio_exposure(a: FinancialAction, lim: TenantLimits, s: RiskState):
    if lim.max_portfolio_exposure is None:
        return None
    proj = s.gross_exposure + a.notional_value
    if proj > lim.max_portfolio_exposure:
        return RiskViolation(
            "MAX_PORTFOLIO_EXPOSURE",
            f"projected exposure {proj:.2f} exceeds cap {lim.max_portfolio_exposure:.2f}",
            {"projected": proj, "cap": lim.max_portfolio_exposure})
    return None


def _check_concentration(a: FinancialAction, lim: TenantLimits, s: RiskState):
    if not s.aum or a.instrument not in s.current_position_by_instrument:
        return None
    frac = s.current_position_by_instrument[a.instrument] / s.aum
    if a.side == "buy" and frac >= lim.concentration_limit:
        return RiskViolation(
            "CONCENTRATION_LIMIT",
            f"instrument {a.instrument} already at {frac:.2%} of AUM "
            f"(cap {lim.concentration_limit:.2%})",
            {"fraction": frac, "cap": lim.concentration_limit})
    return None


def _check_velocity(a: FinancialAction, lim: TenantLimits, s: RiskState):
    if s.actions_in_window >= lim.velocity_max_per_window:
        return RiskViolation(
            "VELOCITY_LIMIT",
            f"actions in window {s.actions_in_window} >= cap "
            f"{lim.velocity_max_per_window}",
            {"in_window": s.actions_in_window, "cap": lim.velocity_max_per_window})
    return None


_CHECKS: list[Callable[[FinancialAction, TenantLimits, RiskState], Optional[RiskViolation]]] = [
    _check_order_notional,
    _check_position_size,
    _check_daily_loss,
    _check_portfolio_exposure,
    _check_concentration,
    _check_velocity,
]


class RiskEngine:
    """Deterministic risk evaluation. Narrowing-only."""

    def __init__(self, checks: Optional[list] = None):
        self._checks = checks or _CHECKS

    def evaluate(self, action: FinancialAction, limits: TenantLimits,
                 state: Optional[RiskState] = None,
                 input_verdict: str = "AUTO") -> RiskVerdict:
        state = state or RiskState()
        violations: list[RiskViolation] = []
        for check in self._checks:
            v = check(action, limits, state)
            if v is not None:
                violations.append(v)
        # NARROWING ONLY: only AUTO (or HUMAN, pending approval) can be blocked.
        # BLOCKED stays BLOCKED. Approved HUMAN stays approved (approval handled
        # by the operator layer, not here).
        if input_verdict == "BLOCKED":
            return RiskVerdict(ok=False, verdict="BLOCKED",
                              input_verdict="BLOCKED", violations=violations,
                              checks_run=len(self._checks))
        if violations:
            return RiskVerdict(ok=False, verdict="BLOCKED",
                              input_verdict=input_verdict, violations=violations,
                              checks_run=len(self._checks))
        return RiskVerdict(ok=True, verdict=input_verdict,
                          input_verdict=input_verdict,
                          checks_run=len(self._checks))

    # Convenience accessors for the adversarial suite.
    @property
    def check_codes(self) -> list[str]:
        return [c.__name__ for c in self._checks]


__all__ = ["RiskEngine", "RiskVerdict", "RiskViolation", "RiskState"]

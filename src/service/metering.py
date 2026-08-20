"""Per-AUM commercial metering (B9) for the Rathnone product service.

Deterministic, auditable accrual: every AUTHORIZED (AUTO) action records the
tenant's AUM at that moment. Billable exposure accrues as a running sum of AUM;
the monthly bill = Σ(AUM) × AUM_FEE_RATE. BLOCKED/HUMAN actions accrue nothing
(a tenant is only metered when authority is actually granted). No network, no
clock drift — the ledger is the source of truth and is reproducible from the
signed audit trail.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# Per-AUM fee rate (fraction of AUM per billing period). Commercial knob.
AUM_FEE_RATE = 0.0005  # 5 bps per period


@dataclass
class MeteringLedger:
    """Per-tenant metering. Pure, deterministic, reconstructable from the audit
    trail (each entry carries aum + verdict)."""

    tenant_id: str
    entries: list[dict] = field(default_factory=list)
    # running sum of AUM across authorized actions
    _aum_sum: float = 0.0

    def record(self, *, verdict: str, capability: str, aum: float,
               request_id: str) -> None:
        """Accrue one action. Only AUTO actions contribute to billable AUM."""
        authorized = verdict == "AUTO"
        if authorized:
            self._aum_sum += aum
        self.entries.append({
            "request_id": request_id,
            "capability": capability,
            "verdict": verdict,
            "aum": aum,
            "metered": authorized,
        })

    @property
    def authorized_actions(self) -> int:
        return sum(1 for e in self.entries if e["metered"])

    @property
    def aum_exposure(self) -> float:
        return self._aum_sum

    @property
    def billable(self) -> float:
        return round(self._aum_sum * AUM_FEE_RATE, 6)

    def summary(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "authorized_actions": self.authorized_actions,
            "total_actions": len(self.entries),
            "aum_exposure": self.aum_exposure,
            "aum_fee_rate": AUM_FEE_RATE,
            "billable": self.billable,
        }


__all__ = ["MeteringLedger", "AUM_FEE_RATE"]

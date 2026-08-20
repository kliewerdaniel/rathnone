"""FinancialAction — the formal economic state-transition object (v2, P0).

This is the central abstraction of the v2 control plane. Where v1 authorized a
nearly-opaque (producer, request_id, capability, action_descriptor, payload)
tuple, v2 authorizes a *precisely defined economic state transition*:

    FinancialAction
    ├── action_id, tenant_id, actor, strategy_id
    ├── instrument, venue, side, quantity, price_limit
    ├── currency, notional_value, settlement_asset, destination
    ├── nonce, timestamp, expiry
    ├── risk_class, evidence

The action is signed/authorized/audited as a single hash:

    action_hash = keccak256(canonical(action))

which becomes the unified signable target, replacing the ad-hoc per-record
intent/order dict hashing.

Relationship to the existing spine (Fork 1 = A): a FinancialAction is carried as
an *advisory* `action` field on `RathnoneFinanceProposal`. The spine translator
(`RathnoneFinanceProposal.to_authorization_request`) still drops everything but
the neutral tuple, so the frozen `fleet.epistemic.decide()` contract is
UNCHANGED. Invariant 1 (ModelOutput != Authorization) holds: the model proposes
the action; the spine never sees its economic detail.

This module is pure data + hashing. It contains NO authority logic.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, fields, asdict
from typing import Any, Optional

from ..live.signing import keccak256


# Fields that participate in the canonical action hash. Ordered for readability;
# we sort_keys in canonical_json regardless, but listing them makes the contract
# explicit and lets us drop non-deterministic/volatile fields cleanly.
_HASH_FIELDS = (
    "action_id", "tenant_id", "actor", "strategy_id",
    "capability", "instrument", "venue", "side",
    "quantity", "price_limit", "currency", "settlement_asset",
    "destination", "nonce", "timestamp", "expiry", "risk_class",
)


@dataclass
class FinancialAction:
    """A precisely defined economic state transition proposed for authorization.

    Mutating the action changes its hash, so any post-authorization tampering is
    detectable by the signer (approved_action_hash != action_hash).
    """

    # Identity / lineage
    action_id: str = ""                 # unique per proposed action
    tenant_id: str = ""
    actor: str = ""                    # agent/strategy principal
    strategy_id: str = ""
    capability: str = ""               # rathnone.* capability string

    # Economic description
    instrument: str = ""
    venue: str = "sim://exchange"
    side: str = ""                     # buy / sell / transfer / settle
    quantity: float = 0.0
    price_limit: float = 0.0
    currency: str = "USD"
    settlement_asset: str = ""
    destination: str = ""             # target address / account

    # Execution security primitives
    nonce: int = 0
    timestamp: int = 0                # epoch seconds
    expiry: int = 0                  # epoch seconds; 0 = no expiry

    # Governance metadata (advisory; never reaches decide())
    risk_class: str = "standard"
    evidence: dict[str, Any] = field(default_factory=dict)

    # --- canonicalization ------------------------------------------------
    def canonical(self) -> dict:
        """Stable, hash-deterministic projection of the action."""
        out: dict[str, Any] = {}
        for f in _HASH_FIELDS:
            out[f] = getattr(self, f)
        return out

    @property
    def action_hash(self) -> str:
        return keccak256(
            json.dumps(self.canonical(), sort_keys=True,
                       separators=(",", ":")).encode()
        ).hex()

    # --- derived economic quantities ------------------------------------
    @property
    def notional_value(self) -> float:
        """Best-effort notional = |quantity| * price_limit (advisory)."""
        try:
            return abs(float(self.quantity)) * abs(float(self.price_limit))
        except (TypeError, ValueError):
            return 0.0

    # --- validation (structural; not authority) -------------------------
    def validate_structure(self) -> None:
        """Cheap structural sanity. Raises ValueError on malformed action.
        Does NOT authorize anything — pure shape checking used before hashing."""
        if not self.tenant_id:
            raise ValueError("action.tenant_id is required")
        if not self.action_id:
            raise ValueError("action.action_id is required")
        if not self.capability:
            raise ValueError("action.capability is required")
        if not isinstance(self.nonce, int) or isinstance(self.nonce, bool) or self.nonce < 0:
            raise ValueError("action.nonce must be a non-negative integer")
        if self.expiry and self.timestamp and self.expiry < self.timestamp:
            raise ValueError("action.expiry must be >= timestamp")
        if self.quantity and abs(self.quantity) <= 0 and self.side not in ("transfer", "settle"):
            # settle/transfer may be value-based rather than quantity-based
            raise ValueError("action.quantity must be non-zero for buy/sell")

    # --- lifecycle helpers ----------------------------------------------
    def as_intent(self) -> dict:
        """Project to the legacy settlement-intent shape (for chain_settle)."""
        return {
            "to": self.destination,
            "value": str(int(self.notional_value)) if self.settlement_asset.startswith("wei") or self.currency == "wei" else str(self.quantity),
            "nonce": self.nonce,
        }

    def as_order(self) -> dict:
        """Project to the legacy trade-order shape (for trade_execute)."""
        return {
            "symbol": self.instrument,
            "side": self.side,
            "quantity": self.quantity,
            "price_limit": self.price_limit,
            "venue": self.venue,
        }

    def to_advisory(self) -> dict:
        """Advisory projection carried on the proposal (dropped by the spine)."""
        return asdict(self)


def action_from_intent(intent: dict, *, action_id: str, tenant_id: str,
                       capability: str, nonce: int = 0, **overrides) -> "FinancialAction":
    """Build a FinancialAction from the legacy settlement-intent dict (v1 compat)."""
    return FinancialAction(
        action_id=action_id, tenant_id=tenant_id, capability=capability,
        destination=intent.get("to", ""),
        quantity=float(intent.get("value", 0) or 0),
        currency="wei" if "value" in intent else "USD",
        settlement_asset="wei" if "value" in intent else "",
        nonce=int(intent.get("nonce", nonce)),
        **overrides,
    )


def action_from_order(order: dict, *, action_id: str, tenant_id: str,
                      capability: str, **overrides) -> "FinancialAction":
    """Build a FinancialAction from the legacy trade-order dict (v1 compat)."""
    return FinancialAction(
        action_id=action_id, tenant_id=tenant_id, capability=capability,
        instrument=order.get("symbol", ""),
        side=order.get("side", ""),
        quantity=float(order.get("quantity", 0) or 0),
        price_limit=float(order.get("price_limit", 0) or 0),
        venue=order.get("venue", "sim://exchange"),
        **overrides,
    )


__all__ = ["FinancialAction", "action_from_intent", "action_from_order"]

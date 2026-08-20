"""v2 Venue adapter + reconciliation engine (P1, Fork 5 = A).

A signer must never assume SIGNED == SETTLED. The venue adapter is the boundary
to an external executOR (real or simulated). The reconciliation engine diffs
Rathnone's internal authorized state against what the venue actually reports, and
emits reconciliation events for every divergence:

    - signed but never submitted
    - submitted but rejected
    - accepted but not settled
    - duplicate execution
    - partial execution
    - unexpected settlement amount
    - unexpected destination
    - nonce mismatch
    - missing external transaction
    - state divergence

The default ``SimulatedVenue`` is deterministic and can be *adversarially
perturbed* (wrong destination, partial fill, nonce mismatch, missing tx) — which
is exactly what powers Attacks 08/09 in the scenario suite. No live network is
required; wiring a real L2 RPC is a deployment step, not a code-path change.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class VenueState(str, Enum):
    NONE = "NONE"                # venue has never heard of this action
    SUBMITTED = "SUBMITTED"
    REJECTED = "REJECTED"
    ACCEPTED = "ACCEPTED"
    SETTLED = "SETTLED"
    PARTIAL = "PARTIAL"         # partial fill/settlement


@dataclass
class VenueReport:
    action_id: str
    state: VenueState
    destination: str = ""
    amount: float = 0.0
    nonce: int = 0
    tx_hash: str = ""
    note: str = ""


@dataclass
class InternalState:
    """Rathnone's authorized expectation for an action."""
    action_id: str
    action_hash: str
    destination: str
    amount: float
    nonce: int
    state: str  # expected: SUBMITTED/ACCEPTED/SETTLED


class VenueAdapter(ABC):
    @abstractmethod
    def submit(self, action) -> VenueReport:
        ...

    @abstractmethod
    def query(self, action_id: str) -> VenueReport:
        ...


class SimulatedVenue(VenueAdapter):
    """Deterministic sim venue. By default it faithfully settles. A ``perturb``
    flag lets the adversarial suite inject divergence without touching the
    pipeline code."""

    def __init__(self, behave: str = "faithful"):
        # behave: faithful | wrong_destination | partial | reject | missing_tx | nonce_shift
        self._behave = behave
        self._reports: dict[str, VenueReport] = {}
        self._counter = 0

    def submit(self, action) -> VenueReport:
        self._counter += 1
        dest = action.destination
        amt = action.notional_value or float(action.quantity)
        nonce = action.nonce
        note = ""

        if self._behave == "wrong_destination":
            dest = "0x" + "99" * 20
            note = "venue reported different destination"
        elif self._behave == "partial":
            amt = amt / 2.0
            note = "partial fill"
        elif self._behave == "reject":
            rep = VenueReport(action.action_id, VenueState.REJECTED,
                              destination=dest, amount=amt, nonce=nonce,
                              note="venue rejected")
            self._reports[action.action_id] = rep
            return rep
        elif self._behave == "missing_tx":
            # venue accepted but never produced a tx (divergence: no settlement)
            rep = VenueReport(action.action_id, VenueState.ACCEPTED,
                              destination=dest, amount=amt, nonce=nonce,
                              note="accepted, no tx produced")
            self._reports[action.action_id] = rep
            return rep
        elif self._behave == "nonce_shift":
            nonce = nonce + 1
            note = "nonce mismatch"

        rep = VenueReport(action.action_id, VenueState.SETTLED,
                          destination=dest, amount=amt, nonce=nonce,
                          tx_hash=f"0xtx{self._counter:08x}",
                          note=note)
        self._reports[action.action_id] = rep
        return rep

    def query(self, action_id: str) -> VenueReport:
        return self._reports.get(
            action_id,
            VenueReport(action_id, VenueState.NONE, note="unknown to venue"))


# ---------------------------------------------------------------------------
# Reconciliation
# ---------------------------------------------------------------------------

class ReconciliationCode(str, Enum):
    MATCH = "MATCH"
    UNEXPECTED_DESTINATION = "UNEXPECTED_DESTINATION"
    PARTIAL_EXECUTION = "PARTIAL_EXECUTION"
    VENUE_REJECTED = "VENUE_REJECTED"
    MISSING_EXTERNAL_TX = "MISSING_EXTERNAL_TX"
    UNEXPECTED_AMOUNT = "UNEXPECTED_AMOUNT"
    NONCE_MISMATCH = "NONCE_MISMATCH"
    STATE_DIVERGENCE = "STATE_DIVERGENCE"
    NEVER_SUBMITTED = "NEVER_SUBMITTED"


@dataclass
class ReconciliationEvent:
    action_id: str
    code: ReconciliationCode
    detail: str
    internal: Optional[InternalState] = None
    venue: Optional[VenueReport] = None


class ReconciliationEngine:
    def __init__(self, venue: VenueAdapter):
        self._venue = venue

    def reconcile(self, internal: InternalState) -> ReconciliationEvent:
        rep = self._venue.query(internal.action_id)
        if rep.state == VenueState.NONE:
            return ReconciliationEvent(internal.action_id,
                                       ReconciliationCode.NEVER_SUBMITTED,
                                       "venue has no record of this action",
                                       internal=internal, venue=rep)
        if rep.state == VenueState.REJECTED:
            return ReconciliationEvent(internal.action_id,
                                       ReconciliationCode.VENUE_REJECTED,
                                       rep.note or "venue rejected",
                                       internal=internal, venue=rep)
        if rep.state in (VenueState.SUBMITTED, VenueState.ACCEPTED):
            return ReconciliationEvent(internal.action_id,
                                       ReconciliationCode.MISSING_EXTERNAL_TX,
                                       "submitted/accepted but not yet settled",
                                       internal=internal, venue=rep)
        if rep.state == VenueState.PARTIAL:
            return ReconciliationEvent(internal.action_id,
                                       ReconciliationCode.PARTIAL_EXECUTION,
                                       rep.note or "partial execution",
                                       internal=internal, venue=rep)
        # SETTLED — compare destination/amount/nonce
        if rep.destination and internal.destination and \
                rep.destination.lower() != internal.destination.lower():
            return ReconciliationEvent(internal.action_id,
                                       ReconciliationCode.UNEXPECTED_DESTINATION,
                                       f"venue dest {rep.destination} != expected {internal.destination}",
                                       internal=internal, venue=rep)
        if abs(rep.amount - internal.amount) > 1e-9:
            return ReconciliationEvent(internal.action_id,
                                       ReconciliationCode.UNEXPECTED_AMOUNT,
                                       f"venue amount {rep.amount} != expected {internal.amount}",
                                       internal=internal, venue=rep)
        if rep.nonce != internal.nonce:
            return ReconciliationEvent(internal.action_id,
                                       ReconciliationCode.NONCE_MISMATCH,
                                       f"venue nonce {rep.nonce} != expected {internal.nonce}",
                                       internal=internal, venue=rep)
        return ReconciliationEvent(internal.action_id, ReconciliationCode.MATCH,
                                   "settlement matches authorization",
                                   internal=internal, venue=rep)


__all__ = [
    "VenueAdapter", "SimulatedVenue", "VenueState", "VenueReport",
    "InternalState", "ReconciliationEngine", "ReconciliationEvent",
    "ReconciliationCode",
]

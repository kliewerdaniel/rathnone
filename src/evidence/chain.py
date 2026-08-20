"""v2 Evidence graph + economic state machine (P1, Fork 4 = A).

Extends — does NOT replace — the existing signed hash-chain ledger in
``src/mirror`` (GENESIS head, sha256(prev||body), per-tenant Ed25519 key). The
existing ``verify_chain`` / ``verify_locally`` stays the source of truth for
INTEGRITY (Invariant 3: Verification ⟂ Cognition). What this module adds is
*semantic structure on top of the same chain*: each ``EvidenceEvent`` carries a
``state`` (the economic state-machine node) and ``prev_event_hash`` (causal link
to the prior event in this action's life), so a verifier can reconstruct the full
causal story of an action as a graph rather than a flat log.

States (happy path + failure branches):
    PROPOSED -> AUTHORIZED -> APPROVED -> SIGNED -> SUBMITTED -> ACCEPTED -> SETTLED
    REJECTED / EXPIRED / CANCELLED / FAILED / REVERSED / DISPUTED

Each transition is an EvidenceEvent. Because every event is still appended to the
SAME signed tenant ledger, the resulting evidence graph is cryptographically
verifiable by anyone holding the tenant public key.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ActionState(str, Enum):
    PROPOSED = "PROPOSED"
    AUTHORIZED = "AUTHORIZED"
    EVALUATED = "EVALUATED"
    APPROVED = "APPROVED"
    SIGNED = "SIGNED"
    SUBMITTED = "SUBMITTED"
    ACCEPTED = "ACCEPTED"
    SETTLED = "SETTLED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"
    REVERSED = "REVERSED"
    DISPUTED = "DISPUTED"


# Legal forward transitions (happy path + terminal/divergent branches).
_LEGAL = {
    ActionState.PROPOSED: {ActionState.AUTHORIZED, ActionState.REJECTED,
                          ActionState.EXPIRED, ActionState.CANCELLED},
    ActionState.AUTHORIZED: {ActionState.EVALUATED, ActionState.APPROVED,
                             ActionState.REJECTED, ActionState.EXPIRED,
                             ActionState.CANCELLED},
    ActionState.EVALUATED: {ActionState.APPROVED, ActionState.REJECTED,
                            ActionState.CANCELLED},
    ActionState.APPROVED: {ActionState.SIGNED, ActionState.REJECTED,
                           ActionState.CANCELLED},
    ActionState.SIGNED: {ActionState.SUBMITTED, ActionState.CANCELLED,
                         ActionState.FAILED},
    ActionState.SUBMITTED: {ActionState.ACCEPTED, ActionState.SETTLED,
                            ActionState.FAILED, ActionState.CANCELLED},
    ActionState.ACCEPTED: {ActionState.SETTLED, ActionState.FAILED,
                           ActionState.REVERSED, ActionState.DISPUTED},
    ActionState.SETTLED: {ActionState.REVERSED, ActionState.DISPUTED},
    # terminal-ish branches: no onward transition (but REVERSED/DISPUTED can
    # occur from post-settlement, modeled above).
    ActionState.REJECTED: set(),
    ActionState.EXPIRED: set(),
    ActionState.CANCELLED: set(),
    ActionState.FAILED: set(),
    ActionState.REVERSED: set(),
    ActionState.DISPUTED: set(),
}


def legal_transition(src: ActionState, dst: ActionState) -> bool:
    return dst in _LEGAL.get(src, set())


@dataclass
class EvidenceEvent:
    """One node in the causal evidence graph. The ``event_hash`` is computed over
    the canonical body; the ledger signs the same body, so an external verifier
    can re-derive and confirm ``event_hash`` independently."""
    action_id: str
    tenant_id: str
    state: ActionState
    event_type: str           # REQUEST/INTENT/PROPOSAL/POLICY/EPISTEMIC/RISK/APPROVAL/SIGNATURE/SUBMISSION/VENUE/SETTLEMENT/RECONCILIATION
    action_hash: str = ""
    prev_event_hash: str = ""  # causal link to the prior event in this action
    causal_refs: list[str] = field(default_factory=list)  # other action/event hashes
    payload: dict = field(default_factory=dict)
    timestamp: int = 0
    event_hash: str = ""

    def canonical_bytes(self) -> bytes:
        return json.dumps({
            "action_id": self.action_id,
            "tenant_id": self.tenant_id,
            "state": self.state.value,
            "event_type": self.event_type,
            "action_hash": self.action_hash,
            "prev_event_hash": self.prev_event_hash,
            "causal_refs": sorted(self.causal_refs),
            "payload": self.payload,
            "timestamp": self.timestamp,
        }, sort_keys=True, separators=(",", ":")).encode()

    def finalize_hash(self) -> "EvidenceEvent":
        self.event_hash = hashlib.sha256(self.canonical_bytes()).hexdigest()
        return self


class EvidenceGraph:
    """Per-tenant causal record. In-memory; mirrors the durable ledger. The
    durable, signed copy lives in Tenant.append_ledger; this graph is the
    reconstructed/queryable view."""

    def __init__(self):
        self._events: list[EvidenceEvent] = []
        self._by_action: dict[str, list[EvidenceEvent]] = {}

    def add(self, ev: EvidenceEvent) -> EvidenceEvent:
        ev.finalize_hash()
        self._events.append(ev)
        self._by_action.setdefault(ev.action_id, []).append(ev)
        return ev

    def trace(self, action_id: str) -> list[EvidenceEvent]:
        """Return the causal chain for an action, ordered by insertion."""
        return list(self._by_action.get(action_id, []))

    def current_state(self, action_id: str) -> Optional[ActionState]:
        chain = self.trace(action_id)
        return chain[-1].state if chain else None

    def validate_transitions(self, action_id: str) -> list[str]:
        """Return a list of violations if any transition was illegal."""
        chain = self.trace(action_id)
        violations: list[str] = []
        prev: Optional[ActionState] = None
        for ev in chain:
            if prev is not None and not legal_transition(prev, ev.state):
                violations.append(
                    f"illegal {prev.value} -> {ev.state.value} at {ev.event_type}")
            prev = ev.state
        return violations

    def verify_chain_integrity(self) -> bool:
        """Confirm every event's prev_event_hash actually chains to the prior
        event for the same action (causal, not just ledger order)."""
        by_action: dict[str, list[EvidenceEvent]] = {}
        for ev in self._events:
            by_action.setdefault(ev.action_id, []).append(ev)
        for chain in by_action.values():
            prev_hash = ""
            for ev in chain:
                if ev.prev_event_hash != prev_hash:
                    return False
                prev_hash = ev.event_hash
        return True


__all__ = [
    "ActionState", "EvidenceEvent", "EvidenceGraph", "legal_transition",
]

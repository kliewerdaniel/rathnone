"""v2 Authorization Pipeline — the financial control-plane orchestrator (P0+P1).

This is the deterministic authority layer that turns a proposed FinancialAction
into a signed, reconciled, evidenced state transition. It reuses the FROZEN spine
as the ONLY epistemic surface, then layers deterministic authority on top.

Order of layers (each is a hard boundary, in dependency order):
    1. EPISTEMIC   -> tenant.authorize() -> AUTO / HUMAN / BLOCKED  [frozen spine]
    2. POLICY      -> capability allowlist/denylist (already in authorize)
    3. RISK        -> RiskEngine.evaluate()  [NARROWING ONLY: AUTO->BLOCKED]
    4. HUMAN       -> if HUMAN: require signed ApprovalRecord(action_hash)
    5. REPLAY/ISO  -> ActionRegistry.register() [nonce/expiry/replay/cross-tenant]
    6. SETTLEMENT  -> structural + bound checks (value/PII/velocity)
    7. SIGNER      -> SettlementAuthRecord / OrderAuthRecord over action_hash
    8. STATE       -> EvidenceEvent transitions (AUTHORIZED->APPROVED->SIGNED->...)
    9. VENUE       -> SimulatedVenue.submit()
   10. RECONCILE   -> ReconciliationEngine.diff(internal, venue)
   11. EVIDENCE    -> final EvidenceEvent + ledger append

Crucially: the risk engine and approval layer can only NARROW the verdict. The
model's AUTO is necessary-but-not-sufficient. This preserves Invariant 1.

The pipeline is transport-agnostic; app.py calls it and maps results to HTTP.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..finance.action import FinancialAction
from ..config import TenantLimits
from ..risk.engine import RiskEngine, RiskVerdict, RiskState
from ..security.operator import OperatorAuthority, ApprovalRecord
from ..security import replay as _replay
from ..evidence.chain import (
    EvidenceGraph, EvidenceEvent, ActionState, legal_transition,
)
from ..venue.adapter import SimulatedVenue, ReconciliationEngine, InternalState
from ..security.guards import (
    assert_no_pii, validate_settlement_intent, validate_order,
    CircuitBreaker, VelocityGuard,
)
from ..live import SettlementAuthRecord, OrderAuthRecord
from ..finance.capabilities import (
    CAP_FIN_TRADE_EXECUTE, CAP_FIN_TREASURY_REBALANCE, CAP_FIN_CHAIN_SETTLE,
)


@dataclass
class PipelineResult:
    action_id: str
    action_hash: str
    verdict: str                # final verdict (epistemic, possibly narrowed)
    risk_ok: bool = False
    risk_violations: list = field(default_factory=list)
    approval_bound: bool = False     # True if a signed approval covered this action
    replay_ok: bool = True
    replay_error: Optional[str] = None
    live_record: Optional[dict] = None
    state: ActionState = ActionState.PROPOSED
    venue_state: Optional[str] = None
    reconciliation: Optional[str] = None     # code
    reconciliation_detail: Optional[str] = None
    evidence_events: list = field(default_factory=list)
    blocked_reason: Optional[str] = None
    ledger_entry: Optional[dict] = None


class AuthorizationPipeline:
    def __init__(self, tenant, *, operator: OperatorAuthority,
                 registry: "_replay.ActionRegistry", evidence: EvidenceGraph,
                 limits: Optional[TenantLimits] = None,
                 risk_engine: Optional[RiskEngine] = None,
                 breaker: Optional[CircuitBreaker] = None,
                 velocity: Optional[VelocityGuard] = None,
                 venue=None, clock_now: int = 0):
        self._tenant = tenant
        self._operator = operator
        self._registry = registry
        self._evidence = evidence
        self._limits = limits or TenantLimits()
        self._risk = risk_engine or RiskEngine()
        self._breaker = breaker
        self._velocity = velocity
        self._venue = venue or SimulatedVenue()
        self._recon = ReconciliationEngine(self._venue)
        self._now = clock_now
        self._last_hash = ""      # causal head for the evidence chain

    def _emit(self, action: FinancialAction, state: ActionState,
              event_type: str, prev: str, payload: dict) -> EvidenceEvent:
        # Chain each event to the PREVIOUS event's actual hash (the causal
        # link), NOT the action's own action_hash. The action_hash (keccak256
        # of the intent) and the event_hash (sha256 of the event body) are
        # distinct; binding the chain to the wrong one made every chain after
        # the root fail verify_chain_integrity. `prev` is accepted for
        # call-site compatibility but the real link is tracked here.
        ev = EvidenceEvent(
            action_id=action.action_id, tenant_id=action.tenant_id,
            state=state, event_type=event_type, action_hash=action.action_hash,
            prev_event_hash=self._last_hash, payload=payload, timestamp=self._now)
        self._evidence.add(ev)
        self._last_hash = ev.event_hash
        return ev

    def run(self, action: FinancialAction,
            approval: Optional[ApprovalRecord] = None,
            require_human_approval: bool = False,
            denylist: tuple = ()) -> PipelineResult:
        tid = action.tenant_id
        ah = action.action_hash
        res = PipelineResult(action_id=action.action_id, action_hash=ah,
                             verdict="BLOCKED", state=ActionState.PROPOSED)

        # --- structural sanity (not authority) ---
        try:
            action.validate_structure()
        except ValueError as e:
            res.blocked_reason = f"structural: {e}"
            return res

        # --- 1. EPISTEMIC (frozen spine) ---
        proposal = _proposal_from_action(action)
        decision = self._tenant.authorize(
            proposal, denylist=denylist,
            require_human_approval=require_human_approval)
        verdict = decision.verdict
        self._emit(action, ActionState.PROPOSED, "EPISTEMIC",
                   "", {"verdict": verdict})
        res.verdict = verdict
        if verdict == "BLOCKED":
            res.blocked_reason = "epistemic BLOCKED"
            self._emit(action, ActionState.REJECTED, "REJECTION",
                       ah, {"reason": "epistemic BLOCKED"})
            res.state = ActionState.REJECTED
            return res

        # --- 2. POLICY already enforced by authorize(); advance to AUTHORIZED ---
        self._emit(action, ActionState.AUTHORIZED, "AUTHORIZED",
                   ah, {"capability": action.capability})

        # --- 3. RISK (narrowing only) ---
        risk: RiskVerdict = self._risk.evaluate(
            action, self._limits, state=RiskState(aum=self._tenant.aum),
            input_verdict=verdict)
        res.risk_ok = risk.ok
        res.risk_violations = [v.__dict__ for v in risk.violations]
        self._emit(action, ActionState.EVALUATED, "RISK", ah,
                   {"ok": risk.ok, "violations": res.risk_violations})
        if not risk.ok:
            res.verdict = "BLOCKED"
            res.blocked_reason = "risk: " + "; ".join(risk.reasons)
            self._emit(action, ActionState.REJECTED, "REJECTION", ah,
                       {"reason": "risk BLOCKED"})
            res.state = ActionState.REJECTED
            return res

        # --- 4. HUMAN workflow (signed approval binding) ---
        if verdict == "HUMAN":
            # A HUMAN verdict is ONLY executable when a genuine signed operator
            # approval covers the EXACT action hash. We verify BOTH:
            #   - the approval structurally binds to this action_hash, AND
            #   - the operator's Ed25519 signature over the approval is valid.
            # A forged approval (correct hashes, bad sig) is rejected here.
            good_sig = bool(approval) and approval.verify(self._operator.public_key)
            if approval is None or not approval.binds_to(ah) or not good_sig:
                res.blocked_reason = ("HUMAN verdict requires a valid signed "
                                      "operator approval binding this action")
                self._emit(action, ActionState.REJECTED, "REJECTION", ah,
                           {"reason": "missing/invalid/forged approval"})
                res.state = ActionState.REJECTED
                return res
            res.approval_bound = True
            self._emit(action, ActionState.APPROVED, "APPROVAL", ah,
                       {"operator": approval.operator_id,
                        "signature_verified": good_sig})
        else:
            self._emit(action, ActionState.APPROVED, "APPROVAL", ah,
                       {"auto_approved": True})

        # --- 5. REPLAY / ISOLATION registry ---
        try:
            self._registry.register(
                tenant_id=tid, action_id=action.action_id, action_hash=ah,
                nonce=action.nonce, now=self._now, expiry=action.expiry)
        except _replay.ReplayError as e:
            res.replay_ok = False
            res.replay_error = str(e)
            res.blocked_reason = f"replay/isolation: {e}"
            self._emit(action, ActionState.REJECTED, "REJECTION", ah,
                       {"reason": str(e)})
            res.state = ActionState.REJECTED
            return res

        # --- 6. OPERATOR CIRCUIT BREAKER (independent halt, before any signing) ---
        # The operator's panic switch halts execution regardless of verdict.
        # It must fire BEFORE the signer, so a halted operator stops everything.
        if self._breaker is not None and self._breaker.is_open:
            res.blocked_reason = "circuit breaker open"
            self._emit(action, ActionState.REJECTED, "REJECTION", ah,
                       {"reason": "breaker open"})
            res.state = ActionState.REJECTED
            return res

        # --- 7. SETTLEMENT structural + bound checks ---
        try:
            if action.capability == CAP_FIN_CHAIN_SETTLE:
                assert_no_pii(action.as_intent())
                validate_settlement_intent(action.as_intent())
            elif action.capability == CAP_FIN_TRADE_EXECUTE:
                validate_order(action.as_order())
        except ValueError as e:
            res.blocked_reason = f"settlement gate: {e}"
            self._emit(action, ActionState.REJECTED, "REJECTION", ah,
                       {"reason": str(e)})
            res.state = ActionState.REJECTED
            return res

        # --- 8. SIGNER (live track, opt-in & fail-closed) ---
        live_record = None
        if self._tenant.settlement_key is not None:
            try:
                if self._velocity:
                    self._velocity.check()
            except ValueError as e:
                res.blocked_reason = f"velocity: {e}"
                self._emit(action, ActionState.REJECTED, "REJECTION", ah,
                           {"reason": str(e)})
                res.state = ActionState.REJECTED
                return res
            if action.capability == CAP_FIN_CHAIN_SETTLE:
                rec = SettlementAuthRecord.build_for_action(
                    action=action, decision_ref=decision.request_ref,
                    capability=action.capability, verdict=verdict,
                    signer=self._tenant.settlement_key,
                    approved=res.approval_bound)
                live_record = rec.__dict__
            elif action.capability == CAP_FIN_TRADE_EXECUTE:
                rec = OrderAuthRecord.build_for_action(
                    action=action, decision_ref=decision.request_ref,
                    capability=action.capability, verdict=verdict,
                    signing_key=self._tenant.gov.private_key,
                    approved=res.approval_bound)
                live_record = rec.__dict__
            res.live_record = live_record
            self._emit(action, ActionState.SIGNED, "SIGNATURE", ah,
                       {"signer": live_record.get("signer_address")
                        or live_record.get("signer_pubkey")})
            self._registry.advance(tid, ah, _replay.ActionStatus.SIGNED)
            # Persist the live authorization record to the tenant's immutable
            # ledger (forensic closure): a genuine, on-chain-verifiable signature
            # over the authorized intent, with NO gateway key required to verify.
            self._tenant.append_ledger({
                "event": "live_sign",
                "action_id": action.action_id,
                "action_hash": ah,
                "capability": action.capability,
                "settlement_address": live_record.get("signer_address"),
                "intent_hash": ah,
                "live_signature": live_record.get("signature"),
            })

        # --- 8. VENUE submit ---
        venue_rep = self._venue.submit(action)
        res.venue_state = venue_rep.state.value
        self._emit(action, ActionState.SUBMITTED, "SUBMISSION", ah,
                   {"venue_state": venue_rep.state.value,
                    "tx_hash": venue_rep.tx_hash})
        self._registry.advance(tid, ah, _replay.ActionStatus.SUBMITTED)

        # --- 9. RECONCILE ---
        internal = InternalState(
            action_id=action.action_id, action_hash=ah,
            destination=action.destination,
            amount=action.notional_value or float(action.quantity),
            nonce=action.nonce, state=venue_rep.state.value)
        recon = self._recon.reconcile(internal)
        res.reconciliation = recon.code.value
        res.reconciliation_detail = recon.detail
        settled_state = (ActionState.SETTLED if recon.code.value == "MATCH"
                         else ActionState.FAILED)
        self._emit(action, settled_state, "RECONCILIATION", ah,
                   {"code": recon.code.value, "detail": recon.detail})
        res.state = settled_state

        # --- 10. Ledger append (durable, signed, key-free-verifiable) ---
        res.ledger_entry = self._tenant.append_ledger({
            "event": "v2_pipeline",
            "action_id": action.action_id,
            "action_hash": ah,
            "capability": action.capability,
            "verdict": res.verdict,
            "risk_ok": res.risk_ok,
            "approval_bound": res.approval_bound,
            "replay_ok": res.replay_ok,
            "venue_state": res.venue_state,
            "reconciliation": res.reconciliation,
            "reconciliation_detail": res.reconciliation_detail,
            "live_signature": (live_record or {}).get("signature"),
            "intent_hash": ah,
        })
        return res


def _proposal_from_action(action: FinancialAction):
    from ..finance.proposal import RathnoneFinanceProposal
    return RathnoneFinanceProposal(
        producer=action.actor or "rathnone-agent",
        request_id=action.action_id,
        capability=action.capability,
        action_descriptor=f"{action.side} {action.quantity} {action.instrument}",
        advisory_evidence={"financial_action": action.to_advisory()},
    )


__all__ = ["AuthorizationPipeline", "PipelineResult"]

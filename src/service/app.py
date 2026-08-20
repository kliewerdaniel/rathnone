"""FastAPI product gateway for Rathnone (F4).

Thin HTTP surface over the tenant-scoped, local-first authority runtime. Every
authorization call reaches the SAME frozen fleet.epistemic.decide() through
GatewayContext. The service:

  - mints tenants (each with its own Ed25519 key)         -> B8 isolation
  - authorizes the finance trio against the frozen spine  -> Invariant 1
  - appends a signed, key-free-verifiable ledger entry     -> F3 mirror
  - meters authorized (AUTO) actions per-AUM               -> B9
  - refuses execution unless authorized (fail-closed)       -> Phase 3

The signing key NEVER leaves the service; the console verifies with the tenant's
public key only.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel

from ..finance.proposal import RathnoneFinanceProposal
from ..finance.action import FinancialAction
from ..config import TenantLimits
from ..risk.engine import RiskEngine, RiskState
from ..security.operator import OperatorAuthority, ApprovalRecord
from ..security import replay as _replay
from ..security.replay import ActionRegistry, DurableActionRegistry
from ..evidence.chain import EvidenceGraph
from ..service.pipeline import AuthorizationPipeline
from ..venue.adapter import summarize_reconciliation, get_venue
from .. import hygiene as _hyg
from ..security.guards import (
    CircuitBreaker, VelocityGuard, Clock,
    sanitize_advisory_evidence,
)
from ..config import (
    max_settlement_value_wei, live_signing_rate_max_per_window,
)
from .auth import require_api_key, assert_auth_configured
from .tenant import TenantRegistry
from .metering import MeteringLedger

app = FastAPI(title="Rathnone Gateway", version="0.1.0")
assert_auth_configured()  # ADR 17: refuse to boot an unauthenticated control plane
_registry = TenantRegistry()
_meters: dict[str, MeteringLedger] = {}

# V4: process-wide safety controls for the autonomous loop. The circuit breaker
# is an independent halt the operator can trip WITHOUT the frozen decide() agreeing
# (the antidote to the "immutable cage" failure). VelocityGuard caps live-signing
# throughput so the live track can never become a high-frequency predation engine
# (antidote to V1). Both are environment-configurable and fail-closed: a malformed
# env value raises at import time rather than silently disabling the guard.
_clock = Clock(monotonic=True)
_breaker = CircuitBreaker(clock=_clock)
# Deployment knobs (fail-closed; see src/config.py):
#   RATHNONE_MAX_SETTLEMENT_VALUE_WEI  -> refuse transfers above this many wei
#   RATHNONE_LIVE_RATE_MAX             -> max live signatures per sliding window
_MAX_VALUE_WEI = max_settlement_value_wei()          # None = no ceiling (set in prod)
_velocity = VelocityGuard(clock=_clock,
                          max_per_window=live_signing_rate_max_per_window())

# Real-venue deployment switch (v2 P2). With no RATHNONE_L2_RPC_URL set (the
# default), get_venue() returns SimulatedVenue — identical to today, no egress.
# Set both to broadcast authorized+live-signed actions to a real L2. Never
# invented here; supply real values at deploy time.
import os
_L2_RPC_URL = os.environ.get("RATHNONE_L2_RPC_URL", "")
_L2_CHAIN_ID = int(os.environ.get("RATHNONE_L2_CHAIN_ID", "0") or "0")

# v3 epistemic-hygiene gate (knowledge-poisoning defense). DISABLED by default:
# the layer is opt-in (mirrors the live track). Set RATHNONE_HYGIENE_ENABLED=1 to
# turn it on. When enabled it demands independent corroboration for the action's
# economic claims and fails-closed (BLOCKED) on any uncorroborated claim. Sources
# (instrument master, price feeds) are configured out-of-band; unset => fail-closed.
_RATHNONE_HYGIENE_ENABLED = os.environ.get("RATHNONE_HYGIENE_ENABLED", "") == "1"
_hygiene = _hyg.CorroborationLayer(enabled=_RATHNONE_HYGIENE_ENABLED)

# v2 control-plane state (per-process singletons; deterministic authority layer).
_operator = OperatorAuthority()          # operator's Ed25519 approval key
_replay_registry = (
    DurableActionRegistry()
    if os.environ.get("RATHNONE_LEDGER_DB") else ActionRegistry()
)   # replay / nonce / cross-tenant (durable when RATHNONE_LEDGER_DB is set)
_evidence = EvidenceGraph()             # causal evidence graph (queryable view)
_risk_engine = RiskEngine()              # deterministic, narrowing-only
_limits = TenantLimits.from_env()        # env-sourced risk bounds


@dataclass
class _AuthorizeIn:
    producer: str
    request_id: str
    capability: str
    action_descriptor: str
    proposal_ref: str = ""
    advisory_evidence: Optional[dict] = None
    require_human_approval: bool = False
    denylist: tuple = ()


class _TenantCreate(BaseModel):
    aum: float = 0.0
    live: bool = False  # opt-in to the live (real-signing) track -> mints a settlement key


def _meter_for(tenant_id: str, tenant) -> MeteringLedger:
    m = _meters.get(tenant_id)
    if m is None:
        m = MeteringLedger(tenant_id=tenant_id)
        _meters[tenant_id] = m
    return m


@app.post("/tenants")
def create_tenant(body: _TenantCreate, _: None = Depends(require_api_key)):
    t = _registry.create(aum=body.aum)
    if body.live:
        t.enable_live()
    _meter_for(t.tenant_id, t)
    return {"tenant_id": t.tenant_id, "public_key_pem": t.public_key_pem,
            "aum": t.aum, "settlement_address": t.settlement_address}


@app.get("/tenants")
def list_tenants(_: None = Depends(require_api_key)):
    return {"tenant_ids": _registry.ids()}


@app.get("/safety")
def safety_state():
    """V4: expose the independent circuit-breaker state (operator visibility)."""
    return {"breaker_open": _breaker.is_open,
            "live_signing_enabled": not _breaker.is_open}


@app.post("/safety/halt")
def safety_halt(_: None = Depends(require_api_key)):
    """V4: trip the circuit breaker. Stops live signing/execution immediately,
    independently of the frozen decide(). This is the antidote to the immutable
    cage: the operator can always halt the autonomous loop."""
    _breaker.halt()
    return {"breaker_open": True}


@app.post("/safety/resume")
def safety_resume(_: None = Depends(require_api_key)):
    """V4: clear the circuit breaker. Operator action only — authenticated via
    the control-plane API key (ADR 17)."""
    _breaker.resume()
    return {"breaker_open": False}


def _get_tenant(tenant_id: str) -> "object":
    t = _registry.get(tenant_id)
    if t is None:
        raise HTTPException(status_code=404, detail="tenant not found")
    return t


@app.post("/tenants/{tenant_id}/authorize")
def authorize(tenant_id: str, body: _AuthorizeIn):
    t = _get_tenant(tenant_id)
    # V1: advisory_evidence is sanitized before recording. It NEVER reaches
    # fleet.epistemic.decide() (the translator drops it); this is defense-in-depth
    # so a future edit cannot smuggle a neutral decision field through.
    evidence = sanitize_advisory_evidence(body.advisory_evidence or {})
    proposal = RathnoneFinanceProposal(
        producer=body.producer, request_id=body.request_id,
        capability=body.capability, action_descriptor=body.action_descriptor,
        proposal_ref=body.proposal_ref,
        advisory_evidence=evidence,
    )
    decision = t.authorize(
        proposal,
        require_human_approval=body.require_human_approval,
        denylist=tuple(body.denylist),
    )
    # Record the authorization event in the tenant's signed ledger.
    rec = t.append_ledger({
        "event": "authorization",
        "request_id": body.request_id,
        "capability": body.capability,
        "verdict": decision.verdict,
        "producer": body.producer,
    })
    # Meter only on AUTO.
    _meter_for(tenant_id, t).record(
        verdict=decision.verdict, capability=body.capability,
        aum=t.aum, request_id=body.request_id,
    )
    return {"decision": asdict(decision), "ledger_entry": rec,
            "verify": t.verify_locally()[0]}


class _AuthorizeActionIn(BaseModel):
    """A proposed FinancialAction (v2 control-plane input)."""
    action: dict
    # Optional signed operator approval (HUMAN workflow). Must bind to action_hash.
    approval: Optional[dict] = None
    require_human_approval: bool = False
    denylist: tuple = ()


@app.post("/tenants/{tenant_id}/authorize_action")
def authorize_action(tenant_id: str, body: _AuthorizeActionIn):
    """v2 control-plane endpoint: run the FULL pipeline over a FinancialAction.

    Order: epistemic (frozen spine) -> policy -> risk (narrowing) -> HUMAN
    approval (if required) -> replay/isolation -> settlement gate -> signer ->
    state machine -> venue -> reconciliation -> evidence ledger.

    The operator approval (if supplied) MUST bind to the action's exact hash, or
    the request is refused (closes the "approve-one-execute-another" gap). Returns
    a machine-readable PipelineResult incl. the causal evidence events.
    """
    t = _get_tenant(tenant_id)
    try:
        action = FinancialAction(**body.action)
    except TypeError as e:
        raise HTTPException(status_code=400, detail=f"invalid action: {e}")
    action.tenant_id = tenant_id  # tenant-scoped; never trust caller's tenant

    approval = None
    if body.approval:
        try:
            approval = ApprovalRecord(**body.approval)
            approval.verify(_operator.public_key)
        except Exception:
            raise HTTPException(
                status_code=403,
                detail="supplied approval signature invalid or does not verify")

    # circuit breaker (independent operator halt)
    if _breaker.is_open:
        raise HTTPException(
            status_code=503,
            detail="live signing halted: circuit breaker open (operator control)")

    pipe = AuthorizationPipeline(
        t, operator=_operator, registry=_replay_registry, evidence=_evidence,
        limits=_limits, risk_engine=_risk_engine, hygiene=_hygiene,
        breaker=_breaker, velocity=_velocity, clock_now=_clock.now(),
        max_value_wei=_MAX_VALUE_WEI,
        venue=get_venue(t, rpc_url=_L2_RPC_URL, chain_id=_L2_CHAIN_ID))
    result = pipe.run(
        action, approval=approval,
        require_human_approval=body.require_human_approval,
        denylist=tuple(body.denylist))

    # Map final blocked/refused outcomes to HTTP 403/503.
    if result.blocked_reason:
        code = 503 if "breaker" in result.blocked_reason else 403
        raise HTTPException(status_code=code, detail=result.blocked_reason)

    return {
        "action_id": result.action_id,
        "action_hash": result.action_hash,
        "verdict": result.verdict,
        "risk_ok": result.risk_ok,
        "risk_violations": result.risk_violations,
        "approval_bound": result.approval_bound,
        "replay_ok": result.replay_ok,
        "hygiene_ok": result.hygiene_ok,
        "hygiene_violations": result.hygiene_violations,
        "state": result.state.value,
        "venue_state": result.venue_state,
        "tx_hash": getattr(result, "tx_hash", None),
        "reconciliation": result.reconciliation,
        "reconciliation_detail": result.reconciliation_detail,
        "live_record": result.live_record,
        "verify": t.verify_locally()[0],
    }


@app.get("/tenants/{tenant_id}/evidence/{action_id}")
def evidence_trace(tenant_id: str, action_id: str, _: None = Depends(require_api_key)):
    """Return the causal evidence chain for one action (the Authorization Trace)."""
    _get_tenant(tenant_id)
    chain = _evidence.trace(action_id)
    return {
        "action_id": action_id,
        "events": [c.__dict__ for c in chain],
        "current_state": (_evidence.current_state(action_id).value
                          if _evidence.current_state(action_id) else None),
        "transition_violations": _evidence.validate_transitions(action_id),
        "chain_integrity_ok": _evidence.verify_chain_integrity(),
    }


@app.get("/tenants/{tenant_id}/audit")
def audit(tenant_id: str, _: None = Depends(require_api_key)):
    t = _get_tenant(tenant_id)
    ok, reason = t.verify_locally()
    return {"tenant_id": tenant_id, "records": t.audit(),
            "verify_ok": ok, "verify_reason": reason}


@app.get("/tenants/{tenant_id}/meter")
def meter(tenant_id: str, _: None = Depends(require_api_key)):
    t = _get_tenant(tenant_id)
    return _meter_for(tenant_id, t).summary()


@app.get("/tenants/{tenant_id}/reconciliation")
def reconciliation(tenant_id: str, _: None = Depends(require_api_key)):
    """Cross-action reconciliation view (v2 P2).

    Aggregates the durable per-action reconciliation codes already committed to
    the tenant ledger — it does NOT re-query the venue. Fail-closed: never
    invents state, and an unrecognized code is reported as a divergence rather
    than dropped. Surfaces MATCH count, divergence list, and an all_matched flag.
    """
    t = _get_tenant(tenant_id)
    return {"tenant_id": tenant_id, **summarize_reconciliation(t.audit())}


__all__ = ["app", "_registry", "_meters"]

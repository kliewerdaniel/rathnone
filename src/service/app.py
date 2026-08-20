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

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ..finance.proposal import RathnoneFinanceProposal
from ..finance.adapters import (
    execute_trade_execute, execute_treasury_rebalance, execute_chain_settle,
    ExecutionRefused,
)
from ..security.guards import (
    CircuitBreaker, VelocityGuard, Clock,
    assert_no_pii, sanitize_advisory_evidence,
    validate_settlement_intent, validate_order,
)
from .tenant import TenantRegistry
from .metering import MeteringLedger

app = FastAPI(title="Rathnone Gateway", version="0.1.0")
_registry = TenantRegistry()
_meters: dict[str, MeteringLedger] = {}

# V4: process-wide safety controls for the autonomous loop. The circuit breaker
# is an independent halt the operator can trip WITHOUT the frozen decide() agreeing
# (the antidote to the "immutable cage" failure). VelocityGuard caps live-signing
# throughput so the live track can never become a high-frequency predation engine
# (antidote to V1). Defaults are permissive for local testing; production should
# tighten VelocityGuard(min_interval=..., max_per_window=...).
_clock = Clock()
_breaker = CircuitBreaker(clock=_clock)
_velocity = VelocityGuard(clock=_clock)
_MAX_VALUE_WEI = None  # set a deployment ceiling (e.g. 10**24) to refuse ruinous transfers


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
def create_tenant(body: _TenantCreate):
    t = _registry.create(aum=body.aum)
    if body.live:
        t.enable_live()
    _meter_for(t.tenant_id, t)
    return {"tenant_id": t.tenant_id, "public_key_pem": t.public_key_pem,
            "aum": t.aum, "settlement_address": t.settlement_address}


@app.get("/tenants")
def list_tenants():
    return {"tenant_ids": _registry.ids()}


@app.get("/safety")
def safety_state():
    """V4: expose the independent circuit-breaker state (operator visibility)."""
    return {"breaker_open": _breaker.is_open,
            "live_signing_enabled": not _breaker.is_open}


@app.post("/safety/halt")
def safety_halt():
    """V4: trip the circuit breaker. Stops live signing/execution immediately,
    independently of the frozen decide(). This is the antidote to the immutable
    cage: the operator can always halt the autonomous loop."""
    _breaker.halt()
    return {"breaker_open": True}


@app.post("/safety/resume")
def safety_resume():
    """V4: clear the circuit breaker (operator action only)."""
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


@app.post("/tenants/{tenant_id}/execute")
def execute(tenant_id: str, request_id: str, capability: str,
            action_descriptor: str, verdict: str,
            simulated: bool = True, human_approved: bool = False):
    """Fail-closed execution: refuses unless previously authorized (AUTO/HUMAN)."""
    t = _get_tenant(tenant_id)
    proposal = RathnoneFinanceProposal(
        producer="rathnone-gateway", request_id=request_id,
        capability=capability, action_descriptor=action_descriptor,
    )
    try:
        if capability == "rathnone.trade_execute":
            result = execute_trade_execute(proposal, verdict, simulated=simulated,
                                            human_approved=human_approved)
        elif capability == "rathnone.treasury_rebalance":
            result = execute_treasury_rebalance(proposal, verdict, simulated=simulated,
                                                 human_approved=human_approved)
        elif capability == "rathnone.chain_settle":
            result = execute_chain_settle(proposal, verdict, simulated=simulated,
                                          human_approved=human_approved)
        else:
            raise HTTPException(status_code=400, detail="unknown capability")
    except ExecutionRefused as e:
        raise HTTPException(status_code=403, detail=f"execution refused: {e}")
    return asdict(result)


class _ExecuteLiveIn(BaseModel):
    producer: str = "rathnone-gateway"
    request_id: str
    capability: str
    action_descriptor: str
    # The live payload to be signed (must match what was authorized).
    payload: dict  # settlement intent OR trade order, canonicalized before signing
    human_approved: bool = False
    denylist: tuple = ()


@app.post("/tenants/{tenant_id}/execute_live")
def execute_live(tenant_id: str, body: _ExecuteLiveIn):
    """Live track (opt-in, fail-closed): produce a REAL signature over an
    authorized intent/order.

    Flow: run the frozen decide() -> if AUTO and the live track is enabled for
    this tenant, commit a genuine secp256k1 (settlement) or Ed25519 (order)
    signature. Refuses (403) unless authorized. Never signs anything that was
    not AUTO-authorized by the frozen spine.
    """
    t = _get_tenant(tenant_id)
    # V4: the circuit breaker is an independent halt that does NOT require the
    # frozen decide() to agree. If tripped, live signing stops outright.
    if _breaker.is_open:
        raise HTTPException(
            status_code=503,
            detail="live signing halted: circuit breaker open (operator control)",
        )
    if t.settlement_key is None:
        raise HTTPException(
            status_code=403,
            detail="live track not enabled for tenant (mint with live=true)",
        )
    # V2: reject any ledger body that would bind the immutable record to
    # real-world identity (panopticon defense). Checked before signing.
    try:
        assert_no_pii(body.payload)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))
    # V1: cap live-signing throughput so the track cannot become a high-frequency
    # predation engine. Fail-closed: exceeding the limit refuses.
    try:
        _velocity.check()
    except ValueError as e:
        raise HTTPException(status_code=429, detail=str(e))
    proposal = RathnoneFinanceProposal(
        producer=body.producer, request_id=body.request_id,
        capability=body.capability, action_descriptor=body.action_descriptor,
    )
    decision = t.authorize(
        proposal, require_human_approval=False,
        denylist=tuple(body.denylist),
    )
    if decision.verdict != "AUTO":
        raise HTTPException(
            status_code=403,
            detail=f"live signing refused: verdict={decision.verdict}",
        )
    # V4: structural sanity for the thing actually being signed. Even with an
    # AUTO verdict, a structurally impossible / over-ceiling transfer is refused.
    try:
        if body.capability == "rathnone.chain_settle":
            validate_settlement_intent(body.payload, max_value_wei=_MAX_VALUE_WEI)
        elif body.capability == "rathnone.trade_execute":
            validate_order(body.payload)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=f"intent rejected: {e}")
    try:
        if body.capability == "rathnone.chain_settle":
            record = t.live_settle(
                intent=body.payload, decision_ref=decision.request_ref,
                verdict=decision.verdict)
        elif body.capability == "rathnone.trade_execute":
            record = t.live_order(
                order=body.payload, decision_ref=decision.request_ref,
                verdict=decision.verdict)
        else:
            raise HTTPException(
                status_code=400,
                detail="live track supports chain_settle and trade_execute",
            )
    except Exception as e:
        raise HTTPException(status_code=403, detail=f"live signing failed: {e}")
    # Append the live authorization to the tenant's immutable ledger so the
    # forensic audit trail shows the real signature. Signed with the tenant's
    # governance key -> part of the same key-free-verifiable chain.
    ledger_entry = t.append_ledger({
        "event": "live_sign",
        "capability": body.capability,
        "verdict": decision.verdict,
        "request_id": body.request_id,
        "settlement_address": record.get("signer_address"),
        "intent_hash": record.get("intent_hash"),
        "live_signature": record.get("signature"),
    })
    return {"decision": asdict(decision), "live_record": record,
            "ledger_entry": ledger_entry, "verify": t.verify_locally()[0]}


@app.get("/tenants/{tenant_id}/audit")
def audit(tenant_id: str):
    t = _get_tenant(tenant_id)
    ok, reason = t.verify_locally()
    return {"tenant_id": tenant_id, "records": t.audit(),
            "verify_ok": ok, "verify_reason": reason}


@app.get("/tenants/{tenant_id}/meter")
def meter(tenant_id: str):
    t = _get_tenant(tenant_id)
    return _meter_for(tenant_id, t).summary()


__all__ = ["app", "_registry", "_meters"]

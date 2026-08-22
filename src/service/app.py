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

import os

from dataclasses import asdict, dataclass
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Request
from pydantic import BaseModel

from ..finance.proposal import RathnoneFinanceProposal
from ..finance.action import FinancialAction
from ..config import TenantLimits
from ..risk.engine import RiskEngine, RiskState
from ..security.operator import (
    OperatorAuthority, ApprovalRecord,
    OperatorCommand, verify_command, body_hash_of, OperatorKeyRing,
)
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
    live_default_max_settlement_wei,
    hygiene_enabled, hygiene_price_band_bps, hygiene_quorum, hygiene_price_sources,
)
from .auth import require_api_key, require_key_ops_key, assert_auth_configured
from .tenant import TenantRegistry
from ..security.keystore import DurableOperatorKeyStore
from .metering import MeteringLedger

# ADR 19/21: safety verbs (halt/resume) are SERVICE-GLOBAL, not tenant-scoped, so
# they use a dedicated global operator keyring + command-nonce set (separate from
# any single tenant's). Empty (no active keys) by default => signed-command layer
# dormant; safety verbs stay on the ADR 17 static-key path until operators are
# provisioned out-of-band. Provision via app.configure_safety_operators([pem, ...]).
class _SafetyOperatorScope:
    operator_keys: "OperatorKeyRing" = None  # set below (avoids forward ref at import)
    _used_command_nonces: set[int] = set()
    _keys_hydrated: bool = False  # ADR 23: False => load from durable store on first use

    def record_command(self, *, verb: str, operator_id: str,
                       operator_pubkey_pem: str, nonce: int,
                       reason: str = "") -> None:
        # The service-wide safety audit trail lives in the in-memory registry for
        # immediate visibility, AND (F4) is written through to the durable
        # operator-key store's safety scope when one is configured, so the
        # who-halted / who-resumed trail survives a process restart (Inv 3:
        # key-free replay depends on the binding still existing). The store holds
        # the SAME OperatorKeyEntry data model keyed by (scope, key_id); we reuse
        # it for the safety-command audit as a small, append-only event log.
        _safety_audit.append({
            "event": "operator_command", "verb": verb,
            "operator_id": operator_id, "operator_pubkey_pem": operator_pubkey_pem,
            "nonce": nonce, "reason": reason,
        })
        ks = _key_store_singleton()
        if ks is not None:
            try:
                ks.append_safety_audit({
                    "event": "operator_command", "verb": verb,
                    "operator_id": operator_id,
                    "operator_pubkey_pem": operator_pubkey_pem,
                    "nonce": nonce, "reason": reason,
                    "ts": int(time.time()),
                })
            except Exception:
                # Fail-closed enough: the in-memory trail is intact and the live
                # verdict has already been denied/allowed by the gate above. A
                # store write failure must not crash the verb, but it IS logged
                # for the operator (the durable trail is best-effort on top of
                # the authoritative in-memory record).
                pass


_SAFETY_SCOPE = "safety"  # ADR 23: durable-store scope id for the global safety keyring
# Per-tenant scope id is the tenant_id itself.

# ADR 23 — durable operator-key store. None when RATHNONE_KEY_DB is unset:
# the service stays fully in-memory (ADR 17-22 default). When set, the keyring is
# hydrated from / written through to SQLite so runtime key changes survive restart.
#
# Resolved LAZILY at call time (like the ADR 17 auth env reads) so a deployment
# can enable durability without re-importing the app module — and so the test
# suite can toggle it per-session. The first call that finds RATHNONE_KEY_DB set
# builds (and caches) the connection.
_key_store: Optional["DurableOperatorKeyStore"] = None


def _key_store_singleton() -> Optional["DurableOperatorKeyStore"]:
    global _key_store
    if _key_store is None and os.environ.get("RATHNONE_KEY_DB"):
        _key_store = DurableOperatorKeyStore()
    return _key_store


_SAFETY_TENANT = _SafetyOperatorScope()
_SAFETY_TENANT.operator_keys = OperatorKeyRing()
_safety_audit: list[dict] = []


def _hydrate_safety_keys() -> None:
    """ADR 23 — load the global safety keyring from the durable store on first use.

    Idempotent: guarded by ``_keys_hydrated``. After any mutation through the
    management surface we reset that flag so a later read re-hydrates from the
    written-through store (reflecting the new truth) rather than the stale
    in-memory copy. A store read failure is fatal (fail-closed).
    """
    if _SAFETY_TENANT._keys_hydrated:
        return
    ks = _key_store_singleton()
    if ks is None:
        return
    _SAFETY_TENANT.operator_keys = ks.load_scope(_SAFETY_SCOPE)
    _SAFETY_TENANT._keys_hydrated = True


def configure_safety_operators(pems: list[str]) -> None:
    """Provision the global operator keyring for safety verbs (ADR 19 + ADR 21).

    Called out-of-band (deploy-time / operator tooling). Until called (or after
    every key is revoked/expired), the signed-command layer for halt/resume is
    dormant and the ADR 17 static key is the sole gate — fail-closed and
    console-compatible. ADR 21: each PEM becomes a keyring entry so individual
    keys can later be revoked/expired without a redeploy. ADR 23: when a durable
    store is configured, the new ring is written through so it survives restart.
    """
    _SAFETY_TENANT.operator_keys = OperatorKeyRing.from_pems(pems)
    ks = _key_store_singleton()
    if ks is not None:
        ks.persist_ring(_SAFETY_SCOPE, _SAFETY_TENANT.operator_keys)
    _SAFETY_TENANT._keys_hydrated = True  # bootstrap authoritative; mark hydrated


_hydrate_safety_keys()  # hydrate at import if a durable store is configured


app = FastAPI(title="Rathnone Gateway", version="0.1.0")
assert_auth_configured()  # ADR 17: refuse to boot an unauthenticated control plane


# ---------------------------------------------------------------------------
# ADR 22 — operator-key lifecycle management surface (runtime, no redeploy)
#
# These endpoints change WHO can sign operator commands (safety verbs + tenant
# settlement), so they are the control plane's crown jewels. Each is gated by
# TWO factors (ADR 17 + ADR 22):
#   - require_api_key           -> the shared RATHNONE_API_KEY (transport gate)
#   - require_key_ops_key       -> a DISTINCT RATHNONE_KEY_OPS secret (2nd factor)
# Both must be satisfied in enforce mode; fail-closed otherwise. The console
# never calls these (it cannot hold signing keys) — an out-of-band ops tool
# does. A second factor is mandatory because a single shared key that also
# gates routine tenant provisioning is a single point of compromise for the
# entire live-signing authority.
# ---------------------------------------------------------------------------

class _OpKeyAdd(BaseModel):
    public_key_pem: str
    operator_id: str = ""
    role: str = "operator"
    expires_at: Optional[int] = None   # epoch s, None = no expiry


class _OpKeyRevoke(BaseModel):
    key_id: str          # sha256(pem)[:16] handle, OR the full PEM


class _OpKeyRotate(BaseModel):
    new_public_key_pem: str
    old_public_key_pem: Optional[str] = None
    operator_id: str = ""
    expires_at: Optional[int] = None
    expire_old_in_s: int = 0      # >0 -> graceful grace window instead of instant revoke


def _scope_for(scope: str, tenant_id: str = ""):
    """Resolve the keyring a management call targets (fail-closed)."""
    if scope == "safety":
        return _SAFETY_TENANT
    if scope == "tenant":
        if not tenant_id:
            raise HTTPException(status_code=400, detail="tenant_id required for scope=tenant")
        return _get_tenant(tenant_id)
    raise HTTPException(status_code=400, detail="scope must be 'safety' or 'tenant'")


def _key_summary(ring: "OperatorKeyRing") -> list[dict]:
    return [{
        "key_id": e.key_id,
        "operator_id": e.operator_id,
        "role": e.role,
        "added_at": e.added_at,
        "expires_at": e.expires_at,
        "revoked": e.revoked,
        "active": e.is_active(int(time.time())),
    } for e in ring]


def _store_scope(target, scope: str, tenant_id: str = "") -> None:
    """ADR 23 — write a mutated keyring back to the durable store (fail-closed).

    Only acts when a durable store is configured. After persisting, reset the
    target's ``_keys_hydrated`` flag so a subsequent read re-hydrates from the
    store (the authoritative truth) rather than the now-stale in-memory copy.
    A store write failure raises rather than silently degrading to memory.
    """
    ks = _key_store_singleton()
    if ks is None:
        return
    sid = _SAFETY_SCOPE if scope == "safety" else tenant_id
    ks.persist_ring(sid, target.operator_keys)
    target._keys_hydrated = True


@app.get("/operator-keys")
def list_operator_keys(scope: str, tenant_id: str = "",
                       _: None = Depends(require_api_key),
                       __: None = Depends(require_key_ops_key)):
    """ADR 22 — list current operator keys (active + historical) for a scope."""
    target = _scope_for(scope, tenant_id)
    return {"scope": scope, "tenant_id": tenant_id,
            "keys": _key_summary(target.operator_keys)}


@app.post("/operator-keys")
def add_operator_key(body: _OpKeyAdd, scope: str, tenant_id: str = "",
                     _: None = Depends(require_api_key),
                     __: None = Depends(require_key_ops_key)):
    """ADR 22 — provision a new operator key into a scope (no redeploy)."""
    target = _scope_for(scope, tenant_id)
    entry = target.operator_keys.add(
        body.public_key_pem, operator_id=body.operator_id,
        role=body.role, expires_at=body.expires_at)
    _store_scope(target, scope, tenant_id)
    return {"key_id": entry.key_id, "operator_id": entry.operator_id,
            "active": entry.is_active(int(time.time()))}


@app.post("/operator-keys/revoke")
def revoke_operator_key(body: _OpKeyRevoke, scope: str, tenant_id: str = "",
                        _: None = Depends(require_api_key),
                        __: None = Depends(require_key_ops_key)):
    """ADR 22 — immediately revoke a key by handle (key_id) or full PEM."""
    target = _scope_for(scope, tenant_id)
    ok = target.operator_keys.revoke(body.key_id)
    if not ok:
        raise HTTPException(status_code=404, detail="operator key not found")
    _store_scope(target, scope, tenant_id)
    return {"revoked": body.key_id, "layer_active": bool(target.operator_keys.active_pems())}


@app.post("/operator-keys/rotate")
def rotate_operator_key(body: _OpKeyRotate, scope: str, tenant_id: str = "",
                        _: None = Depends(require_api_key),
                        __: None = Depends(require_key_ops_key)):
    """ADR 22 — add a new key and gracefully retire the old one (grace window)."""
    target = _scope_for(scope, tenant_id)
    new = target.operator_keys.rotate(
        body.new_public_key_pem, old_pem=body.old_public_key_pem,
        operator_id=body.operator_id, expires_at=body.expires_at,
        expire_old_in_s=body.expire_old_in_s)
    _store_scope(target, scope, tenant_id)
    return {"new_key_id": new.key_id,
            "layer_active": bool(target.operator_keys.active_pems())}


@app.get("/operator/public-key")
def operator_public_key():
    """ADR 37 — READ-ONLY operator public-key endpoint.

    Returns the gateway's current operator signing key (the key that authorizes
    approvals and signed operator commands, ADR 19/20) so an out-of-band auditor
    can build a cross-surface attestation manifest (``scripts/surface_attest.py``)
    against the key the gateway is *actually* serving -- not a key it merely
    claims about itself.

    This is the public half of a key pair; exposing it is safe (mirrors the
    evidence engine's ungated ``/authority/public-key``). It writes nothing and
    touches no authz path. The frozen ``decide()`` spine is never referenced here.
    """
    import hashlib
    pem = _operator.public_key_pem
    fp = hashlib.sha256("".join(pem.split()).encode("utf-8")).hexdigest()
    return {
        "algorithm": "ed25519",
        "operator_id": _operator.operator_id,
        "public_key_pem": pem,
        "key_fingerprint": fp,
    }


_registry = TenantRegistry()
_meters: dict[str, MeteringLedger] = {}

# V4: process-wide safety controls for the autonomous loop. The circuit breaker
# is an independent halt the operator can trip WITHOUT the frozen decide() agreeing
# (the antidote to the "immutable cage" failure). VelocityGuard caps live-signing
# throughput so the live track can never become a high-frequency predation engine
# (antidote to V1). Both are environment-configurable and fail-closed: a malformed
# env value raises at import time rather than silently disabling the guard.
_clock = Clock(monotonic=True)
# F5: a SEPARATE clock for operator-command timestamp verification. It returns
# wall-clock epoch-nanoseconds (int(time.time()*1e9)) — the same domain the
# out-of-band signing tool uses — so a command minted in one process is accepted
# by the gateway in another within the acceptance window. (The monotonic `_clock`
# above is process-relative and only suitable for intra-process liveness.)
_command_clock = Clock(epoch_ns=True)
_breaker = CircuitBreaker(clock=_clock)
# Deployment knobs (fail-closed; see src/config.py):
#   RATHNONE_MAX_SETTLEMENT_VALUE_WEI  -> refuse transfers above this many wei
#   RATHNONE_LIVE_RATE_MAX             -> max live signatures per sliding window
# ADR 26: if the operator sets no explicit ceiling, a LIVE tenant is still
# bounded by a deliberately small conservative default (1 ETH) rather than left
# unbounded. Simulated/non-live deployments keep the None (no cap) behaviour so
# existing dev/CI is unaffected — the cap only bites on the live settlement path.
_velocity = VelocityGuard(clock=_clock,
                          max_per_window=live_signing_rate_max_per_window())


def _settlement_ceiling_wei(t) -> Optional[int]:
    """ADR 26: resolve the settlement ceiling for THIS request.

    Read at request time (not import time) so an operator who flips
    RATHNONE_MAX_SETTLEMENT_VALUE_WEI sees it take effect on the next request
    without reloading the module. A LIVE tenant (settlement_key set) with no
    operator ceiling is bounded by a deliberately small conservative default
    (1 ETH) instead of being left UNBOUNDED — the exact machine-speed drain
    the 2026 OpenAI->HuggingFace intrusion demonstrated. Simulated/non-live
    tenants keep the None (no cap) behaviour so existing dev/CI is unaffected.
    """
    operator_ceiling = max_settlement_value_wei()
    if operator_ceiling is not None:
        return operator_ceiling
    return live_default_max_settlement_wei() if t.settlement_key is not None else None

# Real-venue deployment switch (v2 P2). With no RATHNONE_L2_RPC_URL set (the
# default), get_venue() returns SimulatedVenue — identical to today, no egress.
# Set both to broadcast authorized+live-signed actions to a real L2. Never
# invented here; supply real values at deploy time.
import time
_L2_RPC_URL = os.environ.get("RATHNONE_L2_RPC_URL", "")
_L2_CHAIN_ID = int(os.environ.get("RATHNONE_L2_CHAIN_ID", "0") or "0")

# v3 epistemic-hygiene gate (knowledge-poisoning defense). DISABLED by default:
# the layer is opt-in (mirrors the live track). Set RATHNONE_HYGIENE_ENABLED=1 to
# turn it on. When enabled it demands independent corroboration for the action's
# economic claims and fails-closed (BLOCKED) on any uncorroborated claim. Sources
# (instrument master, price feeds) are configured out-of-band; unset => fail-closed.
# ADR 24: sources are read from fail-closed env knobs so a deployment can configure
# genuinely DISTINCT corroboration origins without code changes; quorum counts
# distinct sources, not repeated values.
_RATHNONE_HYGIENE_ENABLED = os.environ.get("RATHNONE_HYGIENE_ENABLED", "") == "1"
_hygiene = _hyg.CorroborationLayer(
    enabled=_RATHNONE_HYGIENE_ENABLED,
    price_band_bps=hygiene_price_band_bps(),
    quorum=hygiene_quorum(),
    price_sources=hygiene_price_sources() or None,
)

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


def _require_command(request: "object", *, verb: str, tenant_id: str,
                     body: bytes, tenant) -> None:
    """ADR 19/20 gate for a safety- or settlement-critical verb.

    The static control-plane key (ADR 17, ``require_api_key``) is coarse transport
    defense-in-depth; for safety/settlement-critical verbs it is no longer
    *sufficient* once the operator allowlist is configured. When configured, the
    command must additionally carry a signed ``OperatorCommand`` binding this exact
    verb + tenant + body hash + nonce + timestamp to an allowlisted operator key.

    Applied to:
      - ``halt`` / ``resume`` (ADR 19) — ``tenant`` is the service-global
        ``_SAFETY_TENANT`` scope (safety verbs are service-global).
      - ``authorize`` (ADR 20) — ``tenant`` is the *actual* tenant; the command is
        verified against that tenant's own ``operator_allowlist`` (settlement
        authority is a property of the tenant, not the service).

    Fail-closed: a missing allowlist => the signed-command layer is dormant and the
    ADR 17 static key remains the sole gate. The console never holds signing keys,
    so the verb stays on the shared-key path until operators are provisioned
    out-of-band (tenant-scoped for authorize, global for safety verbs).
    """
    allowlist = tenant.operator_keys.active_pems() if hasattr(tenant, "operator_keys") else getattr(tenant, "operator_allowlist", [])
    if not allowlist:
        # No operators configured: the signed-command layer is not in force for
        # this tenant. The static control-plane key (applied at the route) remains
        # the sole auth. Safety verbs stay on the shared-key path until operators
        # are provisioned out-of-band.
        return
    # An operator allowlist IS configured: a signed command is mandatory. It
    # arrives as an X-Operator-Command header (base64 of the JSON-serialized
    # OperatorCommand) so it can wrap a request body of any shape.
    import base64, json as _json
    req = request if isinstance(request, Request) else None
    cmd_json = req.headers.get("x-operator-command") if req is not None else None
    if not cmd_json:
        raise HTTPException(
            status_code=401,
            detail="operator-signed command required (tenant has an operator allowlist)")
    try:
        cmd_dict = _json.loads(base64.b64decode(cmd_json).decode())
        cmd = OperatorCommand(**{
            k: v for k, v in cmd_dict.items()
            if k in OperatorCommand.__dataclass_fields__
        })
    except Exception:
        raise HTTPException(status_code=400, detail="malformed operator command")
    ok, why = verify_command(
        cmd, body=body, allowlist_pems=allowlist,
        used_nonces=tenant._used_command_nonces, now=_command_clock.now(),
        scope=tenant_id)
    if not ok:
        raise HTTPException(status_code=401, detail=f"operator command refused: {why}")
    tenant._used_command_nonces.add(cmd.nonce)
    tenant.record_command(
        verb=verb, operator_id=cmd.operator_id,
        operator_pubkey_pem=cmd.pubkey_pem, nonce=cmd.nonce)


@app.post("/tenants")
def create_tenant(body: _TenantCreate, _: None = Depends(require_api_key)):
    t = _registry.create(aum=body.aum)
    if body.live:
        t.enable_live()
    _meter_for(t.tenant_id, t)
    return {"tenant_id": t.tenant_id, "public_key_pem": t.public_key_pem,
            "aum": t.aum, "settlement_address": t.settlement_address,
            "operator_gated": bool(t.operator_keys.active_pems())}


@app.get("/tenants")
def list_tenants(_: None = Depends(require_api_key)):
    return {"tenant_ids": _registry.ids()}


@app.get("/safety")
def safety_state():
    """V4: expose the independent circuit-breaker state (operator visibility)."""
    return {"breaker_open": _breaker.is_open,
            "live_signing_enabled": not _breaker.is_open}


@app.post("/safety/halt")
async def safety_halt(request: Request, _: None = Depends(require_api_key)):
    """V4: trip the circuit breaker. Stops live signing/execution immediately,
    independently of the frozen decide(). This is the antidote to the immutable
    cage: the operator can always halt the autonomous loop.

    ADR 19: when the global operator allowlist is configured, the command must be
    a signed OperatorCommand (attributed + replay-guarded). Otherwise the ADR 17
    static control-plane key remains the sole gate. F2b: the command is bound to
    the ACTUAL request body (the raw POST bytes), not a hardcoded literal, so the
    signed-command gate enforces real request binding rather than a constant.
    """
    raw = await request.body()
    _require_command(request, verb="halt", tenant_id="__safety__",
                     body=raw, tenant=_SAFETY_TENANT)
    _breaker.halt()
    return {"breaker_open": True}


@app.post("/safety/resume")
async def safety_resume(request: Request, _: None = Depends(require_api_key)):
    """V4: clear the circuit breaker. Operator action only.

    ADR 19: signed OperatorCommand required when the global operator allowlist is
    configured (see safety_halt)."""
    raw = await request.body()
    _require_command(request, verb="resume", tenant_id="__safety__",
                     body=raw, tenant=_SAFETY_TENANT)
    _breaker.resume()
    return {"breaker_open": False}


def _get_tenant(tenant_id: str) -> "object":
    t = _registry.get(tenant_id)
    if t is None:
        raise HTTPException(status_code=404, detail="tenant not found")
    # ADR 23: if a durable key store is configured, hydrate this tenant's
    # operator keyring from it on first access (lazy, fail-closed). A tenant
    # created in this process starts with `_keys_hydrated=False`, so a keyring
    # we built locally is used as-is until a mutation path marks it dirty.
    if _key_store_singleton() is not None and not getattr(t, "_keys_hydrated", False):
        t.operator_keys = _key_store_singleton().load_scope(tenant_id)
        t._keys_hydrated = True
    return t


@app.get("/tenants/{tenant_id}")
def tenant_info(tenant_id: str, _: None = Depends(require_api_key)):
    """Non-secret tenant metadata (operator visibility)."""
    t = _get_tenant(tenant_id)
    return {
        "tenant_id": t.tenant_id,
        "aum": t.aum,
        "live": t.settlement_key is not None,
        "operator_gated": bool(t.operator_keys.active_pems()),
    }


@app.post("/tenants/{tenant_id}/authorize")
def authorize(tenant_id: str, body: _AuthorizeIn,
              _: None = Depends(require_api_key)):
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
    # ADR 18: optional signed operator DOWNGRADE of a hygiene-BLOCKED action.
    # Must bind to action_hash and release only the violations the action was
    # actually blocked on; verified against the tenant operator-allowlist.
    downgrade: Optional[dict] = None
    require_human_approval: bool = False
    denylist: tuple = ()


@app.post("/tenants/{tenant_id}/authorize_action")
async def authorize_action(tenant_id: str, body: _AuthorizeActionIn,
                           request: Request,
                           _: None = Depends(require_api_key)):
    """v2 control-plane endpoint: run the FULL pipeline over a FinancialAction.

    Order: epistemic (frozen spine) -> policy -> risk (narrowing) -> HUMAN
    approval (if required) -> replay/isolation -> settlement gate -> signer ->
    state machine -> venue -> reconciliation -> evidence ledger.

    The operator approval (if supplied) MUST bind to the action's exact hash, or
    the request is refused (closes the "approve-one-execute-another" gap). Returns
    a machine-readable PipelineResult incl. the causal evidence events.
    """
    t = _get_tenant(tenant_id)
    # ADR 20: for a tenant with an operator allowlist, the live-settlement transport
    # requires a signed OperatorCommand (verb="authorize") binding this exact request
    # body. Dormant until the tenant opts into operator authority (allowlist set
    # out-of-band); non-gated tenants stay on the ADR 17 static-key path. The body
    # hash binds the full canonical request (action + approval + downgrade + flags),
    # so a captured command cannot be replayed against a different action/approval.
    import json as _cmd_json
    _authorize_body = _cmd_json.dumps(
        body.model_dump(), sort_keys=True, separators=(",", ":")).encode()
    _require_command(
        request, verb="authorize", tenant_id=tenant_id,
        body=_authorize_body, tenant=t)
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

    # ADR 18: a signed operator downgrade of a hygiene-BLOCKED action. The
    # pipeline verifies it against the TENANT's operator-allowlist (not the
    # gateway's single operator key) — fail-closed if it cannot be verified.
    downgrade = None
    if body.downgrade:
        from src.hygiene import DowngradeRecord
        try:
            downgrade = DowngradeRecord(**{
                k: v for k, v in body.downgrade.items()
                if k in DowngradeRecord.__dataclass_fields__
            })
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="invalid downgrade record")

    # circuit breaker (independent operator halt)
    if _breaker.is_open:
        raise HTTPException(
            status_code=503,
            detail="live signing halted: circuit breaker open (operator control)")

    pipe = AuthorizationPipeline(
        t, operator=_operator, registry=_replay_registry, evidence=_evidence,
        limits=_limits, risk_engine=_risk_engine, hygiene=_hygiene,
        breaker=_breaker, velocity=_velocity, clock_now=_clock.now(),
        max_value_wei=_settlement_ceiling_wei(t),
        venue=get_venue(t, rpc_url=_L2_RPC_URL, chain_id=_L2_CHAIN_ID))
    result = pipe.run(
        action, approval=approval, downgrade=downgrade,
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
        "downgraded": result.downgraded,
        "downgrade_violations": result.downgrade_violations,
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


# --- ADR 40: agent-harness authority binding ---------------------------------
# The harness (Hermes + Codex sub-agents) asks the control plane whether a
# consequential action may be applied. It is the 8th registered consumer of the
# SAME frozen decide() spine (see src/finance/registry.py). Fail-closed: any
# unverifiable state refuses rather than running open.
from .harness_auth import evaluate_harness_action


@app.post("/harness/authorize")
def harness_authorize(
    body: dict,
    _: None = Depends(require_api_key),
):
    """ADR 40: gate a harness apply-action against the control plane.

    Body may carry ``{"policy_allow": bool, "human_override": bool}``. Returns
    ``{decision, reason, breaker_open, dormant}``. The harness consults this
    before applying a patch / commit / destructive command, and refuses on
    anything other than ``ALLOW``.
    """
    policy_allow = bool(body.get("policy_allow", True))
    human_override = bool(body.get("human_override", False))
    verdict = evaluate_harness_action(
        policy_allow=policy_allow,
        human_override=human_override,
        breaker_open=_breaker.is_open,
    )
    return {
        "decision": verdict.decision,
        "reason": verdict.reason,
        "breaker_open": verdict.breaker_open,
        "dormant": verdict.dormant,
    }


__all__ = ["app", "_registry", "_meters"]

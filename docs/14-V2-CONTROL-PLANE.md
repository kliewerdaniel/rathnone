# Rathnone v2 — Financial Authorization & Settlement Control Plane

**Status: IMPLEMENTED & VERIFIED — full v2 control plane + real L2 venue + operator console shipped. 85 pytest green (incl. the real-venue gateway e2e). Not yet committed (standing discipline: review before push).**

This document extends Rathnone from a *secure signing gateway* into a *financial
control plane*: a deterministic authority layer that turns an autonomous agent's
economic intent into a cryptographically verifiable, auditable state machine —
without ever feeding execution state back into the epistemic spine.

It deliberately builds on what already exists. The table below maps the v2 layers
to real symbols in the repo so we extend, not rebuild.

---

## 0. Thesis (the part worth building around)

> A *potentially untrusted* autonomous system may propose economically
> consequential actions, but an **independent deterministic authority layer**
> decides whether they are executable, enforces financial constraints, requires
> human intervention when appropriate, and produces cryptographically verifiable
> evidence explaining what happened.

This is the financial instantiation of Sovereign Agent Fleet's execution protocol:

```
Sovereign Agent Fleet:  agent → governed execution → verification → evidence
Rathnone v2:           agent → financial intent → governance → risk →
                        authorization → settlement → reconciliation → evidence
```

"Live crypto" is explicitly NOT the centerpiece. The adversarial suite runs
entirely on the **simulated** path. The centerpiece is the control plane.

---

## 1. Current state (what already exists — do not rebuild)

| Layer | Today (real symbol) | v2 role |
|---|---|---|
| Epistemic | `fleet.epistemic.decision.decide()` via `GatewayContext.authorize()` (`src/gateway`, `src/service/tenant.py:authorize`) | unchanged — the ONLY model surface |
| Verdict | `AUTO` / `HUMAN` / `BLOCKED` (`src/finance/proposal.py`, `exchange.epistemic_adapter`) | unchanged; HUMAN becomes a workflow (Fork 3) |
| Proposal | `RathnoneFinanceProposal(producer, request_id, capability, action_descriptor, proposal_ref, advisory_evidence)` | wrapped by `FinancialAction` (Fork 1) |
| Bounds | `RATHNONE_MAX_SETTLEMENT_VALUE_WEI`, `RATHNONE_LIVE_RATE_MAX` (`src/config.py`) | folded into risk engine as limits |
| Signing | `SettlementAuthRecord` (secp256k1), `OrderAuthRecord` (Ed25519) (`src/live/__init__.py`) | hashes over `FinancialAction`, not raw dict |
| Ledger | signed sha256(prev‖body) chain, `Tenant.append_ledger`/`verify_locally` (`src/mirror`, `src/service/tenant.py`) | extended with state + causal refs (Fork 4) |
| Safety | `CircuitBreaker`, `VelocityGuard` (`src/security/guards.py`, `/safety/halt`) | unchanged (independent operator halt) |
| Execution | `execute_trade_execute` / `_treasury_rebalance` / `_chain_settle` (`src/finance/adapters.py`) | gated behind risk + approval + state |
| Tenant | `Tenant` / `TenantRegistry`, per-tenant Ed25519 key (`src/service/tenant.py`) | isolation hardened (Fork 7) |

Invariants preserved: **Inv 1** (ModelOutput ≠ Authorization — risk/approval never
feed decide), **Inv 3** (Verification ⟂ Cognition — key-free ledger verify
unchanged), **V1** (velocity), **V2** (no PII in ledger), **V4** (operator
circuit breaker independent of spine).

---

## 2. Target pipeline

```
Agent
  │  FinancialAction (proposed economic state transition)
  ▼
Epistemic Layer      fleet.epistemic.decide()  → AUTO / HUMAN / BLOCKED   [frozen, only model surface]
  ▼
Policy Authorization tenant.authorize() + allowlist/denylist              [unchanged]
  ▼
Financial Risk       RiskEngine.evaluate(action, limits)  → narrows AUTO→BLOCKED only   [NEW, deterministic]
  ▼
Human Approval       if HUMAN/forced: require signed ApprovalRecord(action_hash) + verify sig  [NEW]
  ▼
Replay & Isolation   ActionRegistry: nonce/expiry/replay/cross-tenant                    [NEW]
  ▼
Circuit Breaker      operator halt gate — checked BEFORE settlement/signer                [NEW placement]
  ▼
Settlement Gate      structural + bound checks (value, nonce, expiry, replay)            [extended]
  ▼
Signer               SettlementAuthRecord / OrderAuthRecord over action_hash           [re-hash target]
  ▼
State Machine        PROPOSED→AUTHORIZED→APPROVED→SIGNED→SUBMITTED→ACCEPTED→SETTLED     [NEW, P1]
  ▼
Venue (sim)         VenueAdapter.submit()  → venue state                                [NEW, P1]
  ▼
Reconciliation      diff(internal, venue) → reconciliation events                       [NEW, P1]
  ▼
Evidence Graph      causal chain of signed events, each refs prev event hash            [NEW, P1]
```

Key asymmetry (ratify in Fork 2): **the risk engine and approval layer can only
NARROW a verdict (AUTO→BLOCKED), never WIDEN (BLOCKED→AUTO).** The model's
AUTO is necessary-but-not-sufficient; deterministic authority is the final word.

---

## 3. P0 — the cohesive first phase

### 3.1 `FinancialAction` (Fork 1)
`src/finance/action.py` — a dataclass carrying the economic state transition:

```
action_id, tenant_id, actor, strategy_id, instrument, venue,
side, quantity, price_limit, currency, notional_value,
settlement_asset, destination, nonce, timestamp, expiry,
risk_class, evidence
```

- `action_hash = keccak256(canonical_json(action))` — the **unified signable
  target**, replacing the current per-record `intent`/`order` dict hashing in
  `SettlementAuthRecord.compute_intent_hash` / `OrderAuthRecord.compute_order_hash`.
- Wrapped under `RathnoneFinanceProposal` as an *advisory* `action` field that
  the spine translator drops — **spine contract unchanged** (Inv 1).

### 3.2 `RiskEngine` (Fork 2)
`src/risk/engine.py` — pure function:

```
RiskVerdict = evaluate(action: FinancialAction, limits: TenantLimits) -> (ok, violations[])
```

Deterministic checks (v2 seeds ~6, extensible): max order notional, max position
size, max daily loss, max portfolio exposure, concentration limit, velocity.
Limits sourced from `TenantLimits` (env + per-tenant). Runs AFTER decide();
can only set `AUTO→BLOCKED`.

### 3.3 `OperatorAuthority` + `ApprovalRecord` (Fork 3)
`src/security/operator.py` — operator owns an Ed25519 key (env-provided or
generated at boot for v2; single operator). HUMAN verdicts require:

```
ApprovalRecord{ action_hash, operator_id, decision: approve|reject|modify,
                approved_action_hash, sig }
```

Live signer rejects if `approved_action_hash != action_hash` (closes the
"approve-one-execute-another" gap). Reject/modify re-enter the pipeline.

### 3.4 Replay & isolation registry (Fork 7, folded into P0)
`src/security/replay.py` — `ActionRegistry` keyed `(tenant_id, action_id)`:

- same `action_hash` already SIGNED → idempotent, BLOCK replay
- different `action_hash` with same `nonce` → BLOCK
- `expiry < now` → BLOCK
- replayed signature → BLOCK
- `tenant_id` mismatch on lookup → BLOCK (cross-tenant confusion, Attack 16)

### 3.5 Pipeline rewire
`src/service/app.py` — `execute_live` (and a new `authorize_action`) run the
ordered pipeline above. Each stage appends a signed ledger event.

### 3.6 Adversarial scenario harness
`tests/scenarios/` — machine-readable evidence artifacts per attack:

```
01 unauthorized transfer       07 nonce collision
02 AUTO + excessive notional    08 venue wrong destination
03 replay identical request     09 settlement amount differs
04 modify payload post-auth     10 circuit breaker mid-exec
05 approval/action hash mismatch11 ledger corruption
06 expired authorization        12 compromised model
13 compromised operator        14 stale market price
15 rapid burst                  16 cross-tenant confusion
```

All run on the simulated path. Each asserts the correct BLOCK/403/verify-fail.

---

## 4. P1 — state, reconciliation, evidence

### 4.1 Economic state machine (Fork 4)
Extend ledger entries (NOT replace the chain) with `event_type`, `state`,
`action_id`, `prev_event_hash`, `causal_refs[]`. Add `StateMachine.validate`
(legal transitions + failure branches: REJECTED/EXPIRED/CANCELLED/FAILED/
REVERSED/DISPUTED). Mirror `verify_chain` unchanged (sig + chain integrity) so
**Inv 3 holds**. `reconstruct_trace(action_id)` returns the causal chain.

### 4.2 Venue adapter + reconciliation (Fork 5)
`src/venue/adapter.py` — `VenueAdapter` ABC + `SimulatedVenue` that can be
*adversarially perturbed* (wrong destination, partial fill, nonce mismatch,
missing tx). `ReconciliationEngine.diff(internal, venue)` emits reconciliation
events. Default = simulated; no live RPC required. Directly powers Attacks 08/09.

---

## 5. P2 — demonstrability & depth
- `console/app/trace/page.tsx` — **Authorization Trace** view (proposal →
  epistemic → policy → risk → settlement → signature → settlement → verified).
- Portfolio/position engine (`src/finance/positions.py`) enabling real
  exposure/collateral checks.
- Additional venue adapters.

---

## 6. Forks — ALL RATIFIED (implemented as Fork A defaults)

| # | Fork | Ratified (A) |
|---|---|---|
| 1 | Core schema | layer `FinancialAction` under `RathnoneFinanceProposal` — spine contract preserved |
| 2 | Risk placement | orthogonal narrowing-only engine AFTER decide — Inv 1 preserved |
| 3 | Human approval | operator key + signed `ApprovalRecord` (hash binding + sig verify) |
| 4 | Ledger | extend entries with state/causal fields, keep `verify_chain` — Inv 3 preserved |
| 5 | Reconciliation | sim venue + engine shipped |
| 6 | Isolation | `ActionRegistry` keyed `(tenant_id, action_id)` — cross-tenant blocked |
| 7 | Sequencing | big-bang P0+P1 (user Fork 7B) — all layers shipped cohesive |

---

## 7. Verification plan (REAL, executed)
- `pytest` → **85 passed**: 53 v1 + 16 adversarial scenarios + live-track suite +
  real-venue unit tests (`test_real_l2_venue.py`) + real-venue **gateway e2e**
  (`test_real_venue_e2e.py`) which drives a live tenant through
  `POST /tenants/{id}/authorize_action` with a fake JSON-RPC transport and
  independently recovers the on-chain signer of the broadcasted EIP-155 tx
  (no private key) — proving the real venue signs with the tenant's own key.
- Host smoke: `POST /tenants` (live=true) → `POST /tenants/{id}/authorize_action`
  → AUTO verdict, real secp256k1 sig committed, `live_sign` ledger event
  persisted, `verify_locally()` returns True.
- `console/` `npm run build` → clean (4 static routes), audit view surfaces
  `live_sign` signatures (settlement address + intent hash + r‖s‖v).
- `verify_locally()` still green (Inv 3 unchanged).
- Docker amd64 smoke pending external push (see commit step).

# ADR 17 — P0 Security Remediation: Single Authorization Path + Static API-Key Auth

**Status:** RATIFIED (2026-08-20). Implementation follows.

**Trigger:** External source audit of `main` confirmed multiple security-boundary failures
around the authorization API surface. The core v2 `authorize_action` pipeline is sound; the
older API surfaces sit beside it and undermine its guarantees. This ADR collapses the API to
one authoritative path and adds a fail-closed control-plane auth layer.

**Scope (ratified, P0 only):**
- Collapse to a single authorization path.
- Add static-API-key auth to operator/control-plane endpoints.
- Out of scope this phase (deferred to P1/P2): durability store for replay/ledger, velocity
  real-clock fix, integer/Decimal quantities, Next.js upgrade, dep pins, recursive PII,
  adversarial integration tests.

---

## 1. Problem statement

The audit confirmed (verified against source, not asserted):

| # | Finding | Where | Confirmed |
|---|---|---|---|
| 1 | `/safety/halt` + `/safety/resume` unauthenticated | `app.py:139-152` | yes |
| 2 | `/execute` trusts caller-supplied `verdict=AUTO` | `app.py:197-221` | yes (mitigated today by `simulated=True` default) |
| 3 | `/execute_live` authorizes the thin tuple `(producer, request_id, capability, action_descriptor)` but signs a *separate* `body.payload` with no cryptographic binding | `app.py:270-309` | yes |
| 6 | `POST /tenants` unauthenticated, including `live=true` (mints real settlement key) | `app.py:117-124` | yes |
| 7 | Tenant reads unauthenticated: `/tenants`, `/audit`, `/meter`, `/reconciliation`, `/evidence` | `app.py:127,420,428,434,405` | yes |

**Root cause behind #2 and #3:** two alternate execution authorities exist beside the v2
pipeline. The v2 pipeline itself is correct — its signer layer
(`pipeline.py:259-272`) signs over the *full* `action.action_hash` via
`SettlementAuthRecord.build_for_action` / `OrderAuthRecord.build_for_action`, which is the
same hash `decide()` authorized. So "fold live signing into `authorize_action`" is already
done; the fix is to **delete the bypass twins**, not to re-plumb signing.

---

## 2. Decision: one path, one auth gate

### 2.1 Single authorization path

- **`POST /tenants/{id}/authorize_action` is the ONLY path that can reach a signer.**
  It consumes a `FinancialAction`, hashes it canonically, runs the frozen spine, risk,
  hygiene, HUMAN-bound-approval, replay, breaker, signer, venue, reconcile, evidence — in order.
- **`/execute` is DELETED.** It accepted caller `verdict` and bypassed `decide()`.
- **`/execute_live` is DELETED.** It authorized a thin tuple and signed a separate,
  unbound `payload`. Its legitimate capability (produce a real signature over an authorized
  action) already lives in the pipeline's signer layer and triggers when the tenant has a
  `settlement_key` and the action is AUTO (or HUMAN+bound-approval).
- `POST /tenants/{id}/authorize` (v1 advisory) is **kept** as a read-only decision
  endpoint. It appends an authorization-ledger event but does NOT execute or sign. This is
  safe: the v1 proposal translator drops economic detail before `decide()`, and the endpoint
  has no signing path. It remains a useful "what would decide say?" surface.

### 2.2 Static API-key auth (F-A, ratified: simplest, fail-closed)

A single env-loaded shared secret gates every control-plane and operator endpoint.

- Env: `RATHNONE_API_KEY` (required in production; if unset, the service refuses to start in
  "enforce" mode — see §3).
- Header: `Authorization: Bearer <key>` (or `X-API-Key: <key>`).
- Endpoints gated (all are privileged control-plane ops):
  - `POST /tenants` (provisioning, incl. `live=true`)
  - `POST /safety/halt`, `POST /safety/resume` (operator breaker)
  - `GET /tenants`, `GET /tenants/{id}/audit`, `GET /tenants/{id}/meter`,
    `GET /tenants/{id}/reconciliation`, `GET /tenants/{id}/evidence/{action_id}`
- **NOT gated** (by design): `POST /tenants/{id}/authorize` (advisory, no side effects) and
  `POST /tenants/{id}/authorize_action` (the authorization itself is the product; the action
  is tenant-scoped and the crypto binds the tenant, not the caller). Tenant-id possession is
  not authorization, but these endpoints cannot move funds or trip the breaker — the dangerous
  verbs are the ones that are gated. *Note for P1: tenant reads should later be scoped to an
  authenticated principal; deferred per scope.*
- Fail-closed: missing/invalid key → `401`. Constant-time compare (`hmac.compare_digest`).
  No key in logs.

### 2.3 Why not signed-operator-command for `/safety`?

Ratified choice is static API key for the whole P0. Signed-operator-command (Ed25519 over
`(command, timestamp, nonce, reason)`) is the stronger option and is the recommended P1
upgrade for `/safety` specifically (it gives genuine non-repudiation + replay-resistant
resume). Deferred per the P0-only scope the user selected. The API-key gate is explicitly
designed so `/safety` can later be upgraded to a signed-command requirement without changing
the other gated endpoints.

---

## 3. Implementation notes

- New module `src/service/auth.py`: `require_api_key(request: Request)` dependency + startup
  assertion that `RATHNONE_API_KEY` is set when `RATHNONE_ENFORCE_AUTH != "0"`.
- Delete `def execute(...)` and `def execute_live(...)` + the `_ExecuteLiveIn` model.
- Remove now-dead imports: `execute_trade_execute`, `execute_treasury_rebalance`,
  `execute_chain_settle`, `ExecutionRefused`, `action_from_intent`, `action_from_order`,
  `assert_no_pii`/`validate_*` (those move into the pipeline only), `load_operator_public_key`
  (unused after delete). Keep imports the pipeline still needs.
- Apply `Depends(require_api_key)` to the gated endpoints.
- Console: remove `executeLive` from `console/lib/api.ts`.
- Tests: rewrite `tests/test_service.py` `/execute` calls, `tests/test_live.py`,
  `tests/test_safety.py`, `tests/test_security.py` to drive `authorize_action` instead of
  `/execute_live`. Add a new `tests/test_p0_security.py` proving:
  - unauthenticated `POST /tenants` → 401
  - unauthenticated `POST /safety/halt` → 401
  - authenticated provisioning + breaker works
  - `authorize_action` still produces a real signature for a live tenant (binding intact)
  - a tampered `FinancialAction` yields a different `action_hash` (already implicit in signing)

---

## 4. Invariants preserved

- Inv 1 (ModelOutput != Authorization): unchanged. `decide()` is still the sole epistemic surface.
- Inv 2 (narrowing-only): unchanged.
- Inv 3 (key-free verify): unchanged; `verify_locally()` still works.
- Frozen spine: zero changes.
- Live signing remains opt-in (`settlement_key` present) and fail-closed.

## 5. Verification gate

- `pytest -q` → all green (no regression from deleted endpoints; new P0 tests pass).
- `console` `npm run build` → clean.
- Manual: `RATHNONE_API_KEY=x pytest tests/test_p0_security.py -q` → green;
  a `curl` without the header to `/safety/halt` returns 401.

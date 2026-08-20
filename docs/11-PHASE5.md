# 11 — Phase 5: Product Console + Tenant Isolation + Metering (B8, B9, F4)

Phase 5 exit gate (from `06-ROADMAP.md`): **a tenant can authorize the finance
trio, see the immutable audit trail, and meter usage.**

## Design decisions (ratified defaults, no new forks)

- **Tenant isolation (B8):** each tenant owns a *distinct* `GovernanceAuthority`
  Ed25519 key. Authorization, the signed ledger, and the key-free mirror are all
  **scoped per tenant**. A tenant can never produce a record that verifies under
  another tenant's public key — isolation is enforced by the signature, not by a
  guard flag.
- **Authority placement (F3):** the gateway holds each tenant's signing key
  (local-first). The console + cloud mirror hold only the tenant's *public* key
  and recompute verification (Invariant 3 — key-free).
- **Metering (B9):** **per-AUM** model. Each authorized (AUTO) action records the
  tenant's reported AUM at that moment; billable exposure = Σ(AUM per authorized
  action) × `AUM_FEE_RATE`. Deterministic, auditable, no network.
- **No new substrate behavior:** the service calls the *same frozen*
  `fleet.epistemic.decide()` through `GatewayContext`. The finance trio travels
  through unchanged `AuthorizationRequest` shapes.

## Deliverables

- `src/service/tenant.py` — `Tenant` + `TenantRegistry`: per-tenant key, scope,
  ledger head (GENESIS), AUM, signed-record append, key-free verify.
- `src/service/metering.py` — `MeteringLedger`: per-AUM accrual (deterministic).
- `src/service/app.py` — FastAPI surface:
  - `POST /tenants` → mint a tenant (returns public key + id)
  - `POST /tenants/{id}/authorize` → run `decide()`, record + meter on AUTO
  - `POST /tenants/{id}/authorize_action` → full v2 pipeline (sign + opt-in live)
  - `GET  /tenants/{id}/audit` → signed ledger + `verify_chain` result
  - `GET  /tenants/{id}/meter` → per-AUM usage summary
- `console/` — Next.js (App Router) product console: tenant list, authorize
  console, forensic audit view, meter view. Talks to the gateway over HTTP.
- `tests/test_service.py` — real endpoint tests via `fastapi.testclient`.

## Hard constraints preserved

- `decide()` receives zero epistemic input (Invariant 1).
- Unknown capability → HUMAN (escalation), never silent AUTO.
- BLOCKED / HUMAN-without-approval → adapter refuses; no ledger signature.
- Verification recomputed with PUBLIC key only (Invariant 3, F3).

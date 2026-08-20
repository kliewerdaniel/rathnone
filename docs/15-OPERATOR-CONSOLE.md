# Rathnone v2 — Operator Console

**Status:** IMPLEMENTED & VERIFIED. Console builds clean as six static routes; every
surface is backed by a real `src.service.app` endpoint exercised by the pytest suite
(75 passed). Not a simulation — the console talks to the same FastAPI app the
adversarial suite attacks.

This doc is the operator-facing counterpart to `14-V2-CONTROL-PLANE.md`. The control
plane is the *authority*; the console is the *observability + operator override* layer.
It surfaces exactly what the frozen spine and the narrowing layers produced, and gives
the operator one independent lever the model cannot pull: the V4 circuit breaker.

---

## 1. Map: console surface → backend

| Console route | Backend endpoint(s) | What it shows / does |
|---------------|---------------------|----------------------|
| `/` Tenants | `POST /tenants`, `GET /tenants` | Mint a tenant (optionally `live=True` → issues a real secp256k1 settlement key + returns `settlement_address`), list tenants. |
| `/authorize` | `POST /tenants/{id}/authorize_action` | Submit a `FinancialAction`; shows the frozen verdict (AUTO/HUMAN/BLOCKED), live-signature (r‖s‖v) + signer address when AUTO, and the opt-in live settlement panel. |
| `/audit` | `GET /tenants/{id}/audit`, `GET /tenants/{id}/meter` | Immutable ledger: `v2_pipeline` + `live_sign` events (action hash, intent hash, signature, settlement addr). Per-AUM meter. Drill-in links to Trace and Reconcile. |
| `/trace` | `GET /tenants/{id}/evidence/{action_id}` | Vertical timeline of the 11 control-plane layers with state badges, key-free chain-integrity check, and transition-violation reporting. |
| `/reconcile` | `GET /tenants/{id}/reconciliation` | **Cross-action** aggregate: `all_matched` flag, per-code breakdown, divergence table. (See §3.) |
| `/safety` | `GET /safety`, `POST /safety/halt`, `POST /safety/resume` | V4 operator circuit breaker: live `breaker_open` state, Trip/Clear. Independent of the frozen spine. |

All reads are `GET`s against the tenant-scoped ledger. The only state-changing console
actions are: minting a tenant, submitting an action (which runs the read-only
authorization pipeline), and the operator **Trip/Clear** of the breaker.

---

## 2. The verification principle the console honors

Every console surface is **read-only over durable facts**. It never recomputes or
re-queries anything the control plane did not already durably commit:

- `/audit` renders the appended ledger entries verbatim (signature included).
- `/trace` runs `verify_chain()` / `verify_locally()` — key-free checks (Invariant 3)
  that re-validate the causal hash chain without any private key.
- `/reconcile` aggregates the `reconciliation` code the pipeline already persisted on
  each `v2_pipeline` ledger event. It does **not** re-query the venue.

This means what the operator sees is exactly what an external auditor could reconstruct
from the ledger — the console is a view, not an authority.

---

## 3. Cross-action reconciliation (`/reconcile`)

Per-action reconciliation lives inside the pipeline (`ReconciliationEngine.diff` over a
`SimulatedVenue`). The console aggregates it so one operator can see, across an entire
tenant, *did every authorized action settle as authorized?*

`summarize_reconciliation(records)` (src/venue/adapter.py) — single source of truth:

- filters to `event == "v2_pipeline"` records that carry a `reconciliation` code;
- counts `total_actions`, `matched` (code == `MATCH`);
- lists every non-`MATCH` as a `divergence` (action_id, capability, code, detail,
  venue_state);
- emits `per_code` counts and `all_matched` (true only if total>0 and matches==total).

**Fail-closed:** an unrecognized reconciliation code is reported as a divergence rather
than dropped, and the function never invents venue state. This is covered by
`tests/test_reconciliation_view.py`.

The divergence table is the operator's primary "something went wrong at the venue" signal
— distinct from the epistemic verdict (which governs *whether* to sign) and from the
breaker (which governs *whether signing is enabled at all*).

---

## 4. V4 circuit breaker — the operator's one independent lever

The frozen `fleet.epistemic.decide()` is, by design, **immutable** — the operator cannot
flip an AUTO to a BLOCKED. That immutability is the "cage." The V4 breaker is the
deliberate antidote: a separate, operator-controlled switch that halts **live signing**
regardless of any model verdict.

- `POST /safety/halt` → `breaker_open = true`, `live_signing_enabled = false`.
- `POST /safety/resume` → re-opens.
- While open: `authorize_action` and `execute_live` return **503** before any signing.

The `/safety` page exposes this with a 2-second auto-refresh and an explicit note that it
is independent of the epistemic spine. This is the "kill switch" an operator reaches for
during an incident without touching model code. (`tests/test_safety.py` proves the full
CLOSED→OPEN→503→reopen cycle.)

---

## 5. Navigator orientation

```
Tenants ──mint──▶ Authorize ──submit──▶ Trace (per-action 11-layer proof)
                       │
                       ├─▶ Audit (immutable ledger: v2_pipeline + live_sign)
                       │        ├─▶ Trace (one action)
                       │        └─▶ Reconcile (all actions)
                       └─▶ Safety (V4 breaker: independent halt)
```

From a `live_sign` row in Audit you can jump to that action's Trace *or* the tenant's
cross-action Reconcile. From Reconcile you see whether the aggregate settled as
authorized. Safety is always one tab away.

---

## 6. Verification record

- `cd ~/Projects/rathnone/console && npm run build` → clean, 6 static routes
  (`/`, `/authorize`, `/audit`, `/trace`, `/reconcile`, `/safety`).
- `cd ~/Projects/rathnone && .venv/bin/python -m pytest -q` → **75 passed**
  (53 v1 + 16 adversarial + safety + trace + reconciliation-view).
- Real `TestClient` E2E confirms: live tenant → `authorize_action` → AUTO + real
  secp256k1 signature persisted to ledger (`live_sign`) → `verify_locally() == True` →
  `/reconciliation` → `all_matched: true`; breaker trip → 503 before signing.

**Not yet committed:** this doc (docs are written before commit per the repo's
docs-first discipline, but the console + endpoint code it describes shipped in
`93710e3`).

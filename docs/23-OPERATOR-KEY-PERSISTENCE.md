# ADR 23 — Durable Operator-Key Persistence (crash-survivable keyring)

**Status:** RATIFIED (2026-08-20) + IMPLEMENTED.

**Series context:** ADR 17→22 built the operator-authority system: a signed-command
gate (ADR 19/20) over a per-key lifecycle keyring (ADR 21) that can be mutated at
runtime via a double-gated management surface (ADR 22). But the keyring lived in
**process memory**. A restart wiped every operator key added / rotated / revoked at
runtime, silently reverting the live-money signing authority to whatever
`configure_safety_operators` bootstrapped at startup — a reliability AND security
gap (an operator's deliberate revocation could vanish on a crash or redeploy).

This ADR makes the keyring **durable**: a SQLite-backed store so the authority
survives a restart and is consistent across worker processes.

---

## 1. Decision

Add `src/security/keystore.py` with `DurableOperatorKeyStore` — a SQLite-backed
store keyed by `(scope, key_id)` where `scope` is `"safety"` for the service-global
safety keyring and the tenant id for per-tenant settlement authority. Every key
entry (key_id, operator_id, role, added_at, expires_at, revoked, pem) is persisted
as a row; revocation/expiry are flags on the row, never a deletion, so the
historical authority is preserved (Inv 3 key-free ledger replay depends on the
binding still existing).

The store mirrors the project's existing `DurableActionRegistry` pattern:
- Unset `RATHNONE_KEY_DB` ⇒ **in-memory only** (the ADR 17-22 default behavior is
  unchanged, and the test suite stays hermetic on `:memory:` semantics).
- Set `RATHNONE_KEY_DB=<file>` ⇒ file-backed SQLite, hydrated on first use and
  written through on every mutation.

The store is resolved **lazily at call time** (like the ADR 17 auth env reads), so
a deployment can enable durability without re-importing the app, and the test
suite can toggle it per-session.

## 2. Write-through, not flush-later (the important part)

Every mutation through the ADR 22 surface (`POST /operator-keys`, `/revoke`,
`/rotate`) and `configure_safety_operators` **writes through** to the store
immediately. There is no background flush and no batching — a successful HTTP
response means the change is durable. The store connection is opened on first use
and reused (singleton), so the write path is cheap.

Hydration is **lazy and guarded**:
- `_SAFETY_TENANT` hydrates from the store on first use after import.
- A tenant's keyring hydrates from the store on first access via `_get_tenant`.
- A `_keys_hydrated` flag prevents re-hydration from clobbering an in-memory keyring
  that a test or local flow built but has not yet persisted (fail-closed: we never
  silently throw away an authoritative in-memory state). After any mutation writes
  through, the flag is reset so a *subsequent* read re-hydrates from the store
  (the now-authoritative truth) rather than the stale in-memory copy.

## 3. Invariants preserved

- **Inv 1** (frozen spine untouched): no change to `fleet.epistemic.decide()`.
- **Inv 3** (key-free ledger replay): unchanged; historical keys are retained.
- **Fail-closed:**
  - Unset `RATHNONE_KEY_DB` ⇒ fully in-memory, behavior identical to ADR 17-22.
  - A store read/write failure RAISES rather than silently degrading to memory
    (a control plane that *looks* authorized but isn't — or vice-versa — is worse
    than a hard fail).
  - Unknown tenant scope on a read ⇒ 404 (not a 500), consistent with the rest of
    the surface.
- **Console-compatibility:** unchanged — the console never holds signing keys and
  the durability layer is transparent to it.

## 4. Implementation notes (implemented)

- `src/security/keystore.py` — `DurableOperatorKeyStore` (`load_scope`,
  `save_entry`, `revoke_key`, `revoke_pem`, `persist_ring` in a transaction) +
  `from_env()`.
- `src/service/app.py` — lazy `_key_store_singleton()`; `_hydrate_safety_keys()`;
  `_get_tenant` hydration; `_store_scope` write-through used by all four ADR 22
  endpoints + `configure_safety_operators`; `_SAFETY_TENANT._keys_hydrated` flag.
- `src/service/tenant.py` — `Tenant._keys_hydrated` field.
- `tests/test_operator_key_persistence.py` (6 tests) — add/revoke/rotate each
  survive a *fresh store over the same file* (simulated restart); tenant key
  persists and re-hydrates on a fresh tenant fetch; unknown tenant ⇒ 404; unset
  env ⇒ no store.
- `.env.example` — documented `RATHNONE_KEY_DB`.

## 5. Verification gate (met)

- `pytest -q` → **165 passed** (was 159; +6 ADR 23), no regressions.
- `console npm run build` + `tsc -p tsconfig.json --noEmit` → clean (no console
  changes required).

---

**Ratified and implemented (2026-08-20, "proceed").** Keyring now survives
restart; the ADR 17→23 operator-authority stack is complete, durable, double-gated,
fail-closed, and console-compatible.

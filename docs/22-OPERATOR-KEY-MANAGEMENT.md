# ADR 22 — Operator-Key Lifecycle Management Surface (Runtime, No Redeploy)

**Status:** RATIFIED (2026-08-20) + IMPLEMENTED (commit pending).

**Series context:** the operator-authority architecture hardened in ADR 17→21.
- **ADR 19/20** introduced the *signed operator command* as the authorization
  primitive for safety verbs (halt/resume) and the fund-moving `authorize_action`
  verb, verified against the tenant's (or safety scope's) operator allowlist.
- **ADR 21** replaced the bare `list[str]` of PEMs with an `OperatorKeyRing`
  carrying `operator_id`, `expires_at`, and `revoked` per key, so individual
  keys could be revoked/expired without a redeploy *of the data model* — but the
  only way to actually mutate the keyring at runtime was `configure_safety_operators(...)`
  at startup. Changing operators still meant a process restart with new PEMs.

This ADR closes that gap: a runtime, authenticated management surface for
provisioning / rotating / revoking / listing operator keys — for both the
service-global safety scope and per-tenant settlement authority — with **no
redeploy**.

---

## 1. Decision

Add four endpoints to the control plane (`src/service/app.py`):

- `GET  /operator-keys?scope=safety|tenant&tenant_id=`
- `POST /operator-keys?scope=...&tenant_id=` — body `{public_key_pem, operator_id?, role?, expires_at?}`
- `POST /operator-keys/revoke?scope=...&tenant_id=` — body `{key_id}` (sha256(pem)[:16] handle, or the full PEM)
- `POST /operator-keys/rotate?scope=...&tenant_id=` — body `{new_public_key_pem, old_public_key_pem?, operator_id?, expires_at?, expire_old_in_s?}`

`scope="safety"` targets `_SAFETY_TENANT.operator_keys` (the global safety
verb authority). `scope="tenant"` targets a specific tenant's
`t.operator_keys` (settlement authority). The body shapes map directly onto the
ADR 21 `OperatorKeyRing` API (`add` / `revoke` / `rotate`), which now returns
the new entry so the caller learns its `key_id`.

## 2. Crown-jewel gating (the important part)

These endpoints change **WHO can move live money and trip the circuit breaker**,
so a single shared control-plane key (ADR 17 `RATHNONE_API_KEY`, which also gates
routine tenant provisioning) is **not sufficient**. Each endpoint requires **two
factors**, both enforced fail-closed:

1. `require_api_key` (ADR 17) — `Authorization: Bearer <RATHNONE_API_KEY>`.
2. `require_key_ops_key` (ADR 22, **new**) — a **distinct** `RATHNONE_KEY_OPS`
   secret, presented via `X-Key-Ops` (or `Authorization-KeyOps`).

`require_key_ops_key` (in `src/service/auth.py`):
- Reads env at **call time** (consistent with the ADR 17 design that lets a test
  session toggle both modes without re-importing the app).
- In enforce mode, **401 if `RATHNONE_KEY_OPS` is unset** (fail-closed — never a
  silent pass) or if the presented value doesn't match constant-time.
- Comparison is constant-time (`hmac.compare_digest`); the secret is never logged.

Rationale for the second factor: the key-management surface is the highest-value
target in the control plane. If the shared `RATHNONE_API_KEY` were the only gate,
an operator whose console/CI token leaks would instantly gain the ability to
provision themselves (or an attacker) as a live-money signing authority. A
separate, ops-only secret limits that blast radius; the two factors should live
in different trust domains (e.g. deploy secret vs. rotation tooling).

## 3. Invariants preserved

- **Inv 1** (frozen spine untouched): no change to `fleet.epistemic.decide()`.
- **Inv 3** (key-free ledger replay): unchanged.
- **Fail-closed:**
  - Missing/incorrect either factor ⇒ 401.
  - `scope` not in `{safety, tenant}` ⇒ 400; `scope=tenant` without `tenant_id` ⇒ 400.
  - Revoking an unknown `key_id` ⇒ 404 (no silent success).
- **Console-compatibility:** the console never holds signing keys, so it never
  calls these routes; they are out-of-band ops-tooling territory. Tenants created
  via the ordinary `POST /tenants` (ADR 17 key only) remain on the static-key
  path until an operator is *out-of-band* provisioned via this surface.
- **Revoke-last-key ⇒ dormant, not bypass:** revoking the final active key of a
  scope reverts it to the ADR 17 static-key path (verified by `layer_active=False`
  in the test). The same fail-closed semantics ADR 21 established hold.

## 4. Rotation (unchanged graceful semantics)

`rotate` keeps the ADR 21 grace window: if `expire_old_in_s > 0`, the old key is
given a short `expires_at` so in-flight commands signed under it keep working
during cutover; otherwise the old key is revoked immediately. The new key is
trusted the instant the call returns.

## 5. Implementation notes (implemented)

- `src/service/auth.py` — new `require_key_ops_key` dependency + exported.
- `src/service/app.py` — import `require_key_ops_key`; models `_OpKeyAdd`,
  `_OpKeyRevoke`, `_OpKeyRotate`; helpers `_scope_for` (fail-closed scope
  resolver) and `_key_summary`; the four endpoints, each double-gated.
- `src/security/operator.py` — `OperatorKeyRing.rotate()` now returns the new
  `OperatorKeyEntry` (callers learn `key_id`); both existing keyring tests were
  already discarding the return value, so this is API-compatible.
- `tests/test_operator_key_management.py` (+7) — two-factor gating (each factor
  alone 401, both 200); wrong key-ops secret 401; add→active→listed; revoke by
  id→layer dormant; revoke unknown→404; rotate grace window keeps old key active;
  tenant-scoped add + bad-scope/tenant_id validation.
- `.env.example` — added `RATHNONE_KEY_OPS` knob with fail-closed semantics noted.

## 6. Verification gate (met)

- `pytest -q` → **159 passed** (was 152; +7 ADR 22), no regressions.
- `console npm run build` + `tsc -p tsconfig.json --noEmit` → clean (no console
  changes required; the management surface is ops-only).

---

**Ratified and implemented (2026-08-20, "proceed").** Backend + tests landed;
console unaffected. Committed and pushed on `origin/main`.

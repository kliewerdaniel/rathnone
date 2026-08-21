# ADR 21 — Operator Key Lifecycle (Provision / Rotate / Revoke / Expire)

**Status:** RATIFIED (2026-08-20) + IMPLEMENTED (commit pending).

**Series context:** the operator-authority architecture has hardened in four steps —
- **ADR 17** — static shared API key (`RATHNONE_API_KEY`) as the sole transport gate.
- **ADR 18** — signed operator *downgrade* of hygiene-BLOCKED actions (2-of-2 for
  `DESTINATION_OWNERSHIP`), verified against the tenant operator allowlist.
- **ADR 19** — signed operator *commands* (`OperatorCommand`) for safety verbs
  (halt/resume): attributed, replay-guarded, body-bound, timestamp-expiry-checked.
- **ADR 20** — extended the signed-command gate to `authorize_action` (the
  fund-moving verb) for operator-gated tenants.

ADR 19/20 implemented operator authority as a **bare `list[str]` of PEM public
keys**. That worked for the gate, but it left three lifecycle gaps:

1. **No single-key revocation without a redeploy.** To kill one compromised key
   you had to re-provision the entire list out-of-band.
2. **No graceful rotation.** Swapping keys meant a window where old in-flight
   commands were rejected or the new key wasn't yet trusted.
3. **No expiry.** A lost key stayed authorized forever.

This ADR replaces the bare list with a first-class, metadata-bearing keyring so
each authorized operator key has an `operator_id`, an optional `expires_at`, and
a `revoked` flag, and the signed-command gate verifies against **active** keys
(authorized = present, not revoked, not expired).

---

## 1. Decision

Introduce `OperatorKeyEntry` and `OperatorKeyRing` (in `src/security/operator.py`).

- A `Tenant` no longer holds `operator_allowlist: list[str]`; it holds
  `operator_keys: OperatorKeyRing` (default empty).
- The service-global safety scope (`_SAFETY_TENANT`) likewise holds a keyring,
  populated by `configure_safety_operators([pem, ...])`, which now builds entries.
- `_require_command` (ADR 19/20 gate) computes the allowlist as
  `tenant.operator_keys.active_pems()` — i.e. only keys that are **not revoked
  and not expired**. The downgrade pipeline (`validate_downgrade`) likewise
  receives `tenant.operator_keys.active_pems()`.
- The keyring exposes:
  - `add(pem, operator_id=, role=, expires_at=)` — provision a key.
  - `revoke(key_id_or_pem)` — immediate kill-switch (sets `revoked=True`).
    Returns `True` if found. Entries are retained (not deleted) so the audit
    trail preserves historical authority.
  - `rotate(new_pem, old_pem=, expire_old_in_s=)` — add a new key and retire the
    old one; if `expire_old_in_s > 0` the old key gets a short expiry *grace
    window* (so in-flight commands signed under it keep working during cutover),
    otherwise it is revoked immediately.
  - `active_pems(now_epoch_s=)` — public keys currently authorized.
  - `is_authorized(pem, ...)`, `lookup(pem)`, `revoked/is_expired` helpers.
- `key_id` is `sha256(pem)[:16]` so a single key can be revoked by id without
  transmitting the full PEM.

## 2. Invariants preserved

- **Inv 1** (frozen spine untouched): no change to `fleet.epistemic.decide()`.
- **Inv 3** (key-free ledger replay): `record_command` still records the operator
  pubkey PEM; the ledger verifies with the tenant's governance key, never the
  operator key.
- **Fail-closed, console-compatible:**
  - Empty keyring ⇒ no active keys ⇒ the signed-command layer is **dormant** and
    the ADR 17 static-key path remains the sole gate (identical behavior to
    "no allowlist configured" in ADR 19).
  - Revoking the *last* active key reverts the scope to the static-key path — it
    is **not** an auth bypass. A plain (un-authenticated-for-command) request then
    succeeds on the shared key exactly as before.
  - A request that *does* arrive with a command header is verified against the
    active set only; a command signed by a revoked/expired key is refused (401).
- **Narrowing intact (ADR 18):** downgrades verify against active keys only; a
  revoked operator key no longer authorizes a hygiene release.

## 3. Rotation, not silent replacement

`rotate()` with a grace window is the supported cutover: the old key keeps
signing authority until `expires_at`, the new key is trusted immediately, and the
gate honors both during the window. This avoids the ADR 19/20 "all-or-nothing
re-provision" that forced a choice between rejected in-flight commands and an
untrusted new key.

## 4. Out-of-band provisioning (unchanged custody design)

Keys are still provisioned **out-of-band** (deploy tooling / operator signing
tool), never through the console, which cannot hold signing keys. `scripts/
operator_sign.py` (ADR 20) continues to sign commands with the operator's
Ed25519 key; ADR 21 adds the server-side ability to retire/rotate that key
without a code redeploy.

## 5. Implementation notes (implemented)

- `src/security/operator.py`: added `OperatorKeyEntry` (dataclass with
  `key_id`, `operator_id`, `role`, `added_at`, `expires_at`, `revoked`) and
  `OperatorKeyRing` (`add` / `revoke` / `rotate` / `active_pems` / `is_authorized`
  / `lookup`). `verify_command` signature unchanged (still takes a PEM list — the
  caller now passes `active_pems()`).
- `src/service/tenant.py`: `operator_allowlist: list[str]` →
  `operator_keys: OperatorKeyRing` (default factory). Import added.
- `src/service/app.py`: `_SAFETY_TENANT` holds a keyring (initialized after
  class def to avoid a forward type ref); `configure_safety_operators` builds
  `OperatorKeyRing.from_pems(pems)`. `_require_command` reads
  `tenant.operator_keys.active_pems()` (with a harmless `getattr` fallback for
  any legacy holder). `operator_gated` getters now report
  `bool(t.operator_keys.active_pems())`.
- `src/service/pipeline.py`: downgrade validation passes
  `tenant.operator_keys.active_pems()`.
- `tests/test_operator_command.py`, `tests/test_operator_authorize_signing.py`,
  `tests/test_hygiene_downgrade.py`: updated to set `tenant.operator_keys` /
  `_SAFETY_TENANT.operator_keys` via the keyring API (no behavior change to the
  assertions).
- `tests/test_operator_keyring.py` (+11): add-then-active; revoke by key_id and
  by PEM; revoke-missing returns False; expiry drops the key; unexpired stays;
  rotate grace window keeps old key then retires it; rotate immediate-revoke;
  empty ring not active; revoking the last key reverts the layer to dormant
  (static-key path); command signed by a revoked key refused while the layer is
  in force.

## 6. Verification gate (met)

- `pytest -q` → **152 passed** (was 141; +11 ADR 21), no regressions.
- `console npm run build` + `tsc -p tsconfig.json --noEmit` → clean.
- Manual reasoning (covered by tests):
  - With one active safety key, an un-commanded `POST /safety/halt` → 401; after
    `revoke(key_id)` the same plain halt → 200 (layer dormant, not bypassed).
  - With two keys where one is revoked and one active, a command signed by the
    revoked key → 401 (not in the active set).

---

**Ratified and implemented (2026-08-20, "proceed").** Backend + tests landed;
console unaffected. Committed and pushed on `origin/main`.

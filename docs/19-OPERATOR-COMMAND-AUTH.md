# ADR 19 — Signed Operator Commands (Ed25519) for Safety-Critical Verbs

**Status:** RATIFIED (2026-08-20) + IMPLEMENTED (commit pending).

**Trigger (the real tension):** ADR 17 introduced a *static shared* API key
(`RATHNONE_API_KEY`) as the sole transport authorization for every mutating verb
(`/tenants` provision, `/safety/halt`, `/safety/resume`, `/authorize_action`,
`/audit` reads). ADR 17 §2.3 explicitly recommended upgrading to **Ed25519-signed
operator commands**, and ADR 18 §3 adopted that upgrade "for the downgrade verb
specifically." ADR 18 delivered the operator signature *on the payload*
(`DowngradeRecord`), but the *transport* gate for every verb is still the shared
static key.

The shared static key has three structural weaknesses for fund-moving / safety verbs:
1. **No attribution.** Any holder of the key is indistinguishable from any other; there is
   no record of *which operator* issued a `halt` or `resume`. The signed ledger records the
   *effect*, not the *author*.
2. **No replay resistance.** The bearer token is constant; a captured request can be replayed
   verbatim.
3. **No command binding.** The token authorizes *the connection*, not *the specific command +
   tenant + nonce*. A leaked token grants unbounded authority with no scoping.

ADR 18 already proved the pattern works: a per-operator Ed25519 key on a tenant
`operator_allowlist`, signing over a canonical tuple, verified key-free from the ledger.
ADR 19 generalizes that pattern to the safety-critical verbs so authority is *attributed,
replay-guarded, and command-bound* — without new crypto.

**Scope (implemented):**
- A unified `OperatorCommand` envelope (verb, tenant_id, body_hash, nonce, timestamp,
  operator_id, pubkey_pem, sig) signed by an operator Ed25519 key, verified against the
  tenant/global operator allowlist.
- Applied to the **safety verbs** `halt` and `resume` (the genuine security gap: an
  unauthenticated or shared-key-only circuit-breaker trip). The command is delivered in an
  `X-Operator-Command` header (base64 of the JSON `OperatorCommand`) so it wraps any request
  body shape.
- A **global operator allowlist** (`app.configure_safety_operators([pem, ...])`) backs the
  safety verbs, since `halt`/`resume` are service-global, not tenant-scoped. Per-tenant
  allowlists back the existing ADR 18 downgrade path.
- **Console compatibility preserved:** the console deliberately never holds a signing key
  (stated custody design in `console/lib/api.ts`). Therefore the signed-command layer is
  **dormant until operators are provisioned**: when no allowlist is configured, safety verbs
  stay on the ADR 17 static-key path (exactly as before). This is fail-closed and
  console-compatible — nothing silently authorizes, and the console keeps working until ops
  provisions operator keys out-of-band.
- **Deliberately out of scope for this ADR:** forcing a signed command on
  `POST /authorize_action` (live settlement). The console is the primary live-settlement
  caller and cannot hold a signing key, so mandating a signed command there would break live
  settlement for any tenant with operators configured. The downgrade path (ADR 18) already
  carries its own signed `DowngradeRecord`; live settlement itself is gated by the frozen
  spine + circuit breaker + settlement ceiling. If operator-signed live commands are wanted
  later, they belong in a follow-up with an ops-side signing tool, not the console.

---

## 1. Decision 1 — authorization becomes a signed operator command, not a shared token

Ratify: for safety-critical verbs, the *authorization* primitive is an `OperatorCommand`
signed by an operator key on the operator allowlist:

```
OperatorCommand = {
  verb: str,                 # "halt" | "resume"
  tenant_id: str,
  body_hash: str,            # sha256 of the canonical request body
  nonce: int,                # replay-guarded
  timestamp: int,            # ns-resolution acceptance window (±60s)
  operator_id: str,
  pubkey_pem: str,           # operator Ed25519 pubkey (allowlisted)
  sig: str,                  # Ed25519 over canonical_bytes()
}
```

- Gateway verifies: `pubkey_pem ∈ allowlist`, `sig` valid over the canonical tuple,
  `nonce` unseen (replay guard), `timestamp` within window, `body_hash` matches the request
  body. Fail-closed on any failure.
- The command binds to the *specific* request body via `body_hash` — a captured command cannot
  be reused against a different action (structurally prevents "halt A, replay as halt B").
- **Attribution:** the operator pubkey + id are recorded in the safety audit trail for every
  such verb, so `/audit`-style inspection shows *who* halted/resumed — closing the attribution
  gap ADR 17 left open.

---

## 2. Decision 2 — the static API key degrades to transport defense-in-depth

- Retain `RATHNONE_ENFORCE_AUTH` + `RATHNONE_API_KEY` (ADR 17) as a coarse transport gate: a
  request without the bearer token is still rejected at the edge. But possession of the token
  is no longer *sufficient* for safety verbs **once an operator allowlist is configured**.
- This is a hardening, not a relaxation: the token stops casual/unauthenticated access; the
  operator signature proves *which authorized operator* issued *which specific command*. Two
  independent gates.
- Read-only endpoints (`/audit`, `/meter`, `/reconciliation`, `/evidence`) remain
  static-key-gated only (no fund-moving consequence).

---

## 3. Decision 3 — reuse, don't reinvent (no new crypto)

- `OperatorCommand` reuses the exact Ed25519 verify path ADR 18 built in
  `src/hygiene/downgrade.py` (`canonical_bytes()` + `verify(primary_pem)`). The downgrade
  `DowngradeRecord` is a sibling of `OperatorCommand` (both sign over a canonical tuple and
  verify against an allowlist).
- `tenant.operator_allowlist` (ADR 18) is the single source of authorized operator keys for
  the downgrade path; a new **global** allowlist (`_SAFETY_TENANT.operator_allowlist`)
  backs the service-global safety verbs.
- Replay guard reuses the per-scope used-nonce set (ADR 18 `_used_command_nonces`,
  generalized from `_used_downgrade_nonces`).
- Ledger append reuses the signed-ledger machinery (Inv 3 preserved: key-free replay).

---

## 4. Fork decision — which verbs require a signature

**Ratified:** signed `OperatorCommand` required for `halt` and `resume` **when an operator
allowlist is configured**. Read verbs (`/audit`, `/meter`, `/reconciliation`, `/evidence`)
stay static-key-only. 2-of-2 is **not** required for halt/resume (single operator sufficient;
the consequence is a safety stop, not a fund move) — `downgrade` keeps its ADR 18 2-of-2 rule
for `DESTINATION_OWNERSHIP`. `authorize_action` is intentionally **not** gated by this ADR
(see Scope, console-compatibility rationale).

---

## 5. Invariants preserved

- **Fail-closed:** unconfigured allowlist → signed-command layer dormant (static key still
  gates); once configured, missing/bad/forge/sig/replayed/old command → refused.
- **No new crypto:** Ed25519, reused from ADR 18.
- **Inv 1:** spine untouched; signing is transport/pipeline authorization only.
- **Inv 3:** every command replayable key-free from the audit trail (pubkey recorded).
- **Narrowing:** no verdict is widened; authorization is orthogonal to the spine verdict.

## 6. Implementation notes (implemented)

- `src/security/operator.py`: `OperatorCommand` dataclass + `verify_command(...)` + `body_hash_of(...)`.
  Reuses the existing Ed25519 path; fail-closed on missing allowlist / body mismatch / replay /
  expired timestamp / bad sig.
- `src/service/tenant.py`: `_used_command_nonces` (generalized from `_used_downgrade_nonces`);
  `record_command(...)` appends an attributed `operator_command` ledger event (Inv 3).
- `src/service/app.py`: `_SAFETY_TENANT` + `configure_safety_operators(...)` (global allowlist
  for service-global safety verbs); `_require_command(request, verb, body, tenant)` gate reads
  the `X-Operator-Command` header, verifies, records, and replays the nonce. `halt`/`resume`
  require a signed command when their allowlist is configured. `authorize_action` is unchanged
  (downgrade carries its own signed record per ADR 18).
- `tests/test_operator_command.py`: 7 cases — no-allowlist stays static-key-compatible;
  halt-without-command refused; valid command attributed; replayed nonce refused; wrong-body
  binding refused; bad sig refused; unit-level `verify_command` fail-closed.

## 7. Verification gate (met)

- `pytest -q` → 136 passed (no regressions from 129; +7 ADR 19).
- `console npm run build` → clean (no console changes required; custody design preserved).
- Manual: with `configure_safety_operators([pem])` set, a `halt` lacking the
  `X-Operator-Command` header is 401; a valid signed command trips the breaker and is recorded
  in `_safety_audit` with the operator pubkey; replaying the nonce is 401.

---

**Ratified and implemented (2026-08-20, "proceed").** Backend + tests landed; console
unchanged (key-custody preserved). Committed and pushed on `origin/main`.

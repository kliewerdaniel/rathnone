# ADR 20 — Signed Operator Commands for `authorize_action` (Live Settlement Transport)

**Status:** RATIFIED (2026-08-20) + IMPLEMENTED (commit pending).

**Series context:** the control-plane auth architecture has been hardened in three steps —
- **ADR 17** — static shared API key (`RATHNONE_API_KEY`) as the sole transport gate for every
  route (coarse, no attribution / replay / command-binding).
- **ADR 18** — signed *payload* (`DowngradeRecord`, operator Ed25519) releasing a hygiene-BLOCKED
  action; and the tenant `operator_allowlist` as the source of authorized operator pubkeys.
- **ADR 19** — signed *transport* `OperatorCommand` for the safety verbs `halt`/`resume`, gated by
  a **global** operator allowlist, **dormant until provisioned** (console-compatible).

ADR 19 §5 explicitly deferred `authorize_action`: the console is the primary live-settlement
caller and cannot hold a signing key, so mandating a signed transport command there would break
live settlement for any tenant with operators configured. ADR 20 closes that deferred gap — but
**only for tenants that have an operator allowlist configured**, and via an **ops-side signing
tool**, not the console.

**The remaining gap (precise):** `POST /tenants/{tid}/authorize_action` — the live-settlement
verb that can move real funds — is today authorized *only* by the static API key. For a tenant
that has `operator_allowlist` set (i.e. the operator has already opted into signed authority for
downgrades), the live-settlement *transport* is still bearer-token-only: anyone holding the
shared key can drive that tenant's settlement with no attribution, no replay resistance, and no
command binding. The signed `approval`/`downgrade` *payloads* cover the *intent*, but not *who
issued the settlement request* nor that the request wasn't replayed.

---

## 1. Decision 1 — a signed `OperatorCommand` binds the live-settlement transport

Ratify: for a tenant whose `operator_allowlist` is configured, `authorize_action` requires a
signed `OperatorCommand` (the exact envelope ADR 19 defined) with `verb="authorize"`:

```
OperatorCommand = {
  verb: "authorize",
  tenant_id: str,                       # the {tid} in the path
  body_hash: str,                       # sha256 of the canonical authorize_action body
  nonce: int,                           # replay-guarded per tenant
  timestamp: int,                       # ns acceptance window (±60s)
  operator_id: str,
  pubkey_pem: str,                      # must be ∈ tenant.operator_allowlist
  sig: str,                             # Ed25519 over canonical_bytes()
}
```

- Verified against the **tenant's own** `operator_allowlist` (per-tenant authority; the same
  allowlist ADR 18 uses for downgrades). This is intentionally *tenant-scoped*, not the ADR 19
  global safety allowlist — settlement authority is a property of the tenant, not the service.
- `body_hash` binds to the **full canonical `authorize_action` body** (`action` + `approval` +
  `downgrade` + `require_human_approval` + `denylist`), so a captured command cannot be replayed
  against a different action, approval, or downgrade (structurally prevents
  "approve-benign / execute-poisoned" and "settle-A / replay-as-settle-B").
- Fail-closed: missing command / bad sig / replayed nonce / expired timestamp / wrong body_hash /
  operator not on the allowlist → refused (401/403).

**Dormant-until-provisioned (same pattern as ADR 19):** when `tenant.operator_allowlist` is empty,
the signed-command layer is NOT in force and `authorize_action` stays on the ADR 17 static-key
path (console keeps working for non-operator-gated tenants). The gate activates *only* once a
tenant opts into operator authority.

---

## 2. Decision 2 — the console cannot drive an operator-gated tenant (fail-closed)

The console deliberately never holds a signing key (stated custody design in
`console/lib/api.ts`, unchanged since ADR 19). Therefore:

- For a tenant **without** an operator allowlist → console live settlement works exactly as today
  (static key only). No change.
- For a tenant **with** an operator allowlist → `authorize_action` from the console (no
  `X-Operator-Command` header) is **refused**. This is the intended posture: operator-gated
  tenants require **ops-side signing tooling**, not the UI. The console may still *display* the
  tenant, but its live-settlement button must be **disabled / labeled "requires operator signing
  tool"** when the tenant has operators configured.
- This is consistent with ADR 19: authority that requires a key the console doesn't hold is
  simply not available from the console. Nothing silently authorizes.

**Ops-side signing tool (proposed, not built):** a small CLI/script
(`scripts/operator_sign.py`) that loads an operator Ed25519 key (from an operator-provided,
out-of-band, file-permission-gated path — never the console, never chat) and emits the
`X-Operator-Command` header for a given `authorize_action` request. The gateway verifies exactly
as ADR 19's `_require_command` does; only the verifier is reused and the *tenant* allowlist is
consulted instead of the global one.

---

## 3. No new crypto, invariants preserved

- Reuses `OperatorCommand` + `verify_command` + `body_hash_of` from ADR 19 verbatim (no new code
  beyond wiring the `authorize` verb through `_require_command`).
- `tenant._used_command_nonces` (the ADR 19 generalized set) provides replay guard per tenant.
- Ledger: the attributed `operator_command` event (ADR 19 `record_command`) is appended for the
  settlement verb too — Inv 3 (key-free replay) holds; the operator pubkey is recorded so the
  settlement is attributable end-to-end (spine verdict + operator who released it + operator who
  transported it).
- **Inv 1** — spine untouched; signing is transport/pipeline authorization only.
- **Fail-closed** — unconfigured allowlist → dormant; configured → missing/forged/replayed/old →
  refused.
- **Narrowing** — no verdict widened; authorization orthogonal to the spine verdict.

---

## 4. Fork decision — 2-of-2 on settlement transport?

**Recommended default: single operator** for the `authorize` transport command (consistent with
ADR 19 halt/resume; a 2-of-2 requirement would make every settlement depend on two signers and
is disproportionate for a *transport* gate). The stronger 2-of-2 control already exists at the
*payload* layer (ADR 18) for `DESTINATION_OWNERSHIP` downgrades — i.e. the *intent* to release
the strongest anti-theft check needs two operators, while the *transport* of a normally-authorized
settlement needs one. The two layers compose: a settlement that also downgrades a destination
violation requires 1 transport sig + 2 downgrade sigs. Carry to ratify.

---

## 5. Scope (this ADR only)

- Transport-command gate on `authorize_action`, tenant-scoped, dormant until the tenant's
  `operator_allowlist` is configured.
- Ops-side signing tool (`scripts/operator_sign.py`) to emit the header off-console.
- Console: disable/label the live-settle button for operator-gated tenants (no signing in UI).

**Out of scope:** the frozen spine; the ADR 18 `approval`/`downgrade` payload signing (already
shipped, reused as-is); read verbs (static-key-only); the ADR 19 global safety-verb allowlist
(unchanged). No relaxation of any fail-closed invariant.

---

## 6. Proposed implementation (NOT built — review first)

1. `src/service/app.py`: extend `_require_command` to accept the `authorize` verb and consult
   `tenant.operator_allowlist` (per-tenant) instead of the global safety allowlist. Apply it to
   `authorize_action` when `tenant.operator_allowlist` is non-empty.
2. `src/service/tenant.py`: reuse `_used_command_nonces` for per-tenant replay guard (already
   generalized in ADR 19).
3. `scripts/operator_sign.py` (new): load operator Ed25519 key from an out-of-band path, POST
   `authorize_action` with the `X-Operator-Command` header; never embedded in the console.
4. `console/app/authorize/page.tsx`: when the active tenant has `operator_allowlist`, disable the
   live-settle control and surface a "requires operator signing tool" notice.
5. `tests/test_operator_command.py` (extend): operator-gated tenant refuses console-style
   (no-header) `authorize_action`; valid signed command settles and is attributed; replayed
   nonce refused; wrong-body binding refused; non-gated tenant still static-key-only.

## 7. Verification gate (to be met before "done")

- `pytest -q` → green, including new authorize-command tests (no regressions).
- `console npm run build` → clean.
- Manual: with a tenant `operator_allowlist` set, an `authorize_action` lacking the
  `X-Operator-Command` header is 401; a valid signed command settles and the `operator_command`
  event is in the audit trail with the operator pubkey; replaying the nonce is refused.

---

**This ADR pauses here for review.** On ratify, implementation proceeds: extend `_require_command`
(authorize verb, tenant allowlist) → ops signing tool → console disable → tests. No code lands
until you say proceed.

---

## 8. Implementation notes (implemented)

- `src/service/app.py`: `authorize_action` now takes `request: Request` and calls
  `_require_command(verb="authorize", tenant_id, body=_canonical_body, tenant=t)` right after
  resolving the tenant. The body hash binds the full canonical `_AuthorizeActionIn`
  (`json.dumps(body.model_dump(), sort_keys=True, separators=(",",":"))`). The existing
  `_require_command` already consults `tenant.operator_allowlist` / `_used_command_nonces` /
  `record_command` generically — so the `authorize` verb reuses the exact ADR 19 machinery with
  **per-tenant** authority (not the global safety allowlist).
- `src/service/app.py`: `createTenant` response now includes `operator_gated`; added a read-only
  `GET /tenants/{tenant_id}` info route (auth-gated) exposing non-secret metadata including
  `operator_gated`, so the console can detect operator-gated tenants.
- `scripts/operator_sign.py` (new): ops-side signing tool. Loads an operator Ed25519 key from an
  out-of-band path, canonicalizes the authorize body identically to the gateway, signs an
  `OperatorCommand(verb="authorize")`, and POSTs with the `X-Operator-Command` header. Never
  embedded in the console; key never enters the UI/chat. Supports `--approval` / `--downgrade`
  JSON passthrough (pre-built, operator-issued) to bind the full request.
- `console/lib/api.ts` + `console/app/authorize/page.tsx`: added `api.tenantInfo`; the live-
  settlement button is **disabled** (with a "requires operator signing tool" notice) when the
  active tenant is operator-gated. No signing in the UI — custody design preserved.
- `tests/test_operator_authorize_signing.py` (+5): operator-gated tenant refuses no-header
  `authorize_action` (401); valid signed command settles + is attributed in the audit trail;
  replayed nonce refused; wrong-body binding refused; non-gated tenant still static-key-only.

## 9. Verification gate (met)

- `pytest -q` → 141 passed (was 136; +5 ADR 20), no regressions.
- `console npm run build` + `tsc -p tsconfig.json --noEmit` → clean.
- Manual: with a tenant `operator_allowlist` set, an `authorize_action` lacking the
  `X-Operator-Command` header is 401; a valid signed command (via `scripts/operator_sign.py`)
  settles and records an `operator_command` event with the operator pubkey; replaying the nonce
  is 401.

---

**Ratified and implemented (2026-08-20, "proceed").** Backend + console + ops tool + tests
landed. Committed and pushed on `origin/main`.

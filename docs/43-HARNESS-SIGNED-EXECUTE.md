# ADR 43 — Harness `execute` requires a SIGNED operator command

**Status:** RATIFIED + IMPLEMENTED (2026-08-21)
**Author:** Rathnone control
**Supersedes:** ADR 41 §8 open question #2 (the "HUMAN verdict path" fork)
**Builds on:** ADR 41 (harness as a `decide()` consumer), ADR 42 (explore/execute split),
ADR 19 / 20 / 21 (signed operator commands, command gate, operator keyring)

---

## 1. Context

ADR 42 closed the capability-granularity fork by splitting the harness into
`explore` (read-only, AUTO/silent) and `execute` (consequential, HUMAN-by-default).
But ADR 41 §8 question #2 — *what does HUMAN mean?* — was left open, and ADR 42
shipped the **soft** answer: `execute` returned BLOCKED with a "HUMAN required"
reason, and the harness could re-request with `pre_approved=True` to flip the
verdict to ALLOW.

That `pre_approved` path is a **local acknowledgement flag**, not a cryptographic
one. It has exactly the failure mode ADR 19 was written to close for the finance
gateway: a privileged-but-compromised harness flow could set `pre_approved=True`
and approve an `execute` action the operator never actually reviewed. The
hygiene/audit value of HUMAN collapses to "the harness says it asked the human."

The frozen spine already has the right primitive. `src/security/operator.py`
ships `OperatorCommand` + `verify_command` + `OperatorKeyRing` (ADR 19/20/21): a
signed, replay-guarded, body-bound operator command, verified against an
allowlist of operator keys with nonces and an acceptance window. The finance
gateway uses it for `halt`/`resume`/`authorize` via `app._require_command`. ADR 43
reuses that exact primitive for the harness `execute` surface. **No new crypto,
no new spine behavior, no new key model.**

---

## 2. Decision

**`execute` is hard-blocked until a valid `OperatorCommand` (verb=`harness_apply`)
is presented, signed by an allowlisted operator key, bound to the exact
request body, with an unused nonce and a fresh timestamp.**

Resolution order for `POST /harness/authorize` (each step fails closed):

1. **reachability** — control plane reachable? (client side / 401 on missing key)
2. **ADR 17 key** — `RATHNONE_API_KEY` present? (static transport defense)
3. **capability / kind**
   - `explore` → `CAP_FIN_AGENT_HARNESS_EXPLORE` → AUTO → **ALLOW silently**
     (no operator command required; read-only research needs no signature).
   - `apply` → `CAP_FIN_AGENT_HARNESS_EXECUTE` → HUMAN-by-default.
4. **operator command (apply only; only when an allowlist is configured)** —
   if the harness scope has any active operator key, the request MUST carry a
   signed `OperatorCommand(verb="harness_apply", ...)` in the
   `X-Operator-Command` header, verified by `verify_command` against the harness
   scope's `active_pems()`.
     - missing command → **401** "operator-signed command required"
     - bad sig / wrong scope / replay nonce / stale timestamp / body-hash
       mismatch → **401** "operator command refused: <why>"
5. **decide()** — AUTO → ALLOW; HUMAN (no allowlist configured) → BLOCKED
   "HUMAN required"; BLOCKED → BLOCKED.
6. **operator halt** — `/safety` breaker open ⇒ BLOCKED regardless.

**Dormant posture (fail-closed default).** When the harness scope has **no**
active operator keys, the signed-command layer is *not in force* and `apply`
falls back to the ADR 42 HUMAN → BLOCKED behavior ("HUMAN required: operator
allowlist not provisioned"). This mirrors the finance `authorize` verb's dormant
posture (ADR 20): a deployment that has not yet provisioned operator keys is not
silently allowed to `execute` — it is blocked with an explicit reason — but it is
also not broken by the mere absence of a key. Provisioning operators
out-of-band via `app.configure_harness_operators([pem, ...])` activates the
signed-command requirement.

This resolves Q2 as **"hard BLOCK until a signed operator command arrives"** —
the stronger of the two recommended options — because (a) the primitive already
exists and is proven in the finance path, (b) it makes approval cryptographically
attributable and replay-safe rather than a local boolean, and (c) it is the
honest end-state for "the operator must actually approve a consequential
harness action."

---

## 3. Design

### 3.1 The harness operator scope (reuses ADR 19/21)

`src/service/app.py` gains a service-global `_HARNESS_SCOPE` (an
`OperatorKeyRing`) parallel to the existing `_SAFETY_TENANT` safety scope. It is
empty by default (dormant). `configure_harness_operators([pem, ...])` provisions
it out-of-band (never via the console, which cannot hold signing keys — same
custody rule as ADR 20).

### 3.2 Endpoint change (`/harness/authorize`)

- `kind="explore"`: unchanged — AUTO, ALLOW, no operator command.
- `kind="apply"`: after the static-key gate, call the **existing**
  `_require_command("harness_apply", _HARNESS_SCOPE_SCOPE_ID, body_bytes,
  _HARNESS_SCOPE)` helper. It already:
  - reads the `X-Operator-Command` header,
  - deserializes it to `OperatorCommand`,
  - calls `verify_command(...)` against the scope's `active_pems()`,
  - records the command in the audit trail + marks the nonce used.
  It raises `401` on any refusal. Because it's the same helper the finance
  gateway uses, the harness execute path inherits all of ADR 19/20/21's
  guarantees: scope-binding (`tenant_id` must equal the harness scope id),
  body-hash binding, nonce replay protection, timestamp acceptance window.

  The canonical body bytes the command binds to = `json.dumps(body,
  sort_keys=True, separators=(",",":")).encode()` — the exact `dict` the harness
  posted. The signing operator tool MUST canonicalize identically.

- The `pre_approved` body field is **removed**. ADR 42's "explore silent /
  apply HUMAN-by-default" is preserved; the only way to convert an `apply`
  to ALLOW is a valid signed operator command (or, while dormant, it stays
  BLOCKED with "HUMAN required").

### 3.3 Gate function (`harness_auth.evaluate_harness_action`)

The unit-level `evaluate_harness_action` no longer takes `pre_approved`. For
`apply` it accepts an `operator_command: Optional[OperatorCommand]` plus
`operator_allowlist: list[str]`, `used_nonces: set[int]`, `now: int`. It verifies
the command via `verify_command` exactly as the endpoint does (so the unit suite
and the live endpoint share one verification path). `explore` ignores the
command (AUTO). This keeps the unit tests honest: they can present a correctly
signed command and assert ALLOW, or a missing/invalid/replayed one and assert
BLOCKED.

### 3.4 Client (`HarnessAuthorizer.may_apply`)

`may_apply(action, *, kind="apply", operator_command=None)`:
- `explore` → POST without an operator command → ALLOW on AUTO.
- `apply` → if the harness has provisioned operators, the caller must pass a
  signed `OperatorCommand`; the client serializes it to the
  `X-Operator-Command` base64 header. `may_apply` refuses (False) if `apply` is
  requested without a command when one is required. A helper
  `sign_harness_command(action, key, *, scope_id, nonce, timestamp,
  operator_id)` builds the `OperatorCommand` the same way `scripts/harness_sign.py`
  does, so the consumer and the operator tool agree on canonicalization.

### 3.5 Operator signing tool (`scripts/harness_sign.py`)

A mirror of `scripts/operator_sign.py` for the `harness_apply` verb: loads an
operator Ed25519 key from a file-permission-gated path (never the console, never
chat), binds to the exact `/harness/authorize` body json, emits the
`X-Operator-Command` header value (base64 of the `OperatorCommand` json). This is
the out-of-band operator counterpart the ADR 19/20 design requires: the human
reviews the action, signs it with a key the harness never holds, and the harness
presents that signature.

---

## 4. Fail-closed guarantees (unchanged + added)

- **No new spine behavior.** `evaluate_harness_action` still calls
  `decide_registered` through the SAME registry the finance trio uses. Invariant 1
  honored.
- **Signed command required for apply (when provisioned).** Missing / malformed /
  bad-sig / replayed / body-mismatched / stale command ⇒ 401, never ALLOW.
- **Scope-binding.** `OperatorCommand.tenant_id` must equal the harness scope id,
  so a command minted for one scope cannot satisfy another (ADR 19 F2).
- **Body-binding.** `body_hash` ties the command to the exact `/harness/authorize`
  POST body, so "approve one apply, execute another" is structurally impossible
  (parallels ADR 19 ApprovalRecord `binds_to`).
- **Replay-guarded.** Nonce is consumed once; reuse ⇒ 401.
- **Attributable.** The operator pubkey + id + nonce are recorded in the audit
  trail (reusing `_require_command`'s `record_command`).
- **Dormant = blocked-with-reason, not open.** No allowlist ⇒ apply stays BLOCKED
  ("HUMAN required", not "ALLOW"). Run-open never happens.
- **Operator halt still overrides everything.** Breaker open ⇒ BLOCKED for apply
  regardless of a valid signed command.

---

## 5. What ADR 43 does NOT do

- It does **not** require a signed command for `explore` (read-only, AUTO). That
  stays silent and key-less by design.
- It does **not** invent a new signature scheme, timestamp domain, or nonce store.
  It reuses `OperatorCommand`/`verify_command`/the `_require_command` helper and
  the finance gateway's `Clock(epoch_ns=True)` — identical machinery.
- It does **not** change the frozen `fleet.epistemic.decide()`, the registry, or
  the `explore`/`execute` capability split from ADR 42.

---

## 6. Test strategy

- `tests/test_harness_gate.py`:
  - `explore` AUTO → ALLOW (unchanged).
  - `apply` with a **correctly signed** command over a provisioned allowlist →
    ALLOW (verdict reason records the operator id).
  - `apply` **missing** command while allowlist configured → BLOCKED/DENY shape.
  - `apply` **bad signature** → BLOCKED.
  - `apply` **replayed nonce** → BLOCKED.
  - `apply` **body-hash mismatch** (command signed over a different body) →
    BLOCKED.
  - `apply` **dormant** (no allowlist) → BLOCKED "HUMAN required".
- `tests/test_harness_gate_live_tcp.py`: boot the real gateway (uvicorn + httpx);
  provision harness operators; assert over the wire that (a) `apply` without a
  command = 401, (b) `apply` with a valid signed command = 200 ALLOW, (c) `apply`
  with a replayed command = 401, (d) a live `/safety/halt` still overrides a
  signed-command apply to BLOCKED.
- `tests/test_harness_client_live_tcp.py`: drive `HarnessAuthorizer.may_apply`
  against the live endpoint with a real signed `OperatorCommand` (built by
  `sign_harness_command`) — prove the consumer glue + operator-tool path agrees
  on canonicalization end-to-end.
- `examples/harness_loop.py` (NEW): the **living consumer** — a real harness loop
  that imports `HarnessAuthorizer` and polls `/harness/authorize` before every
  consequential action (explore → silent AUTO, apply → requires a signed command
  bound to the exact action). It boots the real gateway over TCP and drives the
  full plan including the live `/safety/halt` panic button. Run with
  `examples/harness_loop.py`; set `RATHNONE_HARNESS_NO_OPERATOR_KEY=1` to see the
  fail-closed posture (no apply ever allowed).
- `tests/test_harness_loop_live_tcp.py` (NEW): boots the real gateway and drives
  `HarnessLoop` against it — proves the gate is exercised by an *actual loop*, not
  just isolated gate tests. Asserts explore ALLOW, apply-signed ALLOW, replayed
  nonce refused, live `/safety/halt` stops the loop, and fail-closed-without-key.

---

## 7. Exit criteria (definition of "done")

- Harness operator scope (`OperatorKeyRing`) + `configure_harness_operators`
  added; dormant by default (no active keys ⇒ apply stays blocked-with-reason).
- `POST /harness/authorize` requires a signed `OperatorCommand(verb="harness_apply")`
  for `apply` when operators are provisioned, via the existing `_require_command`
  helper. `explore` unchanged (silent AUTO).
- `harness_auth.evaluate_harness_action` verifies the command via `verify_command`;
  no `pre_approved` soft-ack path remains.
- `HarnessAuthorizer.may_apply` forwards `X-Operator-Command`; `sign_harness_command`
  + `scripts/harness_sign.py` let the operator sign out-of-band.
- Full suite green; docs/41 §8 Q2 → RESOLVED by ADR 43; 00-INDEX + README updated.

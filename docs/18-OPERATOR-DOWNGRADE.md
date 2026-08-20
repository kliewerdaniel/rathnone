# ADR 18 — Operator Downgrade Path for Hygiene-BLOCKED Actions

**Status:** DRAFT (2026-08-20). For review. Implementation does NOT begin until ratified.

**Trigger (the real tension):** v3 (ADR 16, forks F5–F9) ratified *narrowing-only*
severity — `AUTO → BLOCKED` allowed, `BLOCKED → AUTO` / `HUMAN → AUTO` forbidden
(`src/hygiene/__init__.py:12`, `HygieneVerdict` docstring). The frozen `BLOCKED`
verdict exists *because the claim could not be independently corroborated* — i.e. the
system's knowledge of the action is **incomplete**, not necessarily wrong.

Two needs now collide:
1. **False-positive pressure:** a dead oracle feed, a transient feed lag, or a legitimately
   new-but-real instrument can trip `BLOCKED` on an action that is in fact safe. With
   always-BLOCKED (F9) and no escape, operators work around the gate out-of-band (manual
   ledger edits, shadow execution) — which destroys the very audit trail the gate exists to
   protect.
2. **Human sovereignty:** the product's thesis is "trust the execution protocol, not the
   model" — but a *signed human operator* is a first-class authority already (HUMAN-bound
   approval in v2). A hygiene `BLOCKED` is a knowledge gap, not a spine rejection; refusing a
   competent operator any override path is over-correction.

The tension is genuine and architectural, so it belongs in an ADR, not a code change.

**Scope (this ADR only):**
- Define a single, auditable, fail-closed **operator downgrade path** for hygiene-BLOCKED
  actions that preserves Inv 3 (key-free verify) and narrows, never widens, the *spine*
  verdict.
- Decide whether the deviation band (F8=50 bps) and quorum (F7=N=2) become **adaptive** vs
  remain fixed-config. (See §4 — the band/quorum question is a *separate fork*; this ADR
  takes the conservative default and defers adaptation.)
- **Out of scope:** changing the frozen spine (zero changes, M0 proof intact), relaxing
  Inv 1 (corroboration never reaches `decide()`), or auto-widening `BLOCKED → AUTO`
  without a human signature.

---

## 1. Decision 1 — the downgrade is a *signed human override*, not an automatic widening

Ratify: hygiene `BLOCKED` may transition to `HUMAN` (human-review-required) **only** via an
explicit, signed operator action — `operator_downgrade_blocked(hygiene_violations, reason)`.

- It reuses the **existing** `OperatorAuthority` / `ApprovalRecord` signing machinery from
  v2 (`docs/14-V2-CONTROL-PLANE.md`) — no new crypto. The operator signs over
  `(action_hash, violation_ids, reason, timestamp, nonce)` with their **operator key**
  (Ed25519, the same key ADR 17 §2.3 recommends upgrading `/safety` to).
- The downgraded action re-enters the pipeline at the `HUMAN` band. It does **not** skip
  risk, replay, breaker, settlement, signer, venue. It only removes the hygiene `BLOCKED`.
- **Narrowing invariant preserved:** the spine verdict is untouched (it was `AUTO` or
  `HUMAN`; hygiene can only narrow `AUTO → BLOCKED`). Downgrade moves `BLOCKED → HUMAN`,
  which is *wider than BLOCKED but equal-or-narrower than the spine's own verdict* — so the
  layer never contradicts `decide()`. This is the precise reason F9 said "always BLOCKED":
  the layer must not self-widen; an external signed human is the only sanctioned widener,
  and that human is already part of the protocol.

### 1.1 Why not auto-adapt the band instead?
Auto-widening the band on low confidence would make the gate silently weaker under exactly
the conditions (feed instability) where it should be *stronger*. That defeats the purpose.
The escape hatch is a *signed human*, recorded forever, not a silent parameter drift.

---

## 2. Decision 2 — every downgrade is immutably audited (Inv 3 preserved)

- A `DowngradeRecord` is appended to the **signed ledger** and the `EvidenceGraph`
  (`src/evidence/chain.py`), exactly like existing `live_sign` / settlement events:
  - `action_hash`, `violation_ids` (which hygiene checks were overridden),
  - `operator_pubkey`, `signature`, `reason`, `observed_at`, `nonce`.
- `verify_locally()` (key-free) replays the record: proves the override was signed by a
  key on the tenant's operator-allowlist, and that the `action_hash` matches the action it
  released. No secret needed to audit — Inv 3 intact.
- Console `/authorize` surfaces `downgraded: true` + `violation_ids` + `operator` so the
  reason is never invisible.

---

## 3. Decision 3 — fail-closed gating of the downgrade itself

- The downgrade endpoint requires **operator auth** (extends ADR 17's static API-key gate;
  the recommended P1 upgrade is Ed25519-signed operator command per ADR 17 §2.3 — this ADR
  adopts that upgrade *for the downgrade verb specifically* because it carries fund-moving
  consequence).
- If the operator key is unconfigured / the signature fails / the action was spine-`BLOCKED`
  (not hygiene-`BLOCKED`) → downgrade refused. **A spine `BLOCKED` can never be downgraded**
  (that would contradict `decide()`). The downgrade path applies *only* to hygiene-narrowed
  `AUTO/Human → BLOCKED`.
- Replay protection: the `nonce` is checked against the durable `ActionRegistry`
  (`DurableActionRegistry`, P1/P2 hardening) — no double-release.

---

## 4. Fork decision — band/quorum adaptation

**Ratified: bands and quorum stay FIXED-CONFIG for now (F8=50 bps, F7=N=2).** Adaptation is
a separate, larger fork (confidence-estimation on feed liveness, per-tenant risk-context
band sizing) and is explicitly **deferred**. This ADR does not open it. The downgrade path
is the safety valve *instead of* auto-adaptation, which is the more conservative ordering.

> Open question for review: should the downgrade require a *second* operator (2-of-2) for
> `DESTINATION_OWNERSHIP` overrides specifically (the strongest anti-theft check, F6)?
> Recommended: yes for F6 overrides, single-operator for the rest. Flagged, not decided.

---

## 5. Invariants preserved

- **Inv 1:** corroboration still never reaches `decide()`. Downgrade is a pipeline-only
  human override, post-spine. Frozen spine: zero changes.
- **Inv 2 (narrowing):** the spine verdict is never widened by the layer; the only widener
  is an external signed human acting within the existing HUMAN authority.
- **Inv 3 (key-free verify):** `DowngradeRecord` is replayable from the ledger without any
  secret.
- **Fail-closed:** missing key / bad sig / spine-BLOCKED / replayed nonce → refused.

## 6. Proposed implementation notes (NOT yet built — review first)

- `src/hygiene/__init__.py`: add `DowngradeRecord` dataclass; `CorroborationLayer` gains
  `downgrade(action_hash, violation_ids, operator_sig, reason, nonce)` that validates the
  signature against the tenant operator-allowlist and emits a `HygieneVerdict(ok=True,
  verdict="HUMAN", downgraded=True, ...)`.
- `src/service/pipeline.py`: when an action arrives already hygiene-`BLOCKED` with a valid
  attached `DowngradeRecord`, it skips the hygiene narrowing and proceeds to `HUMAN`.
- `src/service/app.py`: new `POST /tenants/{id}/authorize_action/downgrade` (or extend
  `authorize_action` with an optional signed `downgrade` body) — gated by the signed
  operator-command auth from ADR 17 §2.3.
- `console/lib/api.ts` + `console/app/authorize`: surface downgrade UI (reason field,
  operator key sign) — **only after the endpoint exists**.
- Tests (`tests/test_hygiene_downgrade.py`): spine-BLOCKED cannot be downgraded; valid signed
  downgrade re-enters at HUMAN and settles; bad sig / replayed nonce refused; `DowngradeRecord`
  verifies key-free via `verify_locally()`.

## 7. Verification gate (to be met before "done")

- `pytest -q` → all green, including new downgrade tests (no regressions in the 122 existing).
- `console npm run build` → clean.
- Manual: a hygiene-BLOCKED action with a forged/no signature is refused (401/403); with a
  valid operator signature it downgrades and the `DowngradeRecord` is present in `/audit`
  and replays via `verify_locally()`.

---

**This ADR pauses here for review.** On ratify, implementation proceeds in dependency order:
`DowngradeRecord` + signature validation → pipeline skip → endpoint + signed-operator auth →
console surface → tests. No code lands until you say proceed.

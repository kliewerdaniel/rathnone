# Rathnone v3 — Epistemic Hygiene Layer

**Status: IMPLEMENTED & VERIFIED — v3 epistemic-hygiene layer shipped. 98 pytest green
(85 prior + 13 hygiene: 11 unit + 2 pipeline-level). Opt-in via RATHNONE_HYGIENE_ENABLED
(default off, so the v1/v2 suites are unaffected). Not yet committed (standing discipline:
review before push).**

This document addresses the *one* open research seam named in `docs/09-OPEN-QUESTIONS.md`
(line 5): **knowledge poisoning**. A perfectly-governed system can still do the wrong thing
if its *knowledge* is wrong. This is the documented v3 frontier.

---

## 1. The precise poisoning seam (grounded in the real code, not prose)

The frozen `fleet.epistemic.decide()` is, by construction, **blind to economic content**.
What it actually receives (see `src/gateway/__init__.py:66` `GatewayContext.authorize` →
`decide(...)`):

```
identity, grant, authorization_scope,
request = AuthorizationRequest(producer, request_id, capability, action_descriptor, proposal_ref),
constraints, current_epoch, now, trusted_issuer_pubkey_pem
```

It NEVER sees: `instrument`, `quantity`, `price_limit`, `destination`,
`notional_value`, or the `advisory_evidence` quant block (intentionally dropped in
`src/finance/proposal.py:41` `to_authorization_request`). Invariant 1 (ModelOutput !=
Authorization) holds *by construction* — the spine literally cannot be poisoned by bad
market data.

So where does poisoning enter? At the **action-proposal layer**. The untrusted agent (or a
corrupted upstream feed) proposes a `FinancialAction` (`src/finance/action.py:52`) whose
*economic content is factually wrong but internally plausible*:

- hallucinated `instrument` (delisted / non-existent symbol),
- `price_limit` wildly off a real quote (fat-finger or bad oracle),
- `destination` pointing at an attacker-controlled address,
- `quantity` inconsistent with the strategy's stated intent,
- `advisory_evidence` that fabricates support the underlying data never showed.

The spine returns `AUTO`. `RiskEngine.evaluate` (`src/risk/engine.py:159`) reads a *plausible*
`notional_value = |quantity| * price_limit` and finds no policy violation. `validate_settlement_intent`
passes its structural (cross-field) gate. Execution goes out. The ledger is signed, the
broadcast tx matches the (wrong) intent, `verify_locally()` is `True`. **Every invariant
passes. The outcome is wrong.** That is knowledge poisoning, end to end.

> The existing v2 layers are *narrowing* layers over the spine (risk, human, replay, breaker).
> They assume the action's *numbers are what the agent meant*. None of them asks: **"are these
> numbers true?"** v3 is that missing question.

---

## 2. Design principles (hard constraints)

- **Inv 1 preserved:** corroboration results must NEVER become inputs to `decide()`. v3 is a
  **new post-`decide()` narrowing layer**, exactly like `RiskEngine`. The frozen spine stays
  byte-for-byte untouched; the M0 domain-generality proof is unaffected.
- **Narrowing-only:** `AUTO → BLOCKED` (and `AUTO → HUMAN` only under Fork F9) are allowed;
  `BLOCKED → AUTO` and `HUMAN → AUTO` are forbidden. Mirror `RiskEngine.evaluate`'s
  narrowing contract (`src/risk/engine.py:168`).
- **Fail-closed:** if a claim cannot be independently corroborated (no feed, dead oracle,
  unknown instrument, unregistered destination) the verdict is `BLOCKED`. A claim is never
  *assumed true* by default. This is the direct inverse of the poisoning failure mode.
- **Inv 3 preserved (key-free verify):** the hygiene verdict must be replayable from the
  ledger without any key — provenance proof + corroboration source are recorded as
  `EvidenceEvent`s (`src/evidence/chain.py`) and signed ledger entries, exactly like today.
- **No new network egress by default:** corroboration sources are *configured* (env/fail-closed
  like `src/config.py`); absent sources → fail-closed, never silent-fallback to "trust the agent".

---

## 3. New model — the action's economic content as *untrusted claims*

`FinancialAction` is already a signed/audited hash (`action_hash`, `src/finance/action.py:94`).
v3 treats selected fields as **claims about the world** that require provenance, and wraps them
in a `ProvenanceClaim` (new `src/hygiene/claim.py`):

```python
@dataclass
class ProvenanceClaim:
    claim_type: str          # INSTRUMENT_EXISTS | PRICE_QUOTE |
                             # DESTINATION_OWNERSHIP | QUANTITY_INTENT_MATCH |
                             # EVIDENCE_GROUNDED
    asserted_value: Any      # the value the agent asserted (e.g. price_limit=1.0)
    source: str              # producer / feed id that asserted it
    evidence_ref: str        # causal_ref into EvidenceGraph (raw artifact)
    observed_at: int         # epoch the claim was made
```

The `advisory_evidence` block (`src/finance/proposal.py:39`), today *dropped* by the spine and
merely shown for audit, becomes **grounded**: each claim it makes must resolve to a referenced
artifact with a provenance hash. Unresolvable claims → hygiene violation. This converts the
advisory block from decoration into a verifiable provenance anchor — without it ever reaching
`decide()`.

---

## 4. New layer — `CorroborationLayer` (new `src/hygiene/`)

A narrowing-only gate inserted **immediately after the spine and before risk** (Fork F5).
For each `ProvenanceClaim` it demands an *independent* corroboration source:

| Claim type | Corroboration requirement (fail-closed) |
|---|---|
| `INSTRUMENT_EXISTS` | Instrument must resolve in a configured instrument master / reference registry. Unknown → `BLOCKED`. |
| `PRICE_QUOTE` | ≥ N independent oracle/feed quotes (Fork F7). `price_limit` must lie within `[min, max]` of corroborated quotes ± deviation band (Fork F8, e.g. 50 bps). Out-of-band / no feed → `BLOCKED`. |
| `DESTINATION_OWNERSHIP` | `destination` must be on the tenant's pre-registered settlement-address allowlist (Fork F6). Off-allowlist → `BLOCKED`. This is the strongest anti-theft control. |
| `QUANTITY_INTENT_MATCH` | `quantity` consistent with the stated strategy rationale in `advisory_evidence` (notional within stated bounds). Inconsistent → `BLOCKED`. |
| `EVIDENCE_GROUNDED` | Every assertion in `advisory_evidence` resolves to a referenced EvidenceGraph artifact. Unresolvable → `BLOCKED`. |

Output: `HygieneVerdict(ok: bool, verdict: str, violations: list, provenance_events: list)` —
narrowing-only, mirroring `RiskVerdict` (`src/risk/engine.py:1`).

> **Why this is not "just more risk."** `RiskEngine` evaluates *policy bounds* (concentration,
> velocity, loss limits) *assuming the numbers are what the agent meant*. `CorroborationLayer`
> evaluates the *truth of the numbers themselves*. They compose: Risk assumes truth; Hygiene
> proves truth. Together: "within our risk appetite **and** independently corroborated as real."

---

## 5. Pipeline reordering (hard boundaries preserved)

Current v2 order (`src/service/pipeline.py:107` `run`):

```
EPISTEMIC(spine) → POLICY → RISK → HUMAN → REPLAY/ISO → BREAKER → SETTLEMENT → SIGNER → STATE → VENUE → RECON → EVIDENCE
```

Proposed v3 order (insert HYGIENE right after the spine, before risk):

```
EPISTEMIC(spine) → HYGIENE(corroborate claims) → POLICY → RISK → HUMAN → REPLAY/ISO →
BREAKER → SETTLEMENT → SIGNER → STATE → VENUE → RECON → EVIDENCE
```

Rationale: a poisoned action is cheapest to block *before* risk even runs, and the hygiene
verdict belongs to the same "is this action safe to consider?" phase as the spine. `res` gains
`hygiene_ok` / `hygiene_violations` (like the existing `risk_ok` / `risk_violations`), and the
endpoint surfaces them. `EvidenceGraph` gains the corroboration events (provenance + source
ref) so an auditor replays: *agent asserted price P → corroborated by oracle X at T within band
→ authorized*.

---

## 6. Integration points (reuse, don't reinvent)

- **`EvidenceGraph`** (`src/evidence/chain.py`) — provenance + causal refs already exist;
  hygiene emits corroboration `EvidenceEvent`s into the same graph. Inv 3 preserved.
- **`RiskEngine.evaluate`** (`src/risk/engine.py:159`) — exact narrowing-only contract to copy
  for `CorroborationLayer.evaluate`.
- **`src/config.py` fail-closed env readers** — new `RATHNONE_HYGIENE_*` knobs mirror the
  existing `RATHNONE_MAX_SETTLEMENT_VALUE_WEI` pattern: unset → `BLOCKED`.
- **`validate_settlement_intent`** (existing cross-field gate) — hygiene reuses its
  structural-assertion style, extended with independent-source assertions.
- **`Tenant`** (`src/service/tenant.py`) — gains a `settlement_allowlist: set[str]` (Fork F6)
  provisioned out-of-band, fail-closed empty.
- **Frozen spine**: zero changes. `decide()` still sees only the neutral tuple. M0 proof intact.

---

## 7. Forks ratified (all recommended defaults, per "proceed with all")

- **F5** hygiene insertion: after spine, before risk ✅ (implemented at `AUTHORIZED→EVALUATED` band)
- **F6** destination trust: per-tenant pre-registered `settlement_allowlist` (fail-closed empty) ✅
- **F7** corroboration quorum: N=2 independent feeds (fail-closed below threshold) ✅
- **F8** price deviation band: 50 bps around corroborated mid ✅
- **F9** severity on uncorroborated: always BLOCKED (narrowing-only) ✅

---

## 8. Verification plan (REAL, executed)

- `tests/test_hygiene.py` (**13 tests, all green**):
  - `test_disabled_is_passthrough` — default runtime: layer off ⇒ AUTO untouched.
  - `test_instrument_unknown_blocked` — hallucinated symbol ⇒ BLOCKED (`instrument_unknown`).
  - `test_price_out_of_band_blocked` — `price_limit` beyond 50bps band ⇒ BLOCKED.
  - `test_destination_off_allowlist_blocked` — attacker address ⇒ BLOCKED.
  - `test_destination_untrusted_when_allowlist_empty` — hygiene on + empty allowlist ⇒ BLOCKED (fail-closed).
  - `test_quantity_intent_mismatch_blocked` — quantity ≠ stated rationale ⇒ BLOCKED.
  - `test_high_risk_without_evidence_blocked` — high-risk + no grounding ⇒ BLOCKED.
  - `test_fail_closed_no_feeds` — configured feeds absent ⇒ BLOCKED (not AUTO).
  - `test_quorum_below_threshold_blocked` — only 1 feed, quorum 2 ⇒ BLOCKED.
  - `test_all_corroborated_passes` — valid instrument + in-band price + allowlisted dest ⇒ AUTO, provenance emitted.
  - `test_narrowing_never_widens_blocked` — frozen BLOCKED stays BLOCKED.
  - `test_pipeline_blocks_poisoned_destination_when_hygiene_enabled` — **end-to-end**: spine AUTO but hygiene BLOCKS off-allowlist dest (REJECTED).
  - `test_pipeline_passes_corroborated_when_hygiene_enabled` — **end-to-end**: corroborated action ⇒ SETTLED/MATCH.
- Full suite: **98 passed** (85 prior + 13 hygiene). `verify_locally()` still green (Inv 3 unchanged).
- Console `/authorize` surfaces `hygiene_ok`/`hygiene_violations` (guarded; lights up on the
  v2 `authorize_action` path). `npm run build` clean.
- Frozen spine: zero changes. Inv 1 + Inv 3 intact. No new network egress in default path.

## 9. Why this is the right v3 (and not scope creep)

It closes the *single* documented open seam using only primitives Rathnone already owns
(EvidenceGraph, narrowing-only engine pattern, fail-closed config, signed ledger), without
touching the frozen spine or relaxing any invariant. It is the natural "does the action's
knowledge correspond to the world?" counterpart to v2's "is this action within our authority?"

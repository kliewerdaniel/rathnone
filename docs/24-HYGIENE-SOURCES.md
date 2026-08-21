# ADR 24 — Distinct-Origin Corroboration Sources (knowledge-poisoning quorum)

**Status:** RATIFIED (2026-08-20) + IMPLEMENTED.

**Series context:** ADR 16 (v3) added the epistemic-hygiene layer — a post-spine,
narrowing-only, fail-closed gate that demands independent corroboration for an
action's economic claims (fork F7: "N=2 independent feeds"). But the implemented
layer took `feeds` as a *plain list of numbers per instrument* and counted the
**list length** toward quorum. That quietly defeated the fork's intent: a single
origin reporting `[1000, 1001, 1002]` satisfied `quorum=2` even though there was
only ONE source of truth. Knowledge poisoning is precisely the case where the
*feed itself* is wrong, so "two numbers from one feed" is zero independent
corroboration.

This ADR makes fork F7 REAL: quorum is satisfied only by **distinct,
independently-originated sources**, each identified by name. No new network
egress — sources remain locally-configured values (the v3 "no egress by default"
principle holds); ADR 24 only makes the *independence* of the quoted evidence a
first-class, enforced property rather than an assumption.

---

## 1. Decision

Change the corroboration-layer's price input from `feeds: {instrument: [..]}`
(anonymous, length-counted) to `price_sources: {source_id: {instrument: price}}`
(named origins). Quorum counts **distinct `source_id` keys**, never repeated
values. Two quotes from the same `source_id` (or the legacy anonymous `feeds`
list, which is treated as a single `"feed"` origin) count **once**.

Add fail-closed env knobs so a deployment configures genuinely distinct origins
without code changes (mirroring the existing `RATHNONE_*` config pattern):

- `RATHNONE_HYGIENE_ENABLED=1` — turn the gate on (default off).
- `RATHNONE_HYGIENE_PRICE_SOURCES` — JSON `{"source_id": {"INSTR": price}}`.
  Unset ⇒ empty ⇒ any priced claim is BLOCKED by default (fail-closed). Malformed
  JSON / non-dict body ⇒ **raises** (never silently trusts one source).
- `RATHNONE_HYGIENE_BAND_BPS` — deviation band (default 50).
- `RATHNONE_HYGIENE_QUORUM` — min distinct sources (default 2); `<1` ⇒ **raises**.

## 2. Why this is the right fix (not scope creep)

The v3 layer already had the narrowing-only / fail-closed / Inv-1 / Inv-3
machinery *correct*. The only defect was the quorum accounting — it conflated
"number of quotes" with "number of independent origins." ADR 24 fixes that single
seam using primitives Rathnone already owns (env readers, the `CorroborationLayer`
constructor, the provenance record). No change to the frozen spine, no new
network dependency, no relaxation of any invariant. It is the natural completion
of fork F7.

## 3. Invariants preserved

- **Inv 1** (spine untouched): zero changes to `fleet.epistemic.decide()`.
- **Inv 3** (key-free ledger replay): provenance records the `sources` list and
  `n_sources`; an auditor can see exactly which origins corroborated.
- **Fail-closed:**
  - unset `RATHNONE_HYGIENE_PRICE_SOURCES` ⇒ no origins ⇒ priced claim BLOCKED;
  - bad JSON / non-dict ⇒ raises at construction (deployment won't boot with a
    broken source config);
  - quorum `<1` ⇒ raises;
  - one origin reporting twice ⇒ still BLOCKED at quorum=2.
- **No egress by default:** sources are values, not live fetches. A deployment
  that wants live feeds wires them in out-of-band and *names* each feed; ADR 24
  simply enforces that ≥ N distinct names actually backed the quote.

## 4. Implementation notes (implemented)

- `src/hygiene/__init__.py` — `CorroborationLayer.__init__` gains
  `price_sources`; `evaluate` gathers quotes keyed by origin, counts
  `len(distinct sources)`, records `n_sources` + `sources` in provenance. Legacy
  `feeds` is back-compatible (one anonymous `"feed"` origin).
- `src/config.py` — `hygiene_enabled`, `hygiene_price_band_bps`,
  `hygiene_quorum`, `hygiene_price_sources` (JSON parse, fail-closed).
- `src/service/app.py` — `_hygiene` built from the env readers.
- `tests/test_hygiene.py` (+8) — distinct-origin quorum satisfied vs. rejected;
  repeated-values-don't-count; 3-source median ignores an outlier; legacy
  anonymous feed counts as one origin; env readers (parse / empty / bad-json /
  quorum-below-1).
- `.env.example` — documents the four `RATHNONE_HYGIENE_*` knobs.

## 5. Verification gate (met)

- `pytest -q` → **173 passed** (was 165; +8 ADR 24), no regressions.
- `console npm run build` + `tsc -p tsconfig.json --noEmit` → clean (no console
  changes required).

---

**Ratified and implemented (2026-08-20, "proceed").** Fork F7's "N=2 independent
feeds" is now genuinely two independent feeds.

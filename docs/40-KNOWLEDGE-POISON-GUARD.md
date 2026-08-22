# ADR 40 — Knowledge-Layer Source Corroboration (knowledge-poisoning guard)

- **Status:** RATIFIED + IMPLEMENTED
- **Extends:** Roadmap `Post-roadmap` (knowledge poisoning, `09-OPEN-QUESTIONS.md`); the ADR 24 analogue at the evidence plane.
- **Depends on:** `src/query/executor.py` (`EvidenceRecord`, `KnowledgeGraph`), `src/query/loader.py`, `src/query/agent.py`; the frozen `decide()` spine (NOT touched — Invariant 1).

## Context

Rathnone closes the authority boundary (frozen `decide()`, ADR 17–24/26/34–39).
But `09-OPEN-QUESTIONS.md` names the residual risk: a *perfectly governed* system
can still act on *wrong knowledge* — the model reasons correctly from wrong
facts, policy authorizes, execution succeeds, verification confirms the expected
(wrong) state. Every invariant passes; the outcome is still undesirable.

The knowledge engine has world-class **authority** trust (ADR 30/34/35/36:
served `EvidenceRecord`s are authentic, signed, replayable) but **zero content
trust**. The loader (`loader.py`) consumes an SKC artifact and trusts every
`source` / `domain` / `authority` / `confidence` at face value. Three concrete
gaps fall out:

1. **Sybil provenance / one-feed-twice.** A single poisoned principal can present
   8 look-alike domains. `authority`/`confidence` float freely. The engine has no
   notion of *distinct registrable origin*, so a one-principal fabrication passes
   as "many sources."
2. **Inflated scores.** A high `authority` score from a single poisoned origin is
   still one origin — but nothing flags that the *supporting evidence* rests on
   one principal.
3. **Total-graph capture.** A query like `MATCH("kubernetes")` `SCORE>=0.0`
   returns a fully-attested `EvidenceRecord` over **100% adversary-supplied text**;
   the attestation vouches for the poison on the caller's behalf.

This is exactly the ADR 24 shape at the *knowledge* layer: ADR 24 demands
`quorum` **DISTINCT** price sources before a finance claim is believed and
explicitly kills "one feed reporting twice." ADR 40 demands `quorum` **DISTINCT
registrable-origin** sources before a *retained evidence set* is treated as
corroborated, and explicitly kills "one principal, many domains."

## Decision

1. **A narrowing-only, opt-in, fail-closed `PurificationLayer`** (`src/query/purify.py`)
   that runs *after* `QueryExecutor` produces an `EvidenceRecord` and *labels* it
   `CLEAN` / `POISONED`. It never withholds the record (withholding is the
   consumer's narrowing step — see §3) and never touches the frozen spine. It is
   the evidence-plane mirror of `hygiene.CorroborationLayer`.
2. **Distinct-origin quorum via eTLD+1 collapse.** Retained `document`/`claim`
   entities are mapped to their **registrable domain** (`_etld1`): `a.evil.com`
   and `b.evil.com` collapse to `evil.com`; distinct eTLDs (`evil.com` vs
   `evil.net`) stay distinct. Quorum counts *distinct registrable origins*, not
   repeated values. Default `quorum=2` (shadows F7's `quorum=2`). A retained set
   resting on `< quorum` distinct origins => `POISONED`.
3. **`authority`/`confidence` are advisory, never corroboration — but an *unearned*
   high score is now flagged.** A retained entity carrying a high trust score
   (`>= unearned_score_floor`, default 0.5) on provenance that fails the distinct-
   origin quorum is internally inconsistent: the corpus asserts trust the
   provenance does not support. This closes the §Context gap #2 (inflated
   scores) without trusting the score as corroboration. We surface the score in
   the report and only flag the *mismatch*, so a legitimately diverse, high-
   confidence corpus is never false-flagged.
4. **Total-graph capture is a diagnosis, not a new blocking rule.** When a query
   retains ≥ `capture_threshold` (default 0.90) of the corpus's doc/claim entities
   AND fails the origin quorum, a `total_graph_capture` violation is also emitted
   (same `POISONED` outcome). Gated on BOTH conditions so a legitimate broad query
   over a clean, diverse corpus is NOT flagged.
5. **Internal contradiction capture (SEMANTIC, corpus-sourced).** The SKC
   `research-knowledge-artifact/1.0` schema carries a top-level `contradictions[]`
   array flagging pairs of mutually-opposing claims (with a `confidence` and
   `dimension`). The loader (`loader.py`) now indexes each claim's opponents into
   `entity.extra["contradicts"]`. If a retained `EvidenceRecord` includes BOTH
   sides of a flagged opposition, the purified verdict is `POISONED` with an
   `internal_contradiction` violation listing the pairs. This is *semantic* poison
   — an agent reasoning from the retained set would hold opposite beliefs — but it
   is detected from the corpus's **own structured signal**, not by an LLM, so it
   stays deterministic, reproducible, and network-free (Invariant 3).
6. **Service wiring (ADR 40 seam).** `service.create_app()` builds a
   `PurificationLayer` from `RATHNONE_PURIFY_ENABLED` / `RATHNONE_PURIFY_QUORUM`
   / `RATHNONE_PURIFY_SCORE_FLOOR` (env, call-time, per-instance). Every
   `/query/*` response carries `out["poison"]` = the verdict dict. Disabled by
   default => pure pass-through, so the existing suite is unaffected.
7. **Consumer narrowing (`KnowledgeAgent.accept`).** The agent is given a
   narrowing-only `accept(result)` that returns `True` only if `poison.verdict ==
   "CLEAN"` (or the service isn't running the layer). A POISONED record is
   perfectly signable — `accept` is independent of `verify_signature`. This is the
   knowledge-plane "refuse to reason from un-corroborated evidence" step.

## What ADR 40 is NOT (honesty register)

- **Structural defense, with a bounded semantic slice.** The structural checks
  (sybil provenance, single-origin reliance, total-graph capture, unearned
  confidence) need no model. The semantic slice is **bounded to signals the
  corpus itself provides**: a retained set that includes BOTH sides of a
  corpus-flagged `contradictions[]` opposition is internally contradictory
  (an agent holding both would believe opposites). This is real semantic poison
  detection, but it is *the corpus's own contradiction label*, not an independent
  judgment of world-truth.
- **It does NOT verify world-truth.** Text that is internally consistent,
  sourced from genuinely distinct reputable origins, and NOT flagged as a
  contradiction by the corpus — but false in the world — still passes. We claim
  *"the retained set is internally consistent and corroborated across distinct
  origins,"* not *"the claims are true."* That limit is stated in the report and
  here. Closing it would require an external fact-verification oracle (network +
  model), which is explicitly out of scope for this local-first, frozen-spine
  plane.
- It does not verify the *content* of any source, follow any link, or fetch
  anything (no network egress; consistent with "no egress by default").

## Consequences

- **Positive.** The knowledge surface now has a structural corroboration gate that
  parallels the finance surface's ADR 24 quorum — closing the "one feed / one
  principal" loophole the open question named, without a model and without
  touching `decide()`.
- **Positive.** The verdict is reproducible from `(graph, record) + quorum policy`
  (Invariant 3): anyone holding the graph and the record can recompute it; it is
  surfaced in every served response and the agent narrows on it.
- **Positive / negative.** Opt-in + fail-closed: disabled by default, so
  local-first use and the existing suite are untouched; enabled, an un-corroborated
  retained set is stamped POISONED, never assumed-clean.
- **Cost.** None new: stdlib only; the verdict is O(retained) and adds no latency
  path to `decide()` (which the engine never calls).

## Verification

- `tests/test_purify.py` (18 tests):
  - `test_etld1_groups_subdomains` — eTLD+1 grouping + multi-label TLDs.
  - `test_clean_diverse_corpus_stays_clean` — 5 distinct origins => CLEAN.
  - `test_single_origin_poisoned` / `test_sybil_subdomains_collapse` — one principal
    (many domains / many subdomains) => POISONED (the ADR 24 loophole closed).
  - `test_distinct_etld_count_as_separate_origins` — honest limit, 2 distinct => CLEAN.
  - `test_quorum_config_enforced` — `quorum=3` flips a 2-origin set to POISONED.
  - `test_authority_score_is_advisory_not_corroboration` — inflated score ≠ clean.
  - `test_concept_only_result_is_clean` — no poison surface when no docs/claims retained.
  - `test_disabled_layer_passthrough` — opt-in off => CLEAN.
  - `test_total_graph_capture_diagnosed` — broad query over 100% poisoned corpus => both
    violations fire.
  - `test_service_annotates_poison_when_enabled` — live `/query/nl` returns POISONED for a
    single-origin artifact, CLEAN for a 3-origin one.
  - `test_agent_refuses_poisoned_accepts_clean` — `KnowledgeAgent.accept` narrows correctly.
  - `test_loader_indexes_corpus_contradictions` — the SKC `contradictions[]` array is
    indexed into each claim's `extra["contradicts"]`.
  - `test_retaining_both_sides_of_contradiction_is_poisoned` — both sides retained =>
    `internal_contradiction` violation fires (semantic slice).
  - `test_retaining_one_side_of_contradiction_stays_clean` — one side only => no
    `internal_contradiction` (contradiction flag is side-aware).
  - `test_unearned_confidence_flagged` — single high-score entity on thin provenance =>
    `unearned_confidence` violation.
  - `test_earned_confidence_diverse_corpus_clean` — high scores across a quorum-reaching
    diverse set => CLEAN (no false positive on legitimate confidence).
  - `test_service_annotates_semantic_poison_over_wire` — live `/query/op` (TYPE=claim)
    retains both opposing claims => POISONED with `internal_contradiction` in the served
    `poison` payload.
- Full suite: **318 pytest passing** (prior baseline 311 + 7 console-contract + this 18).
  The layer is off in every existing test (env unset), so no regression.

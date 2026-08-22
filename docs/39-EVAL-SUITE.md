# ADR 39 — Rathnone Eval Suite (Phase 6: decision sweep + blind adversary harness)

- **Status:** RATIFIED + IMPLEMENTED
- **Supersedes / extends:** Roadmap Phase 6 (`docs/06-ROADMAP.md`, metrics R-SC1 / R-SC2)
- **Depends on:** frozen `fleet.epistemic.decide()` (ADR / Invariant 1), `exchange.epistemic_adapter` (`GovernanceAuthority`, scope/constraint builders), Rathnone finance registry (ADR 17–24, 26)

## Context

Roadmap Phase 6 is the **honesty gate**: the two experimental claims the
entire architecture rests on must be demonstrated with real, reproducible
numbers, not asserted prose.

- **R-SC1** — a parametric sweep over the Rathnone finance decision space
  (≥6,000 points) yields **0 false accepts** (an unauthorized action that
  nonetheless received AUTO/HUMAN).
- **R-SC2** — a blind adversary harness (≥5,000 randomized vectors across the
  four named attack families — forged identity, approval rebind, scope escape,
  executor deception) yields **0 false authorizations**.

A "false accept" / "false authorization" is any point the external safety
contract says MUST be BLOCKED but which returns a non-BLOCKED verdict.

## Decision

1. **Drive the frozen `decide()` directly — not the gateway wrapper.**
   The existing `tests/test_eval.py` stub routed through
   `GatewayContext.authorize()`, which **self-issues its own grant**. That
   wrapper physically cannot present a forged, stale, expired, foreign-issuer,
   or agent-mismatched grant — so the four named attack families were never
   actually exercised. The correct methodology (matching fleet's own
   `test_decision_sweep.py` / `test_adversarial_blind_harness.py`) constructs
   `AuthorityGrant` objects by hand and calls `decide()` as a black box. The
   eval suite now imports ONLY the public substrate API + stdlib; it does not
   consult the threat model or invariant list when deriving expected verdicts.

2. **R-SC1 — fully enumerated, no sampling.**
   The input space is the Cartesian product of:
   3 registered finance caps × 4 identities (grant issued to identity 0) ×
   3 request caps (in-scope / other-registered / unknown) × grant present/absent
   × 3 signature states (valid / corrupted / foreign-issuer) ×
   4 grant epochs × 2 epoch states (current / stale) × 2 clock states
   (fresh / expired) × 2 policy states × 2 human flags = **7,056 distinct
   evaluated points**. Because `decide()` is a pure deterministic function, the
   sweep is exact coverage, not a statistical estimate.

3. **R-SC2 — genuinely randomized negative fuzz + one positive control.**
   5,000 attack vectors (pinned seed `0xA11CE`) cover: forged identity
   (valid grant to agent-0, presented by a different caller), approval rebind /
   scope escape (valid grant for cap A, request cap B or an unknown cap),
   unknown scope escape, foreign-issuer grant (signed by an untrusted key),
   corrupted signature, and stale+expired grant. Every vector MUST be BLOCKED.
   A single positive control (genuinely valid in-scope current grant) MUST be
   authorized (verdict AUTO).

4. **External safety contract as the oracle.**
   An action is legitimately authorized IFF all of: grant present; signature
   verifies against the trusted issuer key; epoch current AND TTL unexpired;
   grant bound to the presenting identity; requested cap within granted scope;
   deterministic policy allows. The oracle is derived ONLY from this protocol
   contract — never from the substrate's internal invariant list — so the test
   is a held-out check, not a restatement of the implementation.

## Consequences

- **Positive.** The two experimental claims are now demonstrable with exact
  counts and a pinned seed/commit: R-SC1 = 7,056 points / 0 false accepts;
  R-SC2 = 5,000 vectors / 0 false authorizations. The count far exceeds the
  roadmap's ≥6,000 / ≥5,000 thresholds.
- **Positive.** The four named attack families (forged identity, approval
  rebind, scope escape, executor deception) are genuinely exercised for the
  first time — previously the gateway wrapper made that impossible. The
  suite is threat-model-agnostic (imports only public API + stdlib).
- **Positive / negative.** R-SC3 (independent ledger reconstruct, 100%) is
  covered by `test_mirror.py` and R-SC4 (4th surface = one-line table edit) by
  `test_registry.py`; both are inherited by this Phase-6 gate, not duplicated.
  The eval asserts the *authority boundary* holds regardless of the model — it
  does NOT claim "the model is safe" (knowledge poisoning remains out of scope,
  `docs/09-OPEN-QUESTIONS.md`).
- **Cost.** None new: the eval reuses the frozen `decide()` and the already-pinned
  `cryptography` dep. Runtime is ~3 s for the full pair; `decide()` is a pure
  in-memory function (p95 well under the R-LAT < 5 ms budget).

## Verification

- `tests/test_eval.py::test_decision_sweep_zero_false_accepts` — 7,056-point
  enumerated sweep; asserts 0 false accepts and that every legitimate point is
  authorized.
- `tests/test_eval.py::test_blind_adversary_harness_zero_false_authorizations`
  — 5,000-vector blind fuzz; asserts 0 false authorizations and a valid-grant
  positive control returns AUTO.
- `python -m tests.test_eval` prints the reproducible report
  (R-SC1: 7056 / 0; R-SC2: 5000 / 0; control AUTO; RESULT PASS).
- Full suite: **282 pytest passing** (the eval pair is strengthened in place;
  it replaces the weaker self-granting stub rather than adding net tests).

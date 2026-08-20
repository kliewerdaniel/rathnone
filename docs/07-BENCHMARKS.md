# 07 — Benchmarks

Success is measured with **real, reproducible numbers**, inheriting fleet's evaluation register (architectural / implementation / experimental kept separate).

## Inherited from `sovereign-agent-fleet` (carry-over, free)

These hold because Rathnone reuses the frozen spine untouched (F1):

- **563 tests passing** in the governance substrate (567 collected; 4 live-venue network tests deselected by default).
- **237 / 532** collected test functions directly exercise an adversarial condition (identity, capability escalation, unauthorized action, approval mutation, artifact tampering, audit tampering, executor deception, verification failure, provenance, cross-domain) — all pass.
- **6,000-point parametric sweep** of `decide()` input space → 0 false accepts (`fleet/tests/test_decision_sweep.py`).
- **5,000-vector blind adversary harness** → 0 false authorizations (`fleet/tests/test_adversarial_blind_harness.py`).
- **18 fail-closed compiler-gate tests** in the knowledge substrate.

## Rathnone-specific (new, must be demonstrated)

| ID | Metric | Target | Maps to |
|----|--------|--------|---------|
| R-SC1 | Parametric sweep over the Rathnone finance registry | ≥6,000 pts, **0 false accepts** | SC1 |
| R-SC2 | Blind adversary harness vs the finance gateway | ≥5,000 vectors, **0 false authorizations** | SC2 |
| R-SC3 | Independent reconstruct of every recorded finance action | **100% match**, fail-closed on mismatch | SC3 / Invariant 3 |
| R-SC4 | Add a 4th finance surface | **one-line table edit**, suite auto-covers | SC4 |
| R-LAT | Gateway `decide()` latency (p95) | < 5 ms (pure function, no model/network) | perf |
| R-AUD | Audit-reconstruct time for a 10k-action ledger | < 2 s on commodity hardware | forensic |

## Honesty register (do not collapse)

- **Architectural claims:** "model output is never on the authority path" — proven by the import wall + `decide()` signature (no epistemic param).
- **Implementation claims:** "Rathnone reuses the frozen `decide()` untouched" — verified by Phase 0 exit (fleet's 563 tests pass from Rathnone venv).
- **Experimental claims:** R-SC1/R-SC2 numbers — reported with counts, failure criteria, and pinned commit, exactly as fleet reports RQ1–RQ4.

## Anti-metric (what we will NOT claim)

- We will **not** claim "the model is safe" — we claim "the *authority boundary* holds regardless of the model." A governed system can still act on wrong knowledge (knowledge poisoning, `09-OPEN-QUESTIONS.md`).

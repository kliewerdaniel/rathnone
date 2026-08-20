# 06 — Roadmap

Dependency-ordered phases. Each phase has an exit criterion tied to a metric in `07-BENCHMARKS.md`. No phase advances until its exit gate is green. **No commit/push until the user reviews final design + build.**

## Phase 0 — Repo + library wiring (B1)
- Create `~/Projects/rathnone/`, wire `sovereign-agent-fleet` as an imported library (`vendor_fleet/`).
- Confirm `import fleet.epistemic` resolves and the frozen `decide()` is callable without modification.
- **Exit:** `pytest` against fleet's 563-test suite passes from within the Rathnone venv (proves the spine is intact, untouched).

## Phase 1 — Finance registry + generality (B2, SC4)
- Define `CAP_FIN_*` trio + Rathnone `REGISTERED_CAPABILITIES`.
- Port the parameterized generality suite from fleet's `domain_registry` to prove same-policy→same-verdict across the finance trio.
- **Exit:** Adding a 4th finance surface is a one-line table edit and the suite auto-covers it.

## Phase 2 — Gateway API (B3, F4)
- Fresh product gateway: accept a `RathnoneFinanceProposal`, build `AuthorizationRequest`, call `decide()`, return `AuthorizationDecision`.
- Translation layer ensures `_advisory_evidence` never reaches `decide()`.
- **Exit:** Gateway returns correct AUTO/HUMAN/BLOCKED for the three capabilities across policy/grant/scope permutations.

## Phase 3 — Execution adapters (B4, B5, B6)
- Fail-closed, opt-in adapters: trade-execute (simulated broker), treasury-rebalance, on-chain settlement (signer + `SettlementAuthRecord`).
- Default = simulated; live venues/chain are opt-in and fail-closed.
- **Exit:** Each adapter produces a signed, ledger-bound record; a forged/mismatched intent is rejected by the verifier.

## Phase 4 — Hybrid audit mirror (B7, F3)
- Client-side signing + local ledger; cloud mirror holds signed chain only, recomputes verification with public keys.
- **Exit:** Cloud console verifies a recorded action with zero signing keys present (SC3).

## Phase 5 — Product console + tenant/metering (B8, B9, F4)
- Risk dashboard, approval console, forensic audit view, tenant isolation, commercial metering.
- **Exit:** A tenant can authorize the finance trio, see the immutable audit trail, and meter usage.

## Phase 6 — Rathnone eval suite (B10, SC1, SC2)
- Decision sweep (≥6,000 pts over the finance registry) → 0 false accepts.
- Blind adversary harness (≥5,000 vectors: forged identity, approval rebind, scope escape, executor deception) → 0 false authorizations.
- **Exit:** Both suites green; reported against RQ1–RQ4 style honesty (architectural / implementation / experimental separated).

## Post-roadmap (research, not this build)
- The open problem from the source: **knowledge poisoning** — a perfectly governed system can still act on wrong *knowledge*. Rathnone inherits this; mitigation is out of scope for v1 (named in `09-OPEN-QUESTIONS.md`).

# 02 — Objectives

## Goals

- **G1 — Govern the finance trio under one authority.** A single frozen `fleet.epistemic.decide()` instance-authority authorizes trade execution, treasury rebalance, and on-chain settlement. Verdict depends on *nothing* the model produced.
- **G2 — Reuse, don't re-implement.** The authorization function, crypto suite, signed hash-chain ledger, identity/cert chain, and generality harness come from `sovereign-agent-fleet` **untouched** (F1).
- **G3 — Hybrid authority (F3).** Local-first authority on client infra; optional cloud audit mirror (read-public, signing-key-free) reusing fleet's GCP mirror pattern.
- **G4 — Audit-grade forensics.** Every authorized finance action is reconstructable by an independent verifier from signed inputs alone (Invariant 3: Verification ⟂ Cognition).
- **G5 — Tenant-aware product surface.** A fresh, product-grade API + UI (F4) that presents the three finance surfaces as one gateway console.

## Non-goals (this phase)

- **NG1 — Not building a new model or quant engine.** The quant/evidence layer is reused as advisory enrichment only.
- **NG2 — Not forking the governance substrate.** `decide()` stays frozen in `sovereign-agent-fleet`; Rathnone calls it.
- **NG3 — Not a general 6-domain product.** Rathnone's scope is the finance trio. The M0 proof in fleet remains the generality evidence; Rathnone proves the *finance* slice.
- **NG4 — Not live-mainnet-by-default.** Execution is fail-closed and opt-in; default runtime is simulated, matching fleet's default.

## Success criteria

- **SC1 — 0 false authorizations** on the finance action space: parametric sweep of the Rathnone registry (analogous to fleet's 6,000-point `test_decision_sweep.py`) yields 0 false accepts.
- **SC2 — Blind adversary harness**: ≥5,000 randomized attack vectors against the finance gateway (forged identity, approval rebind, scope escape, executor deception) → 0 false authorizations.
- **SC3 — Independent reconstruct**: a verifier with only public keys recomputes the disposition of every recorded finance action and matches the ledger (fail-closed on mismatch).
- **SC4 — Generality within finance**: adding a 4th finance sub-surface is a one-line `(label, capability)` table edit in Rathnone's registry, auto-covered by a parameterized suite (mirrors fleet's `domain_registry`).

## Anti-success signals

- A model's confidence score appears anywhere on the authority path.
- An executor's self-report is trusted as verification.
- Adding a finance surface requires editing `decide()` or any fleet substrate file.
- Audit record is a plain log rather than a signed hash chain.

## Ratified forks (F1–F4)

| Fork | Decision |
|------|----------|
| **F1 — Relationship** | Separate repo importing `fleet` as a library/overlay; frozen `decide()` + M0 proof stay intact. |
| **F2 — Flagship surface** | Unified Sovereign Finance Gateway: trade execution + treasury rebalance + on-chain settlement under one governance authority. |
| **F3 — Authority placement** | Hybrid: local-first authority on client infra + optional cloud audit mirror. |
| **F4 — Product stack** | Fresh API + UI stack (not fleet's `fleet/api` + `ui`), reusing the governance spine as a library. |

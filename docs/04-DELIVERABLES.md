# 04 — Deliverables

Split per the standing "compounding work" rule: **Group A** = foundation already built (reused from `sovereign-agent-fleet`), **Group B** = new work Rathnone ships.

## Group A — Foundation (already built, reused untouched)

| # | Built artifact | Source in `sovereign-agent-fleet` | Reuse mode |
|---|----------------|-----------------------------------|------------|
| A1 | Frozen `decide()` authorization | `fleet/epistemic/decision.py` | Import as library |
| A2 | Crypto suite (Argon2id→Ed25519→XChaCha20) | `fleet/crypto/` | Import as library |
| A3 | Signed hash-chain ledger | `fleet/` audit ledger | Import as library |
| A4 | Identity / Ed25519 cert chain | `fleet/epistemic/identity.py`, `fleet.crypto.foundation.AgentCert` | Import as library |
| A5 | Policy + capability scoping (default-deny) | `fleet/layers/policy.py`, `fleet/epistemic/governance_constraints.py` | Import as library |
| A6 | Human approval (D17) + consensus | `fleet/` approval/consensus | Import as library |
| A7 | GCP mirror pattern (fail-closed, read-public) | `fleet/` GCP mirror + `DEPLOY_LIVE.md` | Pattern reuse |
| A8 | Quant evidence layer (advisory) | `exchange/quant/` (Kelly, Bayesian, regime, `zk.py`) | Import as library, enrichment only |
| A9 | M0 generality harness | `domain_registry/` | Pattern reuse for Rathnone's own registry |

> None of A1–A9 is modified by Rathnone. Compounding: the 563-test governance substrate and its adversarial proofs carry over for free.

## Group B — New work (shipped by Rathnone)

| # | Deliverable | Depends on |
|---|-------------|-----------|
| B1 | Rathnone repo + `vendor_fleet/` library import wiring (F1) | A1–A6 |
| B2 | Finance registry: 3 `(label, capability)` pairs + parameterized generality suite (SC4) | A9 pattern, A1 |
| B3 | Fresh product gateway API (F4) — proposal→`AuthorizationRequest`→`decide()`→`AuthorizationDecision` | A1, A4 |
| B4 | Trade-execute adapter (fail-closed, opt-in broker/venue; simulated default) | B3, A8 (enrichment) |
| B5 | Treasury-rebalance adapter (cross-account/asset rebalance orchestrator) | B3 |
| B6 | On-chain settlement adapter (fail-closed tx-intent signer) + **SettlementAuthRecord** schema | B3, see `05-SCHEMA.md` |
| B7 | Hybrid cloud audit mirror client (key-free replica + verify) (F3) | A3, A7 |
| B8 | Product console UI (risk dashboard, approval console, forensic audit) (F4) | B3, B7 |
| B9 | Tenant isolation + commercial metering (per-AUM / per-transaction) | B3, B8 |
| B10 | Rathnone eval suite: decision sweep (≥6,000 pts), blind adversary harness (≥5,000 vectors) (SC1, SC2) | A1, B2 |

## Final checklist (build-phase entry gate)

- [ ] B1–B2 done without touching any file under `sovereign-agent-fleet/`
- [ ] B10 demonstrates SC1 (0 false accepts) and SC2 (0 false authorizations)
- [ ] B7 verifies SC3 (independent reconstruct matches ledger)
- [ ] B2 demonstrates SC4 (4th surface = one-line table edit)

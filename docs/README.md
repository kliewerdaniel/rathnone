# Rathnone

> **Do not trust the model. Trust the execution protocol.**

Rathnone is a **Sovereign Finance Gateway**. It lets a fund, treasury, or protocol deploy autonomous or LLM-driven finance agents while keeping absolute, cryptographically verifiable control over every consequential money movement.

The governance core is **not written by Rathnone**. It is the frozen, deterministic `fleet.epistemic.decide()` function from `sovereign-agent-fleet` — a pure function that takes an identity, a signed grant, a scope, a request, deterministic constraints, governed state, and a trusted issuer public key, and returns exactly one verdict: **AUTO / HUMAN / BLOCKED**. It accepts **zero** probability, confidence, or model output (Invariant 1: `ModelOutput ≠ Authorization`).

Rathnone wires that spine to three real finance actions under one governance authority:
- **Trade execution** — authorize/block order routing & fills.
- **Treasury rebalance** — authorize/block cross-account or cross-asset rebalances.
- **On-chain settlement** — authorize/block smart-contract calls (fail-closed).

## Orientation by role

**Chief Risk Officer / Compliance**
You get a control plane where a confident, hallucinating, or compromised model *cannot* move money it isn't permitted to move. Every action carries a signed authorization and lands in a tamper-evident hash-chain ledger you can independently recompute and forensically audit.

**Quant / Agent builder**
Your model stays an *advisor*. It produces evidence (Kelly sizing, Bayesian edge, regime state) that is **attached as enrichment only** — it never becomes permission. You integrate once against a stable `decide()` contract and stop re-implementing "is this allowed?" for every strategy.

**Platform / Infra engineer**
Local-first authority runs on the client's infra (F3: hybrid). An optional cloud audit mirror (reusing fleet's GCP mirror pattern) provides read-public forensic verification without holding any signing key.

## What Rathnone is NOT

- Not another multi-agent orchestration framework.
- Not a re-implementation of authorization. The authority function is reused, frozen, model-independent.
- Not a predictor. Belief and permission are separate computational boundaries.

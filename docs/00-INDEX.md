# Rathnone — Docs Index

**One-line definition:** A Sovereign Finance Gateway — a commercial product that rides the frozen, model-independent `fleet.epistemic.decide()` authorization spine from `sovereign-agent-fleet` to govern consequential finance actions (trade execution, treasury rebalance, on-chain settlement) with cryptographic verifiability and an immutable audit ledger.

**Status:** Implemented & verified. v1 (53 tests) + v2 control plane (16 adversarial) + operator console (safety, trace, reconcile) all shipped and green (75 pytest). Forks F1–F4 ratified. Live track is opt-in, fail-closed.

## Doc map

| File | Purpose |
|------|---------|
| `README.md` | TL;DR + orientation by role (CRO, Quant, Eng) |
| `01-VISION.md` | Recast thesis: "Do not trust the model. Trust the execution protocol." |
| `02-OBJECTIVES.md` | Goals, non-goals, success criteria, anti-success signals, ratified forks |
| `03-ARCHITECTURE.md` | System design on the real `decide()` contract; inherited vs new |
| `04-DELIVERABLES.md` | Group A (foundation / already built) vs Group B (new work) |
| `05-SCHEMA.md` | New artifact contracts (finance capabilities, settlement auth record) |
| `06-ROADMAP.md` | Phased plan with exit criteria tied to metrics |
| `07-BENCHMARKS.md` | How success is measured (inherits fleet's real metrics + Rathnone-specific) |
| `08-REUSE.md` | Ledger: lift-unchanged / de-domain-ize / build-new + migration steps |
| `09-OPEN-QUESTIONS.md` | Risks, the source's named trap (knowledge poisoning), decisions still open |
| `10-RATIFIED.md` | Ratified forks F1–F4, B6, B9 (signed off "proceed with all") |
| `11-PHASE5.md` | Phase 5 design record (tenant isolation B8, per-AUM metering B9) |
| `12-LIVE-TRACK.md` | Live track: real venue/chain signing adapters (opt-in, fail-closed) |
| `13-SECURITY-THREAT-MODEL.md` | Security threat model: defenses against 4 red-team inversions (V1–V4) |
| `14-V2-CONTROL-PLANE.md` | v2 authorization plane: 11-layer pipeline, signed approvals, replay, evidence graph |
| `15-OPERATOR-CONSOLE.md` | Operator console surface: console→endpoint map, /reconcile, V4 breaker, verification |

## Planned folder layout (target, not yet created)

```
~/Projects/rathnone/
  docs/                 # this set
  src/
    gateway/            # fresh product API surface (F4: fresh stack)
    finance/            # the 3 registered consumers of decide() (F2)
      trade_execute/
      treasury_rebalance/
      chain_settle/
    mirror/             # cloud audit mirror client (F3: hybrid)
  ui/                   # fresh product console
  tests/
  vendor_fleet/         # fleet imported as a library/overlay (F1)
```

## Relationship to sovereign-agent-fleet (F1)

Rathnone is a **separate repo** that imports `fleet` as a library/overlay. The frozen `decide()` and the M0 domain-generality proof stay **untouched** inside `sovereign-agent-fleet`. Rathnone adds the finance *product* surface on top — structurally a 7th consumer of `decide()`, living in its own repo, calling the same neutral `fleet.epistemic.decide()`.

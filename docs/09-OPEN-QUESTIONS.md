# 09 — Open Questions

## Risks & named traps (from the source)

- **Knowledge poisoning (the source's open problem).** A perfectly governed system can still do the wrong thing if its *knowledge* is wrong: model reasons correctly from wrong knowledge, policy authorizes, execution succeeds, verification confirms the expected (wrong) state — every invariant passes, outcome undesirable. Rathnone inherits this. **v1 scope: out of scope**; the governance boundary is the product, not belief correction. Mitigation is a stated future research track, not a hidden gap.
- **Confidence-as-trust leakage.** The single most likely regression: an engineer attaches a model score "just for routing." Must be blocked at review (no epistemic field may touch `decide()`). Covered by import-wall + signature, but the gateway translator (B3) is the watchpoint.
- **Live venue/chain egress.** Real broker/chain adapters are opt-in and fail-closed. Default = simulated. A misconfigured live adapter that bypasses `decide()` would defeat the product — adapters must route *every* action through the gateway, never direct to venue.

## Decisions still open for the user (architecture-affecting)


These are the remaining forks before the build phase. They are **build-time**, not design-breaking, but they should be ratified first.

> **Ratification status (signed off "proceed with all"):** Forks 1–3 below are
> all **RATIFIED** and their implementations are complete:
> - **F4 (concrete stack)** → Python FastAPI gateway + Next.js 14 console. Built
>   (`src/service/app.py`, `console/`). See `11-PHASE5.md`.
> - **B6 (settlement target)** → EVM L2 primary, binding chain-agnostic.
>   Real secp256k1 settlement signing implemented (`12-LIVE-TRACK.md`).
> - **B9 (metering model)** → per-AUM, 5 bps. `MeteringLedger` + console meter
>   view. See `11-PHASE5.md`.

1. **F4 concrete stack.** "Fresh stack" is ratified, but the specific language/framework for the gateway + UI is open. Recommendation: **Python gateway service** (it imports `fleet` directly, no FFI) + a **Next.js** console (matches fleet's `ui/` ergonomics and the user's existing `danielkliewer.com` / Next.js ecosystem) — but a lighter alternative (e.g. FastAPI + React, or a typed CLI-first surface) is valid. *This changes B3/B8 shape, not the governance contract.* **→ RATIFIED: Python gateway + Next.js console.**
2. **On-chain settlement target (B6).** Which chain(s)/protocol? Options: EVM L2 (e.g. Base/Arbitrum), Solana, or chain-agnostic tx-intent abstraction. This changes the `SettlementAuthRecord.chain` field and the signer adapter, and affects the ZK attestation story (`exchange/quant/zk.py` is chain-agnostic but the settlement binding is not). **→ RATIFIED: EVM L2 primary (chain-agnostic binding).**
3. **Commercial metering model (B9).** Per-AUM, per-transaction, or per-seat/tenant? Affects tenant schema and the console's metering view, not the authority path. **→ RATIFIED: per-AUM.**

## What is NOT open

- The governance spine (`decide()`) — frozen, reused, not re-implemented.
- The three trust domains and the five invariants — inherited verbatim.
- Hybrid authority placement (F3) — ratified.
- Finance-trio as the flagship surface (F2) — ratified.

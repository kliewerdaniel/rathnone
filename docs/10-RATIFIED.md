# 10 — Ratified Forks (proceed)

Captured at "proceed with all". These were the three architecture-affecting open
decisions in `09-OPEN-QUESTIONS.md`. All ratified with the recommended default.

## F4 — Concrete product stack
- **Gateway:** Python service. It imports `fleet` directly (no FFI), so the
  frozen `decide()` is called in-process. Matches the local-first authority model.
- **Console:** Next.js (reuses the ergonomics of fleet's `ui/` and the existing
  `danielkliewer.com` / Next.js ecosystem). Deferred to Phase 5; v1 proves the
  gateway + eval first.
- Lighter alternative (FastAPI+React or CLI-first) remains valid but not chosen.

## B6 — On-chain settlement target
- **Primary:** EVM L2 (Base / Arbitrum) — most commercially realistic for
  institutional settlement and the cleanest fit for the existing
  `exchange/quant/zk.py` ZK attestation story.
- **Binding is chain-agnostic:** `SettlementAuthRecord.chain` is a string field;
  the signer adapter is swappable. Adding Solana / a non-EVM chain later is an
  adapter change, not a governance change.

## B9 — Commercial metering model
- **Per-AUM** (assets under governance). Natural for finance: the unit of risk
  is the book size the gateway is authorized to move, not per-transaction noise.
- Console metering view (Phase 5) reads this; the authority path is unaffected.

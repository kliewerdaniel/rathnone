# 12 — Live Track: Real Venue/Chain Signing Adapters (opt-in, fail-closed)

**Status:** Built + verified (82 pytest green, incl. the real-venue suite). The
real L2 venue adapter shipped as `src/venue/l2.py`; default runtime remains the
simulator. Fail-closed: real broadcast requires `RATHNONE_L2_RPC_URL` + a live
tenant.

## Why this exists
Phase 3 adapters are SIMULATED by default — no real signature, no network. The
product is the governance boundary, not the venue. But a buyer doing due
diligence will ask: *"when you say an action was authorized, can anyone prove
the authorized intent was actually bound to an on-chain signature?"* The live
track answers that with **real cryptography**, gated so the default runtime
never touches credentials or the network.

## Invariants (must hold — and do)
- **Invariant 1 (ModelOutput != Authorization).** Signing happens strictly
  *after* the frozen `fleet.epistemic.decide()`. The live path calls `decide()`
  again; the signature binds only what `decide()` returned `AUTO` for. No
  epistemic field reaches `decide()`.
- **Fail-closed.** Non-AUTO verdict → no signature committed. `intent_hash`
  mismatch (executor tampering) → verifier rejects. Live track not enabled for
  a tenant → `authorize_action` refuses to live-sign (no settlement key).
- **Verification ⟂ Cognition (Invariant 3).** A live settlement signature is
  verified with the tenant's **secp256k1 public key / address only** — the same
  material any Ethereum client holds. The gateway's signing key is never
  needed to verify.

## Cryptographic primitives
- `keccak256` — **verified `pycryptodome` `Keccak_256`** (matches the Ethereum
  test vectors exactly). *Decision:* the originally hand-rolled sponge
  (`_keccak.py`) had a structural bug across the ρ/π steps that 8 systematic
  combination checks could not pin down cheaply; rather than ship unverified
  crypto, we use the proven library primitive. The secp256k1 sign/recover is
  still hand-rolled and independently verified (below) — it is the piece that
  gives EVM compatibility; the hash primitive is commodity.
- `Secp256k1Signer` — real secp256k1 ECDSA, deterministic RFC6979 nonce,
  low-S canonical, compressed-key → Ethereum address. `sign_eth` produces the
  `keccak256(msg)` digest signature that `ecrecover` (any Ethereum client)
  recovers to the address. Proven: sign → recover → address round-trips.
- `OrderAuthRecord` — genuine Ed25519 signature over the authorized order,
  binding the tenant's governance key.

## Artifacts
- `SettlementAuthRecord` — `intent_hash = keccak256(canonical(intent))`, signed
  with the tenant's secp256k1 key. `verify(intent)` re-hashes, recovers the
  signer from the signature, and checks the address. Tampered calldata fails.
- `OrderAuthRecord` — Ed25519 over `keccak256(canonical(order))`.
- Every live signature is appended to the tenant's **immutable ledger** as a
  `live_sign` entry (signed with the tenant's governance key), so the forensic
  audit trail + the on-chain-verifiable signature live in the same
  key-free-verifiable chain.

## Service surface (fail-closed)
- `POST /tenants` — `live: bool` opt-in. Mints a secp256k1 settlement key,
  returns `settlement_address`. Simulated default unchanged.
- `POST /tenants/{id}/authorize_action` — runs the frozen `decide()`; if `AUTO` and
  live-enabled, commits a real signature over the action hash; 403 otherwise.
  Refuses on BLOCKED (e.g. deny-listed capability) and when live is not enabled.
  This is the single signing path (ADR 17 deleted `/execute_live`).

## Console
- Mint form: "live track (real signing)" toggle → shows `settlement_address`.
- Authorize page: "Sign live settlement" panel signs a `chain_settle` intent and
  displays the address + signature.
- Audit page: "Live settlement signatures" subsection lists each `live_sign`
  entry's address / intent hash / signature for independent verification.

## Test evidence (`tests/test_live.py`, 12 tests; full suite 43 pass)
- keccak256 vectors (`''`, `'abc'`, `bytes(256)` exactly match Ethereum).
- secp256k1 sign→recover→address round-trip; deterministic nonce (RFC6979).
- `SettlementAuthRecord.verify` accepts original, rejects tampered + wrong
  signer; refuses to build on non-AUTO.
- `OrderAuthRecord.verify` accepts original, rejects tampered.
- Service: live refused when not enabled; signs + independently recovers when
  AUTO; refused on BLOCKED; signature lands in the immutable ledger and is
  independently recoverable from the stored record.

## Out of scope (named, not hidden)
- **Live RPC egress by default.** No broker/chain RPC is contacted in the default
  runtime. Adapters MUST route every action through the gateway (`decide()`
  first) — never direct to venue.
- **Real L2 venue (now implemented as a drop-in).** `src/venue/l2.py` adds
  `RealL2Venue`, a `VenueAdapter` that broadcasts authorized actions to a real
  EVM-L2 over JSON-RPC, signing each raw tx with the tenant's OWN settlement key
  (EIP-155, hand-rolled RLP — no `eth_account` dependency). It is selected by the
  `get_venue()` factory ONLY when `RATHNONE_L2_RPC_URL` is set AND the tenant is
  live (has a `settlement_key`). Otherwise `get_venue()` returns `SimulatedVenue`
  (identical to today — no egress, no credentials). Construction failures RAISE
  rather than silently falling back to the simulator (a simulated MATCH for an
  action never broadcast is the worst outcome). No credentials are invented by
  the code; supply a real RPC url + chain id at deploy time.
- **Multi-chain.** Settlement record carries `chain` (default `evm_l2`); the
  binding is chain-agnostic in shape, EVM-verifiable in practice.

## Constraints preserved
- `sovereign-agent-fleet` repo: untouched (imported via `.pth`, zero edits).
- Nothing committed/pushed (user reviews first).

# 05 — Schema (new artifact contracts)

Rathnone introduces **two** new contracts. Everything else reuses fleet's real field names verbatim (see `03-ARCHITECTURE.md`).

## 1. Rathnone finance capabilities (new registered constants)

These are the literal capability strings the substrate sees — analogous to fleet's `CAP_TRADE_EXECUTE`, `CAP_INCIDENT_REMEDIATE`, etc.

```python
CAP_FIN_TRADE_EXECUTE       = "rathnone.trade_execute"
CAP_FIN_TREASURY_REBALANCE  = "rathnone.treasury_rebalance"
CAP_FIN_CHAIN_SETTLE        = "rathnone.chain_settle"
```

Each is registered as `("rathnone/<surface>", CAP_FIN_*)` in Rathnone's own `REGISTERED_CAPABILITIES`, mirroring fleet's `domain_registry`.

## 2. RathnoneFinanceProposal (new → becomes `AuthorizationRequest`)

The gateway translates a finance proposal into fleet's real `AuthorizationRequest` (no new fields invented — reuses `producer`, `request_id`, `capability`, `action_descriptor`, `proposal_ref`). Rathnone's *wrapper* adds finance-specific context that stays **epistemic (advisory)** and is explicitly excluded from `decide()`:

```json
{
  "producer": "rathnone-gateway",
  "request_id": "req-8f2c...",
  "capability": "rathnone.chain_settle",
  "action_descriptor": "transfer(USDC, 50000, 0xAB..) -> L2",
  "proposal_ref": "prop-...",
  "_advisory_evidence": {
    "kelly_fraction": 0.12,
    "bayesian_edge": 0.034,
    "regime": "trending",
    "zk_range_proof_ref": "zk-...",
    "note": "ATTACHED AS ENRICHMENT ONLY — never read by decide()"
  }
}
```

The `_advisory_evidence` block is the quant layer's output (reused from `exchange/quant/`). It travels with the proposal for human/audit context but **does not enter `decide()`**.

## 3. SettlementAuthRecord (new — binds authorized action to on-chain intent)

Extends fleet's `AuthorizationDecision` (verdict/capability/refs/epoch) with a settlement-specific, fail-closed binding. The record is what the verifier recomputes (Invariant 3).

```json
{
  "kind": "settlement_authorization",
  "decision_ref": "<hash of AuthorizationDecision>",
  "capability": "rathnone.chain_settle",
  "chain": "ethereum-l2",
  "contract_address": "0x...",
  "intent_hash": "<hash of (to, value, calldata, nonce)>",
  "epoch": 1,
  "authorization_verdict": "AUTO",
  "signer_commitment": "<Ed25519 sig over intent_hash by gateway key>",
  "ledger_prev": "<prev AuditState hash>",
  "ledger_next": "<H(prev ‖ this event)>"
}
```

Fail-closed rules (inherited invariants):
- `authorization_verdict != "AUTO"` → no signature committed; the tx intent is **never** signed.
- `intent_hash` mismatch vs the executor's actual calldata → verifier rejects (executor deception, A5).
- Any `ledger_next` that doesn't equal `H(ledger_prev ‖ event)` → fail-closed verify (A4).

## 4. What is deliberately NOT in the schema

- No `confidence`, `probability`, `model_score`, or `belief` field on any **authorization** artifact (Invariant 1).
- No executor self-report field treated as truth (Invariant 3).
- No mutable/plain-log audit entry (Invariant 4 — signed hash chain only).

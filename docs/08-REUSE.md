# 08 — Reuse Ledger

How each piece of `sovereign-agent-fleet` enters Rathnone. Three modes: **lift-unchanged**, **de-domain-ize**, **build-new**.

## Lift unchanged (import as library, zero edits)

| Fleet artifact | Rathnone use | Mode |
|----------------|--------------|------|
| `fleet.epistemic.decision.decide()` | Authority for all 3 finance surfaces | lift-unchanged |
| `fleet.epistemic.decision.AuthorizationDecision` | Verdict artifact returned by gateway | lift-unchanged |
| `fleet.crypto.*` (Argon2id, Ed25519, XChaCha20, hash chain) | All signing + ledger integrity | lift-unchanged |
| `fleet.epistemic.identity.AgentIdentity`, `fleet.crypto.foundation.AgentCert` | Agent identity + cert chain | lift-unchanged |
| `fleet.epistemic.governance_constraints.build_governance_constraints` | Policy (allowlist, require_human) | lift-unchanged |
| `fleet.epistemic.authorization.build_authorization_scope` | Scope binding | lift-unchanged |
| `exchange.epistemic_adapter.{issue_grant, GovernanceAuthority}` | Grant issuance + trust anchor | lift-unchanged |
| `exchange/quant/*` (Kelly, Bayesian, regime, `zk.py`) | Advisory evidence enrichment | lift-unchanged |

## De-domain-ize (pattern reuse, Rathnone owns its copy)

| Fleet pattern | Rathnone copy | Change |
|---------------|---------------|--------|
| `domain_registry.REGISTERED_CAPABILITIES` + `decide_all` | `rathnone/src/finance/registry.py` | Different `(label, capability)` table (finance trio); same neutral `decide()` call; same parameterized generality suite shape |
| `domain_registry.decide_registered` | `rathnone ... decide_fin_registered` | Same logic, finance capabilities |
| GCP mirror + `DEPLOY_LIVE.md` fail-closed judge console | `rathnone/src/mirror/` client | Same fail-closed, read-public, key-free replica pattern |

## Build new (Rathnone-only)

| Piece | Why new |
|-------|---------|
| Gateway API (F4 fresh stack) | Product surface; fleet's `fleet/api` intentionally not reused (F4) |
| `RathnoneFinanceProposal` → `AuthorizationRequest` translator | Binds finance context to fleet's real request fields without inventing auth fields |
| Trade-execute / treasury-rebalance / chain-settle adapters | Finance-domain execution; fleet has `exchange/` but Rathnone's trio is broader (treasury + on-chain) |
| `SettlementAuthRecord` | New artifact binding authorized action to on-chain intent (schema in `05-SCHEMA.md`) |
| Product console UI (F4) | Tenant-aware risk/approval/forensic surface |
| Tenant isolation + metering | Commercial packaging absent from the research repo |

## Migration / boundary rules (hard)

1. **No edits under `sovereign-agent-fleet/`.** Any need to modify `decide()`, crypto, or ledger = a fork request, not a silent edit.
2. **Import wall preserved.** Rathnone's cognition/quant usage never flows into the gateway's `decide()` call. The gateway only ever passes the neutral `(identity, grant, scope, request, constraints, epoch, now, trusted_issuer_pubkey_pem)` tuple.
3. **Capability strings are the only domain signal.** The substrate never sees the `label`; verdict depends only on capability + grant scope + policy (Invariant 1).

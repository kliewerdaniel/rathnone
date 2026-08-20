# 03 — Architecture

## The frozen contract we build on (verbatim from `sovereign-agent-fleet`)

`fleet.epistemic.decision.decide()` — a pure deterministic function:

```python
def decide(
    *,
    identity: AgentIdentity,
    grant: Optional[AuthorityGrant],
    authorization_scope: AuthorizationScope,
    request: AuthorizationRequest,
    constraints: GovernanceConstraints,
    current_epoch: int,
    now: int,
    trusted_issuer_pubkey_pem: str,   # trust anchor; pin, never embed
) -> AuthorizationDecision: ...
```

`AuthorizationDecision` carries **no epistemic field** — no `p`, no confidence, no score:

```python
@dataclass(frozen=True)
class AuthorizationDecision:
    verdict: str          # "AUTO" | "HUMAN" | "BLOCKED"
    capability: str
    request_ref: str      # hash of AuthorizationRequest
    grant_ref: str        # hash of AuthorityGrant
    scope_ref: str        # hash of AuthorizationScope
    epoch: int
    reason: str = ""
```

`AuthorizationRequest` (real fields, from `domain_registry` usage): `producer`, `request_id`, `capability`, `action_descriptor`, `proposal_ref`.

`GovernanceConstraints` builders: `build_governance_constraints(allowlist=(...), require_human_approval=bool)`.

This is the **entire** authority surface Rathnone reuses. Rathnone never imports the cognition layer (import-wall preserved).

## Rathnone as a 7th consumer (mirrors fleet's `domain_registry`)

Rathnone defines its **own** registry (in its own repo) with the finance trio, calling the *same neutral* `fleet.epistemic.decide()`:

```python
# rathnone/src/finance/registry.py  (new code, calls frozen fleet)
REGISTERED_CAPABILITIES: tuple[tuple[str, str], ...] = (
    ("rathnone/trade-execute",   CAP_FIN_TRADE_EXECUTE),
    ("rathnone/treasury-rebalance", CAP_FIN_TREASURY_REBALANCE),
    ("rathnone/chain-settle",    CAP_FIN_CHAIN_SETTLE),
)
```

Each capability is a `(label, capability_string)` pair, exactly the shape fleet's `REGISTERED_CAPABILITIES` uses for its six. Adding a 4th finance surface = one-line table edit + a parameterized generality suite auto-covers it (SC4).

## Three trust domains (inherited, unchanged)

```
  Cognition (UNTRUSTED — proposes only)  → EVIDENCE only, never authority
        │ PROPOSAL / EVIDENCE
        ▼ (crosses authority boundary)
  Governance (PURE FUNCTIONS)            → decides AUTHORIZATION via decide()
        │ AUTHORITY (signed authorization)
        ▼ (crosses execution boundary)
  Domain (trade / treasury / settlement) → ACTION (state-locked execution)
        │ ACTION
        ▼
  Verification (crypto / ledger)         → independent recomputation
```

Rathnone's three finance surfaces all live in the **Domain** box. They produce *actions*; they never decide *authority*.

## Component map: inherited vs new

### Inherited (F1 — reused untouched from `sovereign-agent-fleet`)
- `fleet.epistemic.decide()` — frozen authorization.
- Crypto suite: Argon2id → Ed25519 → XChaCha20-Poly1305.
- Signed hash-chain ledger: `AuditState(t+1) = H(AuditState(t) ‖ Event(t+1))`.
- Identity / Ed25519 cert chain (`AgentCert`, `AgentIdentity.from_cert`).
- Policy + capability scoping (default-deny; exhaustive property test asserts unknown role/capability → DENIED).
- Human approval (D17) + consensus (can-only-escalate).
- GCP mirror pattern (local Firestore-shaped → live, fail-closed, read-public judge console).
- `exchange/quant/` evidence layer (Kelly, Bayesian, regime, ZK Σ-protocol range proof `exchange/quant/zk.py`) — **advisory only**.

### New (built in Rathnone)
- **Fresh product API surface (F4)** — a gateway service exposing the three finance capabilities, packaging proposals → `AuthorizationRequest`, calling `decide()`, returning `AuthorizationDecision`.
- **Finance execution adapters** — fail-closed, opt-in connectors for: a broker/exchange venue (trade-execute), a treasury/rebalance orchestrator (treasury-rebalance), and an on-chain settlement signer (chain-settle). Default = simulated.
- **Settlement authorization record** — a new artifact binding an authorized action to an on-chain tx intent (see `05-SCHEMA.md`).
- **Product console (F4)** — risk dashboard, approval console, forensic audit view, tenant isolation.
- **Commercial packaging** — licensing / metering (per-AUM or per-transaction) and tenant provisioning.

## Hybrid authority placement (F3)

```
 CLIENT INFRA (local-first)                CLOUD (audit mirror, key-free)
 ┌───────────────────────────┐            ┌──────────────────────────────┐
 │ Rathnone Gateway           │            │ GCP Cloud Run (read-public)   │
 │  - decide() authority      │  signed    │  - signed chain replica       │
 │  - signing keys (Argon2id) │ ──chain──▶ │  - independent verify         │
 │  - executor + verifier     │            │  - judge console (fail-closed)│
 └───────────────────────────┘            └──────────────────────────────┘
```

The signing/trust-anchor key **never leaves client infra**. The cloud mirror holds only the signed hash chain and recomputes verification with public keys — it cannot authorize anything.

## Open adapter question (does not block design)

The concrete product stack for F4 (language/framework of the gateway + UI) is an **open decision** — see `09-OPEN-QUESTIONS.md`. The governance spine is language-agnostic at the contract level; the gateway is a thin wrapper, so the choice is a build-time decision, not an architecture change.

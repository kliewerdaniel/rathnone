# Rathnone — Docs Index

**One-line definition:** A local-first, fail-closed authority service with two independent surfaces: (1) a Sovereign Finance Gateway riding the frozen, model-independent `fleet.epistemic.decide()` spine to govern consequential finance actions (trade execution, treasury rebalance, on-chain settlement) with cryptographic verifiability and an immutable audit ledger; and (2) a deterministic Knowledge-Query & Evidence Engine (`src/query/`, ADR 27–33) that compiles an LLM-constructed logical query to an inspectable, attested `EvidenceRecord` served over HTTP behind an independent evidence-domain scope. The two surfaces never share trust (separate Ed25519 evidence key; the engine never imports `decide()`).

**Status:** Implemented & verified. Finance gateway (ADR 17–24, 26) + knowledge-query engine (ADR 27–38) shipped and green. Full suite: **282 pytest passing** (incl. ADR 36 rotation-aware witness audit, ADR 37 cross-surface root-of-trust, ADR 38 live cross-surface attestation consumer). The knowledge substrate is proven both in-process (`TestClient`) and over a real TCP socket (`uvicorn` + `httpx`, ADR 33). Live track, hygiene gate, operator downgrade, and evidence scope are opt-in, fail-closed.

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
| `16-V3-EPISTEMIC-HYGIENE.md` | v3 IMPLEMENTED: epistemic-hygiene / knowledge-poisoning layer (forks F5–F9 ratified) |
| `18-OPERATOR-DOWNGRADE.md` | ADR 18 RATIFIED+IMPLEMENTED: signed operator downgrade path for hygiene-BLOCKED (commit 7458803) |
| `19-OPERATOR-COMMAND-AUTH.md` | ADR 19 RATIFIED+IMPLEMENTED: signed operator command authorization (scope-bound verify) |
| `20-OPERATOR-AUTHORIZE-SIGNING.md` | ADR 20 RATIFIED+IMPLEMENTED: signed operator commands for `authorize_action` (live settlement transport) |
| `21-OPERATOR-KEY-LIFECYCLE.md` | ADR 21 RATIFIED+IMPLEMENTED: operator key lifecycle — provision / rotate / revoke / expire (replaces bare PEM allowlist) |
| `22-OPERATOR-KEY-MANAGEMENT.md` | ADR 22 RATIFIED+IMPLEMENTED: runtime key-management surface (add/revoke/rotate/list), double-gated by RATHNONE_API_KEY + RATHNONE_KEY_OPS |
| `23-OPERATOR-KEY-PERSISTENCE.md` | ADR 23 RATIFIED+IMPLEMENTED: durable SQLite keyring (RATHNONE_KEY_DB) so runtime key changes survive restart across workers |
| `24-HYGIENE-SOURCES.md` | ADR 24 RATIFIED+IMPLEMENTED: distinct-origin corroboration sources (quorum over named sources, not repeated values) + fail-closed env config |
| `26-LIVE-CEILING-DEFAULT.md` | ADR 26 RATIFIED+IMPLEMENTED: live-tenant default settlement ceiling — 1 ETH fail-closed cap when `RATHNONE_MAX_SETTLEMENT_VALUE_WEI` unset |

### Knowledge-Query & Evidence Engine (ADR 27–33, `src/query/`)

| File | Purpose |
|------|---------|
| `27-KNOWLEDGE-QUERY-EVIDENCE.md` | ADR 27 RATIFIED+IMPLEMENTED: deterministic knowledge-query & evidence engine — `Op` algebra + executor + `EvidenceRecord` |
| `28-NL-QUERY-COMPILER.md` | ADR 28 RATIFIED+IMPLEMENTED: deterministic, LLM-free NL → `Op` compiler |
| `29-QUERY-SERVICE.md` | ADR 29 RATIFIED+IMPLEMENTED: knowledge-query HTTP service (`create_app()`) for agent access |
| `30-EVIDENCE-ATTESTATION.md` | ADR 30 RATIFIED+IMPLEMENTED: evidence-domain attestation authority (independent Ed25519 key) |
| `31-AGENT-HARNESS.md` | ADR 31 RATIFIED+IMPLEMENTED: reference `KnowledgeAgent` harness (off-line attestation verify) |
| `32-EVIDENCE-OPERATION-SCOPE.md` | ADR 32 RATIFIED+IMPLEMENTED: per-agent `QueryScope` permissioning, bound to query body, fail-closed over wire |
| `33-LIVE-TRANSPORT.md` | ADR 33 RATIFIED+IMPLEMENTED: live-transport service over real TCP (`uvicorn` + `httpx`) — deployability gate |
| `34-EVIDENCE-AUTHORITY-LOG.md` | ADR 34 RATIFIED+IMPLEMENTED: evidence-authority trust log (anchorable hash-chained root/rotate/revoke; no trust-on-first-fetch) |
| `35-EVIDENCE-WITNESS-LOG.md` | ADR 35 RATIFIED+IMPLEMENTED: evidence-serving witness log (what record hash was served to which agent under which scope) |
| `36-WITNESS-KEY-BINDING.md` | ADR 36 RATIFIED+IMPLEMENTED: rotation-aware witness log — per-entry `key_seq`/`key_fingerprint` binding + `verify_witness_log_anchored` (audit survives evidence-key rotation) |
| `37-CROSS-SURFACE-ROOT-OF-TRUST.md` | ADR 37 RATIFIED+IMPLEMENTED: cross-surface root-of-trust — operator meta-key vouches for both surfaces' current keys (read-only, no shared trust path) |
| `38-LIVE-CROSS-SURFACE-CONSUMER.md` | ADR 38 RATIFIED+IMPLEMENTED: live cross-surface attestation consumer — gateway `GET /operator/public-key` + `surface_attest verify-live` checks the manifest against BOTH running surfaces |

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

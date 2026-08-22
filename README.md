# Rathnone

Rathnone is a **local-first, fail-closed authority service** with two independent
surfaces that share one design discipline — verifiable, inspectable execution
that an operator can audit and halt:

1. **Sovereign Finance Gateway** — rides the frozen, model-independent
   `fleet.epistemic.decide()` authorization spine from `sovereign-agent-fleet` to
   govern consequential finance actions (trade execution, treasury rebalance,
   on-chain settlement) with cryptographic verifiability and an immutable audit
   ledger.
2. **Knowledge-Query & Evidence Engine** (`src/query/`, ADR 27–38) — a
   deterministic, attestable knowledge-execution substrate for agents: an LLM
   *constructs* a logical query (`Op` algebra); Rathnone *compiles and executes*
   it to an inspectable, reproducibly-hashed `EvidenceRecord`, and serves it over
   HTTP behind an independent evidence-domain attestation + operation-scope layer.

The two surfaces never share trust: the knowledge engine has its own Ed25519
evidence key (distinct from the gateway keyring and attestation chain) and never
imports or mutates `fleet.epistemic.decide()`.

See `docs/` for the full design surface (`docs/00-INDEX.md`). The threat model
and the fail-closed operator controls are in `docs/13-SECURITY-THREAT-MODEL.md`.

---

## Finance Gateway — what this is (for the operator)

Rathnone is a **local-first authority service**. It does NOT make autonomous
financial decisions — the frozen `decide()` spine returns `AUTO` / `HUMAN` /
`BLOCKED`, and the service acts only on `AUTO`. The operator always retains an
independent halt (the circuit breaker) that stops the live track regardless of
what `decide()` says. This is the antidote to the "immutable cage" failure.

Two runtime tracks:

- **Simulated (default):** `POST /tenants/{id}/authorize_action` returns the
  authorized action with `simulated=True`. No real signatures, no network egress.
  Safe by default.
- **Live (opt-in):** a tenant minted with `live=true` gets a real settlement key.
  `POST /tenants/{id}/authorize_action` produces a genuine secp256k1 (settlement)
  or Ed25519 (order) signature **only after** `decide()` returns `AUTO`.

There is exactly **one** signing path. The legacy `/execute` (caller-supplied
verdict) and `/execute_live` (unbound payload) bypass endpoints were **deleted**
(ADR 17) — authority can only be exercised through `authorize_action`, which
cryptographically binds the signed `FinancialAction.action_hash`.

---

## Knowledge-Query & Evidence Engine — what this is (for the agent builder)

`src/query/` is an **additive, stdlib-only** subsystem. It moves semantic
retrieval and logical constraint evaluation OUT of the probabilistic layer and
INTO a deterministic execution layer:

- `algebra.py` — a serializable `Op` query-algebra IR (AND / OR / NOT / TYPE /
  SOURCE / MATCH / CONNECTED_TO / DERIVED_FROM / SAME_AS / NEAR / SCORE / TIME /
  PATH). Round-trips `to_dict()` / `from_dict()` for agent ↔ Rathnone.
- `executor.py` — a deterministic executor over an in-memory knowledge graph that
  emits an `EvidenceRecord` (included / excluded entities, predicates evaluated,
  exact reasons, source provenance, and a reproducible `deterministic_hash`).
- `loader.py` — loads a real `research-knowledge-artifact/1.0` SKC artifact into
  the graph (does NOT re-implement the SKC compiler).
- `compiler.py` — a **deterministic, LLM-free** NL → `Op` compiler for a
  constrained query language.
- `attest.py` — an independent evidence-domain authority that signs each record;
  the agent verifies off-line against the held public key (ADR 30).
- `authority.py` — an anchorable trust log (ADR 34): a self-certifying hash-chain
  of `bootstrap`/`rotate`/`revoke` entries so the evidence key can be rotated or
  revoked without redeploy, and an agent verifies the key against a **pinned**
  anchor (no trust-on-first-fetch).
- `witness.py` — an evidence-serving witness log (ADR 35): a tamper-evident,
  hash-chained, signed record of every attested query served (which record hash
  went to which agent under which scope), so an operator can audit what was
  served and detect dropped/substituted entries off-line.
- `scope.py` — per-agent `QueryScope` permissioning, bound to the exact query
  body, enforced fail-closed over the wire (ADR 32).
- `service.py` / `agent.py` — an HTTP service (`create_app()`) and a
  `KnowledgeAgent` client that drive each other unchanged in-process or over TCP.

Built and verified end-to-end: **in-process (`TestClient`) AND over a real TCP
socket** (`uvicorn` + `httpx`, ADR 33). The live-transport test is the
deployability gate.

---

## Deployment knobs (fail-closed) — Finance Gateway

All bounds come from the environment (prefixed `RATHNONE_*`). A malformed value
**raises at import time** rather than silently disabling a guard.

| Variable | Meaning | Default | Production |
|---|---|---|---|
| `RATHNONE_ENFORCE_AUTH` | ADR 17: gate all control-plane endpoints behind a static API key | `0` (dev: open) | **`1`** |
| `RATHNONE_API_KEY` | Static shared secret (Bearer or `X-API-Key`) checked when `ENFORCE_AUTH=1` | unset | **set it** |
| `RATHNONE_MAX_SETTLEMENT_VALUE_WEI` | ADR 26: refuse to sign any settlement above this many wei. **Unset on a LIVE tenant = a conservative 1 ETH fail-closed default** (so a forgotten config fails small, not open) | unset = **1 ETH live default** | **set it** (e.g. `500000000000000000` = 0.5 ETH) |
| `RATHNONE_LIVE_RATE_MAX` | V1: max live signatures per sliding window | `10**12` (unlimited) | **set it** (e.g. `100`) |
| `RATHNONE_LEDGER_DB` | P1: file path for the durable replay/nonce registry (SQLite). Absent => in-memory (process-local, hermetic) | unset = **in-memory** | set a file path (e.g. `/var/lib/rathnone/ledger.db`) so nonce/replay invariants survive restarts |
| `RATHNONE_L2_RPC_URL` | v2 P2: real L2 RPC endpoint; enables real on-chain broadcast of authorized+live-signed actions | unset = **SimulatedVenue** | supply a real URL + `RATHNONE_L2_CHAIN_ID` |
| `RATHNONE_PORT` | uvicorn bind port | `8765` | any |

`.env.example` is a hardened starting point. Copy to `.env` and adjust.

## Deployment knobs (fail-closed) — Knowledge-Query Engine

| Variable | Meaning | Default | Production |
|---|---|---|---|
| `RATHNONE_EVIDENCE_KEY_PEM` | Attestation key for the evidence domain (file path or inline PEM). Unset => ephemeral key (local use only; attestations not reproducible across restarts) | unset = **ephemeral** | **set it** |
| `RATHNONE_EVIDENCE_OP_KEY_PEM` | Evidence-operation authority (ADR 32). Provisioned => scopes **required** (fail-closed 401/403). Unset => scope enforcement **DORMANT** (open, local-first) | unset = **DORMANT** | **set it** |
| `RATHNONE_QUERY_API_KEY` | Control-plane key gate (`X-Control-Plane-Key`) on the query service. Unset => open | unset = **open** | **set it** |
| `RATHNONE_SKC_ARTIFACT` | Path to a `research-knowledge-artifact/1.0` JSON for `loader.py` | research-compiler-agent default | point at your artifact |
| `RATHNONE_QUERY_PORT` | uvicorn bind port for `src.query.service:app` | `8791` | any |

---

## Run it: Python (local/dev)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# The frozen spine is vendored at vendor/fleet_spine (pinned commit in
# vendor/fleet_spine/PINNED_COMMIT). The venv's fleet_overlay.pth points there.
pytest -q                       # 282 passing

# --- Finance Gateway ---
RATHNONE_MAX_SETTLEMENT_VALUE_WEI=500000000000000000 \
RATHNONE_LIVE_RATE_MAX=100 \
  python -m uvicorn src.service.app:app --port 8765

# --- Knowledge-Query Engine (ADR 29 + 30 + 32 + 33) ---
RATHNONE_EVIDENCE_KEY_PEM=path/to/evidence_key.pem \
RATHNONE_EVIDENCE_OP_KEY_PEM=path/to/evidence_op_key.pem \
  python -m uvicorn src.query.service:app --port 8791
```

The vendored spine is a **read-only snapshot** of `sovereign-agent-fleet` at a
pinned commit. That repo is never modified by Rathnone; bump the pin by
re-copying `fleet`/`exchange`/`scripts` and updating `PINNED_COMMIT`.

### Calling the knowledge engine from an agent

```python
import httpx
from src.query.agent import KnowledgeAgent

agent = KnowledgeAgent(httpx.Client(base_url="http://127.0.0.1:8791"))
agent.load_graph("research-knowledge-artifact.json", graph_name="skc")
# NL constructs a query; Rathnone executes it deterministically:
res = agent.query_nl("papers on gradient descent that cite convex optimization", graph_name="skc")
assert res.signature_ok is True           # attestation verified off-line
print(res.included_ids, res.excluded_ids) # inspectable evidence
```

Full provenance is verified by `res.raw["deterministic_hash"]` and the
`EvidenceRecord.verify()` / `reconcile_with()` methods.

### Operating the evidence domain (ADR 34 + 35)

Operator tooling (in `scripts/`, no new code paths — they drive the running
service over HTTP):

- `scripts/evidence_key_log.py` — manage the ADR 34 evidence-authority trust log:
  `bootstrap` / `rotate` / `revoke` the evidence key, producing a self-certifying
  hash-chain the agent verifies against a **pinned** anchor (no trust-on-first-fetch).
- `scripts/evidence_witness_verify.py` — audit the ADR 35 witness log against a
  live deployment:

  ```bash
  # Verify the served-witness chain + signatures off-line against the pinned key:
  python scripts/evidence_witness_verify.py verify \
      --base-url http://127.0.0.1:8791 \
      --evidence-key /secure/evidence_ed25519.pem

  # Archive the log for later off-line replay:
  python scripts/evidence_witness_verify.py export \
      --base-url http://127.0.0.1:8791 --out /audit/witness_$(date +%F).json
  ```

  The tool never trusts the served public key; it verifies against the same key
  the operator anchors via ADR 34. (Drift detection — does a served record still
  match a fresh execution? — lives in the agent harness `assert_stable` /
  `reconcile`, because the witness log stores only the record hash, not the query
  spec, by design.)

---

## Run it: Docker (recommended for prod)

The image bakes the frozen spine in at build time (no runtime fetch from a
mutable repo). It runs as a non-root user and ships a `/safety` healthcheck.

> **Build/run platform — IMPORTANT.** On Apple Silicon, build and run the
> image as **`linux/amd64`** (runs under Rosetta):
> ```bash
> docker build --platform=linux/amd64 -t rathnone:local .
> docker run   --platform=linux/amd64 -d --name rathnone \
>   -p 127.0.0.1:8765:8765 \
>   -e RATHNONE_MAX_SETTLEMENT_VALUE_WEI=500000000000000000 \
>   -e RATHNONE_LIVE_RATE_MAX=100 \
>   rathnone:local
> ```
> Why: the arm64 `cryptography` wheel SIGILLs (exit 132) inside the Docker VM's
> arm64 emulation during ed25519 native init. The amd64 image is stable and
> verified end-to-end (healthcheck, live signing, operator halt).

```bash
# Or with compose (loads .env if present; platform set in the file):
cp .env.example .env     # edit to taste
docker compose up -d
```

---

## Operator controls (the halt switch) — Finance Gateway

| Endpoint | Effect |
|---|---|
| `GET  /safety` | `{breaker_open, live_signing_enabled}` — current halt state |
| `POST /safety/halt` | **Trip the circuit breaker** — live signing stops immediately, regardless of `decide()` |
| `POST /safety/resume` | Clear the breaker (operator action only) |

```bash
curl -X POST http://127.0.0.1:8765/safety/halt   # STOP THE LOOP
curl -X POST http://127.0.0.1:8765/safety/resume  # resume
```

Once the breaker is open, `POST /tenants/{id}/authorize_action` returns `503`
("live signing halted").

---

## Tenant lifecycle (quick reference)

```bash
# 1. Mint a tenant (simulated track) — requires the control-plane API key
curl -s -X POST http://127.0.0.1:8765/tenants -H 'content-type: application/json' \
  -H 'Authorization: Bearer ***' \
  -d '{"aum": 1000000}' | python -m json.tool

# 2. Mint a LIVE tenant (gets a real settlement key + address)
curl -s -X POST http://127.0.0.1:8765/tenants -H 'content-type: application/json' \
  -H 'Authorization: Bearer ***' \
  -d '{"aum": 1000000, "live": true}' | python -m json.tool

# 3. Authorize + (if AUTO) live-sign a settlement in ONE call.
#    The /authorize_action path is open to tenant callers; it runs the frozen
#    decide(), cryptographically binds FinancialAction.action_hash, and (live
#    tenant + AUTO + bounds pass + breaker closed) returns a real signature.
curl -s -X POST http://127.0.0.1:8765/tenants/{TID}/authorize_action \
  -H 'content-type: application/json' \
  -d '{"action":{"action_id":"r1","actor":"p","capability":"rathnone.chain_settle",
       "side":"settle","destination":"0xAB","quantity":1.0,"price_limit":1.0,
       "currency":"wei","settlement_asset":"wei","nonce":1},"denylist":[]}' \
  | python -m json.tool

# 4. Audit the immutable ledger (key-free verifiable)
curl -s http://127.0.0.1:8765/tenants/{TID}/audit | python -m json.tool
```

Full API surface is in `src/service/app.py`; the console UI lives in `console/`.

---

## Safety invariants (what can never happen)

1. **No signing without AUTO.** Live signing happens strictly after
   `decide()` returns `AUTO`. The spine receives zero epistemic input from the
   signing path.
2. **Operator halt is independent.** `/safety/halt` stops the loop without
   `decide()`'s cooperation.
3. **Key-free verification.** The ledger is verifiable with the tenant's public
   key only; the private key never leaves the service.
4. **No identity binding.** PII in a live payload is rejected (403) before
   signing (panopticon defense).
5. **Bounds are enforced even on AUTO.** An over-ceiling or over-rate request is
   refused even with an `AUTO` verdict. **A live tenant with no ceiling set is
   still bounded** by a 1 ETH default (ADR 26) — the gateway fails *small*, never
   *open*.
6. **AUM-independent verdicts.** The gateway cannot gatekeep by capital.
7. **Knowledge engine is isolated.** The evidence domain uses its own key,
   never imports `decide()`, and enforces its own scope + attestation
   fail-closed (ADR 30/32/33).

---

## Design decisions (ADRs)

| ADR | Topic | Status |
|---|---|---|
| 17 | Control-plane API-key gate (delete bypass endpoints) | RATIFIED + IMPLEMENTED |
| 18 | Signed operator downgrade (hygiene-BLOCKED) | RATIFIED + IMPLEMENTED |
| 19 | Signed operator command authorization | RATIFIED + IMPLEMENTED |
| 20 | Signed operator commands for `authorize_action` | RATIFIED + IMPLEMENTED |
| 21 | Operator key lifecycle (provision / rotate / revoke / expire) | RATIFIED + IMPLEMENTED |
| 22 | Runtime operator-key management surface | RATIFIED + IMPLEMENTED |
| 23 | Durable SQLite keyring (survives restart) | RATIFIED + IMPLEMENTED |
| 24 | Distinct-origin corroboration sources (hygiene quorum) | RATIFIED + IMPLEMENTED |
| 26 | Live-tenant default settlement ceiling (1 ETH fail-closed) | RATIFIED + IMPLEMENTED |
| 27 | Deterministic knowledge-query & evidence engine | RATIFIED + IMPLEMENTED |
| 28 | NL → query-algebra compiler (deterministic, LLM-free) | RATIFIED + IMPLEMENTED |
| 29 | Knowledge-query HTTP service | RATIFIED + IMPLEMENTED |
| 30 | Evidence attestation (evidence-domain authority) | RATIFIED + IMPLEMENTED |
| 31 | Reference agent harness (end-to-end consume) | RATIFIED + IMPLEMENTED |
| 32 | Evidence-operation scope (per-agent permissioning) | RATIFIED + IMPLEMENTED |
| 33 | Live-transport service (real TCP boundary) | RATIFIED + IMPLEMENTED |
| 34 | Evidence-authority trust log (anchorable rotate/revoke; no TOFU) | RATIFIED + IMPLEMENTED |
| 35 | Evidence-serving witness log (audit what record hash went to which agent) | RATIFIED + IMPLEMENTED |
| 36 | Rotation-aware witness log (per-entry key binding; audit survives key rotation) | RATIFIED + IMPLEMENTED |
| 37 | Cross-surface root-of-trust (operator meta-key vouches for both surfaces' keys) | RATIFIED + IMPLEMENTED |
| 38 | Live cross-surface attestation consumer (gateway key endpoint + verify-live) | RATIFIED + IMPLEMENTED |
| 39 | Eval suite: 7,056-point decision sweep + 5,000-vector blind adversary harness, 0 false accepts/auths | RATIFIED + IMPLEMENTED |

Full doc map: `docs/00-INDEX.md`.

---

## Repository layout

```
src/
  service/            finance gateway (authorize_action, /safety, tenant lifecycle)
  finance/            registered consumers of decide() (trade / treasury / chain_settle)
  security/           guards, operator signing, keystore, hygiene gate
  hygiene/            epistemic-hygiene / knowledge-poisoning layer
  query/              knowledge-query & evidence engine (algebra, executor, loader,
                    compiler, attest, scope, service, agent) — ADR 27–39
  config.py           all RATHNONE_* readers
vendor/fleet_spine/   pinned, read-only snapshot of sovereign-agent-fleet
console/              Next.js operator console
docs/                 design surface (00-INDEX .. 39-EVAL-SUITE)
examples/             runnable PoCs: agent_harness.py, live_harness.py
tests/                282 tests (gateway, security, query engine, live transport)
scripts/              operator signing / scope-signing / evidence-log audit helpers
Dockerfile            reproducible, non-root, fail-closed image
docker-compose.yml    hardened local deployment
.env.example          deployment knobs
```

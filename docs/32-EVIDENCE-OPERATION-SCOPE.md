# ADR 32 — Evidence-Domain Operation Scope (per-agent query permissioning)

- **Status:** RATIFIED + IMPLEMENTED (2026-08-21) — full suite green (240 passed)
- **Extends:** ADR 29 (query service) + ADR 30 (evidence attestation) + ADR 31 (agent harness)
- **Parallels:** ADR 19/20 (signed operator command, gateway) and ADR 26 (live settlement cap)
- **Depends on:** `src/query/{algebra,executor,attest,service}.py`

## Context

ADR 27-31 build the knowledge substrate and a reference agent (`KnowledgeAgent`)
that consumes it end-to-end, verifying attestations off-line. But today **any
caller can query any graph with any `Op`** — there is no blast-radius limiter on
the knowledge side. The agent harness proves the *attestation* story; it does not
yet prove an *authorization* story.

The 2026 agentic-finance landscape that drove ADR 26 is the same force here:
Mastercard Agent Pay for Machines, Stripe agent tokens, and the OpenAI→HuggingFace
intrusion all show that a **non-bypassable per-agent permission envelope** is the
critical control — cap *what* an agent may do (category), *how much* (max), and
*for how long* (TTL), bound to a specific scope and replay-guarded. ADR 26 puts
that envelope on the settlement path. ADR 32 puts the same envelope on the
evidence-query path, in the evidence trust domain.

We deliberately model this on the gateway's proven `OperatorCommand` (ADR 19/20):
a **bearer, body-bound, replay-guarded, time-windowed signed scope** — not a
held-key model. That keeps the evidence domain parallel to, but independent of,
the frozen gateway.

## Decision

Introduce a **`QueryScope`** signed credential — an evidence-domain operation
scope that an operator mints out-of-band (like `scripts/operator_sign.py`) and an
agent presents on every query. The service, when an operation authority is
**provisioned**, requires a valid scope on all four query routes and enforces
its constraints fail-closed.

### The credential (mirrors `OperatorCommand`)

```
QueryScope {
    graph_name:    str            # authority SCOPE (parallel to tenant_id)
    agent_id:      str            # attribution: who this scope authorizes
    capabilities:  list[str]      # allowed OpKind names; [] = all
    max_results:   int | None     # cap on included+excluded entities (blast-radius)
    not_before:    int            # epoch-nanosecond acceptance floor
    not_after:     int            # epoch-nanosecond expiry (TTL)
    nonce:         int            # replay guard
    operator_id:   str
    pubkey_pem:    str            # for key-free ledger verification (Inv 3)
    sig:           str            # hex(Ed25519) over canonical record
}
```

Signed over canonical `(graph_name, agent_id, capabilities, max_results,
not_before, not_after, nonce, operator_id, pubkey_pem)` — the same
canonicalization discipline as the gateway.

### Verification gate (mirrors `verify_command`)

`verify_scope(scope, *, body, allowlist_pems, used_nonces, now, max_age_s,
graph_name)` — fail-closed, refuses when:
- `graph_name` (the scope) ≠ the query's `graph_name` (**F2 analogue** — a scope
  minted for one graph must never satisfy another),
- `body_hash` of the query body ≠ `scope.body_hash` (scope can't be replayed
  against a different query),
- `nonce` already used (replay),
- `now` outside `[not_before, not_after]` (TTL),
- signature fails against any key on the op-authority allowlist.

### Constraint enforcement (the actual limiter)

After executing the `Op`, the service enforces the scope's constraints
deterministically and inspectably:
- **Capability allowlist:** walk the `Op` tree; if `capabilities` is non-empty
  and any node's `kind` is not in it → reject (403). This is the "category cap".
- **`max_results`:** if set and `(len(included) + len(excluded)) > max_results`
  → reject (403). This is the "max-spend" cap.
- The response carries `scope: {enforced: True, graph_name, agent_id,
  capabilities, max_results}` for audit, exactly like the attestation block.

### Key domain — SEPARATE evidence-operation authority

A **distinct Ed25519 key** from the ADR 30 attestation key and from the gateway
operator keyring, seeded via `RATHNONE_EVIDENCE_OP_KEY_PEM` (file path or inline
PEM). Rationale (mirrors ADR 30's separation discipline): attestation trust and
query-authorization trust have different rotation/revocation lifecycles — you
may want to revoke an agent's query scope without re-rooting evidence trust, and
vice versa. Independent key = independent kill-switch.

**FORK F1 (ratify):** separate op key (recommended) vs reuse the ADR 30
attestation key. See Open Questions.

### Posture when unprovisioned — dormant-until-provisioned

If `RATHNONE_EVIDENCE_OP_KEY_PEM` is **unset**, the operation authority is not
provisioned and scope enforcement is **OFF** — the service stays frictionless
and open for local-first single-operator use (preserves current behavior;
parallel to `RATHNONE_QUERY_API_KEY` and the gateway's dormant-allowlist default).
Scope enforcement activates only when the op key is mounted. This is the same
"dormant until provisioned" pattern as ADR 19/20 and ADR 26.

### Transport

The agent presents the scope in a header `X-Evidence-Scope` carrying the
`QueryScope` JSON (parallel to `X-Control-Plane-Key`). Keeping it out of the
query body leaves `body_hash` a clean binding over the query itself.

**FORK F2 (ratify):** header `X-Evidence-Scope` (recommended) vs a request-body
field. See Open Questions.

### NL binding

For `/query/nl*`, the scope's `body_hash` binds to the **raw NL text** (not the
compiled `Op`) — parallel to the gateway binding `body_hash` to the raw request
body. The capability allowlist is then enforced on the *compiled* `Op` (so an
agent scoped to `MATCH` only cannot smuggle a `CONNECTED_TO` via clever phrasing).

**FORK F3 (ratify):** raw-text binding (recommended) vs compiled-Op binding.

## Implementation sketch (not yet written)

- `src/query/scope.py` (NEW): `QueryScope` dataclass (`canonical_bytes`,
  `verify`, `binds_to`), `EvidenceOpAuthority` (holds the op key; `sign(scope)`),
  `verify_scope` (fail-closed gate), `enforce_constraints(op, scope) -> (ok,
  reason)`. No new deps (reuses `cryptography`).
- `src/query/service.py`: bootstrap `_OP_AUTHORITY` inside `create_app()` from
  `RATHNONE_EVIDENCE_OP_KEY_PEM`; per-instance `_used_scope_nonces: set[int]`;
  a `require_scope(request, body)` dependency on the 4 query routes; pass the
  verified scope into `_run` / `_run_attested` for constraint enforcement; emit
  `scope` audit block.
- `src/query/agent.py`: `KnowledgeAgent` gains an optional `scope` argument on
  `query_nl` / `query_op` (sent as `X-Evidence-Scope`); `examples/agent_harness.py`
  demonstrates: operator mints a scope (via `scripts/evidence_scope_sign.py`),
  agent presents it → success; a query exceeding `capabilities`/`max_results` is
  rejected (403). The `SUMMARY:` line proves the limiter bites.
- `scripts/evidence_scope_sign.py` (NEW): mints a `QueryScope` (parallel to
  `scripts/operator_sign.py`), stamps epoch-ns + canonical `model_dump`.
- `tests/test_query_scope.py` (NEW): signed/verified scope admits in-scope query;
  wrong graph rejected; capability violation rejected (403); max_results
  exceeded rejected; expired/used-nonce/replayed-body rejected; unprovisioned
  service stays open; tamper detection.

## Verification plan

- `tests/test_query_scope.py`: 8-10 cases covering each fail-closed refuse
  branch + the open-when-unprovisioned path.
- `examples/agent_harness.py` runs clean with `SUMMARY: N passed, 0 failed`,
  demonstrating the limiter end-to-end.
- Full tree green (expect 227 + new).

## Status

DRAFT. Not implemented, not committed. Awaits ratification of the three forks
(F1 key separation, F2 transport header, F3 NL binding) and an explicit go.

## Open Questions / Forks to ratify

1. **F1 — Key separation.** (a) *Separate* `RATHNONE_EVIDENCE_OP_KEY_PEM`
   (recommended — independent revocation from attestation trust, mirrors ADR 30
   separation). (b) Reuse the ADR 30 attestation key (simpler, one key, but
   couples attestation trust to query-auth revocation).
2. **F2 — Transport.** (a) `X-Evidence-Scope` header (recommended; clean
   body_hash binding). (b) request-body `scope` field.
3. **F3 — NL binding.** (a) scope `body_hash` over raw NL text (recommended;
   parallel to gateway). (b) over the compiled `Op`.
4. **F4 — Capability default.** `capabilities: []` = allow all (recommended,
   least-surprise for operators minting broad scopes) vs `[]` = deny all.

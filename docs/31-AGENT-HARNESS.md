# ADR 31 — Reference Agent Harness (knowledge-query substrate, end-to-end)

- **Status:** RATIFIED + IMPLEMENTED (2026-08-21)
- **Extends:** ADR 27 (executor) + ADR 28 (compiler) + ADR 29 (service) + ADR 30 (attestation)
- **Depends on:** `src/query/{algebra,executor,compiler,attest,service}.py`

## Context

ADR 27-30 build the knowledge substrate as a service that produces a
**deterministic, reconciliable, attested** `EvidenceRecord`. But a substrate is
only useful if a downstream agent can consume it correctly — and "correctly"
means *never trusting the record on faith*. The missing piece is a reference
client that shows the intended loop: formulate → submit → **verify off-line** →
reconcile. ADR 31 is that reference agent.

## Decision

Add a reusable `KnowledgeAgent` client (`src/query/agent.py`) plus a runnable
`examples/agent_harness.py` demo. The agent encodes the trust discipline:

- **Off-line verification.** On every attested response the agent re-derives the
  `EvidenceRecord` from the JSON and checks the Ed25519 attestation against the
  cached evidence-domain public key (fetched once from `/authority/public-key`).
  Verification does NOT depend on the service being honest at read time.
- **Attested by default.** `query_nl` / `query_op` prefer the `/.../attested`
  routes; plain routes are available for services that don't need attribution.
- **Contract assertion.** The agent can pass `expect_included` / `expect_hash`
  and read back the service's fail-closed `verify()` result (`contract_ok`).
- **Drift detection.** `assert_stable()` re-runs a query and confirms the
  included set is unchanged via `EvidenceRecord.reconcile_with()` — surfaces
  silent knowledge-base movement.
- **Duck-typed transport.** The client takes any `httpx`-like object
  (`TestClient` or `httpx.Client`). The same code runs in-process (tests) or
  against a live deployment — the trust step is identical either way.
- **Independent of the frozen gateway.** `KnowledgeAgent` imports only from
  `src.query`; it never touches `src.service.app` or the finance authz spine.

The runnable harness prints a `SUMMARY: N passed, M failed` line (mirroring the
repo's `tests/poc_findings.py` convention). A non-zero failure count is the
real signal — any `FAIL` means a trust regression.

## Implementation

- `src/query/agent.py` (NEW): `QueryResult` (record + attestation + verdicts),
  `KnowledgeAgent` with `load_graph`, `authority_public_key`, `query_nl`,
  `query_op`, `verify_signature`, `reconcile`, `assert_stable`.
- `src/query/__init__.py`: export `KnowledgeAgent`, `QueryResult`.
- `examples/agent_harness.py` (NEW): end-to-end demo over the real 42KB
  SKC artifact (`RATHNONE_SKC_ARTIFACT` overridable); 8 checks + `SUMMARY:` line.
- `tests/test_query_agent.py` (NEW): 6 integration tests (load, off-line verify,
  op+contract, plain route, drift, reconcile) against the real artifact.
- `docs/31-AGENT-HARNESS.md` (this ADR).

## Status

Full tree green (**227 passed**). `examples/agent_harness.py` runs clean:
`SUMMARY: 8 passed, 0 failed`.

The engine is now a complete, demonstrable, agent-accessible local substrate:

```
agent.formulate() ─┐
                   │  (NL -> compiler -> Op, or a hand-built Op)
                   ▼
        query/nl/attested  ──>  EvidenceRecord + Attestation
                   │
        agent.verify_signature()  ── off-line, against /authority/public-key
                   │
        agent.assert_stable()     ── drift detection via reconcile_with()
```

## Future (deferred)

- Live transport example (`httpx.Client` against a running `uvicorn` instance) so
  the off-line-verification story is demonstrated across a real network boundary.
- An evidence-domain operation scope (ADR 30 follow-on): the agent's query is
  gated by a signed operator scope, parallel to the gateway's ADR 17/20 surface.

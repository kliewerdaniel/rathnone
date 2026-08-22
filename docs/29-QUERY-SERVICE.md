# ADR 29 — Knowledge-Query HTTP Service (agent-accessible substrate)

- **Status:** RATIFIED + IMPLEMENTED (2026-08-21)
- **Extends:** ADR 27 (executor) + ADR 28 (NL compiler)
- **Depends on:** `src/query/{algebra,executor,loader,compiler}.py`

## Context

ADR 27/28 deliver the knowledge engine as a library: an `Op` algebra, a
deterministic executor, an SKC-artifact loader, and an LLM-free NL→`Op`
compiler. The remaining gap for "*an agent system can safely reason*" is a
surface that agent code can call **without importing or understanding
`src/query` internals** — and without the engine being entangled with the
frozen finance/authorization gateway.

## Decision

Add a **separate FastAPI app** (`src/query/service.py`, factory `create_app()`)
exposing the substrate over HTTP:

| Endpoint | Purpose |
|---|---|
| `POST /graphs/load` | load a `KnowledgeGraph` from a local SKC artifact (path on disk) |
| `POST /query/op` | run a query supplied as an `Op.to_dict()` plan |
| `POST /query/nl` | run a query supplied as natural-language text |
| `GET  /health` | liveness probe |

Key constraints:

- **Isolated from the gateway.** The service imports nothing from
  `src.service.app` and never touches the authz spine. The frozen control plane
  (`fleet.epistemic.decide()`) is untouched. Two independent apps, two deploy
  surfaces.
- **"Model constructs, engine executes" enforced structurally.** The service
  accepts only a *query specification* (NL text or `Op` dict) and returns a
  deterministic `EvidenceRecord`. It does not perform open-ended retrieval on
  the caller's behalf.
- **Auditable output.** `/query/nl` echoes the compiled `Op` plan so the caller
  can see exactly what the engine executed. Both query routes accept an optional
  `expect_hash` / `expect_included` / `expect_excluded` contract; the response
  carries the `verify()` result (ok + divergences) — fail-closed reconciliation
  over HTTP.
- **Local-first auth posture.** A control-plane key gate (`X-Control-Plane-Key`)
  activates only if `RATHNONE_QUERY_API_KEY` is set, mirroring the gateway's
  `RATHNONE_ENFORCE_AUTH` posture without modifying the frozen authz code. Left
  open by default for single-operator local use.
- **Process-scoped graph registry.** `POST /graphs/load` populates an
  in-process `name -> KnowledgeGraph` map; queries reference it by name. No
  network egress, no embeddings.

## Implementation

- `src/query/service.py` — `create_app()` + `app` instance; Pydantic request
  models (`LoadRequest`, `OpQueryRequest`, `NLQueryRequest`); `_run()` executes
  and optionally verifies.
- `src/query/executor.py` — added `KnowledgeGraph.entity_count()` /
  `edge_count()` so `/graphs/load` can report provenance stats.
- `src/query/__init__.py` — export `create_app`, `query_service_app`.
- `tests/test_query_service.py` — 6 HTTP tests against the real 42KB
  `research-knowledge-artifact/1.0` (path overridable via
  `RATHNONE_SKC_ARTIFACT`); covers load/missing-artifact/NL-evidence-record/
  `Op`-with-verify-contract / verify-divergence / unknown-graph.

## Status

Full tree green (213 passed). The engine is now a complete, agent-accessible
local substrate:

```
NL text ─┐
         ├─> compiler -> Op tree ─> executor -> EvidenceRecord ─> verify()
Op dict ─┘        (service.py HTTP surface, isolated from finance gateway)
```

## Future (deferred)

- Persistence/eviction for the graph registry (currently process-scoped).
- Optional authz hook so an agent's query is gated by a signed operator scope
  (without touching the frozen gateway — a parallel, evidence-domain key).

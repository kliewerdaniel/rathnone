# ADR 46 — Local MCP surface over the knowledge engine (W3)

**Status:** Proposed (uncommitted — for review)
**Builds on:** `mcp-for-aura` *safety model* (schema-first grounding, Read vs
Read-write separation, per-client scope) — mirrored as a **local stdio MCP
server**; `src/query/service.py` (FastAPI app over `KnowledgeGraph`);
`src/query/scope.py` `QueryScope` (ADR 32); `src/security/operator.py`
`OperatorCommand` + `harness_apply` verb (ADR 43). **Local substrate:**
self-hosted Neo4j (no Aura/cloud) is available on `bolt://127.0.0.1:7687`.
**Range:** Phase 2B.

## Context

`mcp-for-aura` ships a hosted MCP endpoint for Neo4j Aura — FORBIDDEN here
(local-first, no cloud egress). Its **safety model**, however, is exactly what
an agent-facing surface over the knowledge engine needs: (1) `get_schema` to
ground the agent before it queries; (2) `read` = read-only, scoped by an
allowlist + blast-radius limiter; (3) `read_write` = a SEPARATE gated tool.

The repo already has the three primitives for the model: `create_app()` (FastAPI
over `KnowledgeGraph`), `QueryScope` (signed, capability allowlist +
`max_results`), and `OperatorCommand(verb="harness_apply")` (signed operator
gate, ADR 43). **Plus** a local Neo4j server is available, so the MCP tools can
expose the graph both through the existing in-memory service and directly over
the local bolt endpoint under the same signed-scope discipline.

## Decision

- **`src/mcp_local/server.py`** — a local MCP server implementing the MCP
  stdio **transport** (JSON-RPC framed on stdin/stdout), hand-rolled in stdlib
  so it needs **no `mcp` package** (which would be an extra dep; we keep the
  venv's `requirements.txt` frozen and drive the transport ourselves). It
  exposes the skill's three tools:
  - `get_schema(graph_name)` — returns the SKC artifact's node/relationship/
    property shape (entity types, eTLD+1 origins, edge kinds) so the agent is
    grounded before querying. Read-only.
  - `read(query)` — runs a `QueryScope`-constrained read: requires a valid signed
    `QueryScope` (ADR 32); enforces `capabilities` allowlist (mirrors `mcp-for-
    aura` Read safety) + `max_results` blast-radius limiter; returns the
    deterministic `EvidenceRecord`. Fail-closed: no/invalid scope → refuse.
  - `read_write(scope_change)` — SEPARATE tool; gated by a signed
    `OperatorCommand(verb="harness_apply")` (ADR 43), replay-nonce-guarded. A
    real MCP client is **refused write** without a valid signed scope.
- **Per-client scope = existing `QueryScope` (ADR 32).** No new scope concept.
- **Evidence-domain keying stays SEPARATE** from the gateway keyring and from
  ADR 30/34/35/36 evidence trust (ADR 32 F1 analogue preserved).
- **Optional local-Neo4j backing:** if `RATHNONE_NEO4J_URI` is set (pointing at
  `bolt://127.0.0.1:7687`), the `read` tool MAY additionally mirror the served
  record into the local graph via `cypher-no-data-loss` empty-safe writes — but
  this is opt-in and never required for the tool to function; the in-memory
  `KnowledgeGraph` remains the source of truth for query execution.

## Constraints

- **Local-first / no cloud:** stdio only, no network server, no Aura, no
  `neo4j.io` remote URL. `grep` of the diff for `aura`/remote MCP must be empty.
- **Stdlib transport:** hand-rolled JSON-RPC over stdio — **no `mcp` dependency**.
  (The `neo4j` driver is permitted only for the opt-in local-graph mirror and is
  already installed; it talks to localhost only.)
- **Fail-closed:** `read` without a valid signed `QueryScope` → refused;
  `read_write` without a valid signed `OperatorCommand(harness_apply)` → refused;
  unreachable/unprovisioned → refuse.
- **Invariant 1 untouched** — the MCP server only drives `QueryExecutor` +
  `QueryScope` + `OperatorCommand`; never imports `decide()`.
- **Provenance/reproducible** — every `read` verdict reproducible from
  (graph, query, scope); no RNG/model/network (Invariant 3).

## Implementation

- `src/mcp_local/server.py` — stdio JSON-RPC MCP server, `get_schema`/`read`/
  `read_write`.
- `tests/test_mcp_local_stdio.py` — boots the server over a real stdio transport
  (in-process pipe loop), as a real MCP client: schema-grounds, runs a `read`
  with a valid signed scope (ALLOW), and is **refused write** without a signed
  `harness_apply` command. Live-discipline: exercised over the actual stdio
  transport, not a mock.

## Acceptance

1. A real MCP client connects over stdio, calls `get_schema`, gets a grounded
   shape, then runs `read` with a valid `QueryScope` → ALLOW (blinded by
   capability + `max_results`).
2. The same client calling `read_write` WITHOUT a signed `OperatorCommand` is
   refused (fail-closed).
3. `pytest tests/test_mcp_local_stdio.py -q` → green.
4. `grep -rEi 'aura|neo4j\.io|https?://[^ ]*mcp[^ ]*' src/mcp_local` → empty
   (localhost bolt URI allowed).

## Verification

- `env -u PYTHONPATH -u VIRTUAL_ENV .venv/bin/python -m pytest tests/test_mcp_local_stdio.py -q`

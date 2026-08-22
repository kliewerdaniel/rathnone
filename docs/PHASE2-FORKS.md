# Phase 2 fork-ratification register (REVISED — real local substrate)

The four upstream skills assume a **hosted / cloud substrate** (Neo4j Aura, NAMS,
Semvec + remote Neo4j). The mandate forbids **cloud/Aura/hosted**, but the user
explicitly confirmed **self-hosted local Neo4j is in-scope** — and a real one is
**already running**: `bolt://127.0.0.1:7687` (Neo4j 2025.11.2, localhost-only,
auth `neo4j`/`neo4j`), with **Ollama `nomic-embed-text`** (768-d) on
`http://127.0.0.1:11434`. So W3/W4 use **real local** Neo4j + local embeddings.
W1/W2 stay stdlib-only (no substrate needed). All four clear the usefulness
filter (each adds real functionality to the multi-agent harness / evidence audit).

## Fork table (RATIFY before code)

| # | Skill | Upstream substrate | Local mirror (this repo) | New dep? | Status |
|---|-------|--------------------|--------------------------|----------|--------|
| F1 | `nams-skill-distillation` | Neo4j NAMS context graph | `docs/*.md` ADR files + `scripts/distill_skill.py` (stdlib markdown distillation) | **No** | ☐ ratify |
| F2 | `cypher-no-data-loss` | Cypher / Neo4j aggregation | in-memory `KnowledgeGraph` comprehensions + `assert` cardinality (`src/query/audit.py`) | **No** | ☐ ratify |
| F3 | `mcp-for-aura` | hosted MCP-for-Aura + OAuth | **local stdio JSON-RPC MCP** over `create_app()` + `QueryScope`/`OperatorCommand`; optional local-Neo4j mirror | **No** (`mcp` pkg NOT used; `neo4j` driver opt-in, localhost) | ☐ ratify |
| F4 | `cypher-no-data-loss` (graph store) | Neo4j | W2 applies principle to in-memory graph (no store invented); W3/W4 MAY use the real local Neo4j (`bolt://127.0.0.1:7687`) under signed scope | **No** (driver already installed) | ☐ ratify |
| F5 | `semvec-neo4j-memory` | Semvec (768-d) + Neo4j | **real local Neo4j** + **local Ollama `nomic-embed-text`** embeddings → dynamic persona MoE GraphRAG | **neo4j driver only** (installed); no `semvec`/`sentence_transformers`/`numpy` | ☐ ratify |

## Ratified forks (fill in after user sign-off)

- **F1** — distill from `docs/` markdown, not Neo4j. Provenance = per-ADR content
  hash + captured-at date, enforced by a governance test. [ ]
- **F2** — apply empty-safe-anchor principle to the in-memory `KnowledgeGraph`;
  do NOT add a graph store. [ ]
- **F3** — local stdio MCP, hand-rolled JSON-RPC (no `mcp` package); Read vs
  Read-write split + signed-scope gating; optional localhost-Neo4j mirror. [ ]
- **F5** — W4 is a **real local GraphRAG**: persona mixture-of-experts over local
  Neo4j + local Ollama embeddings; `INVESTIGATED`/`:LiteralFact`/`is_drift`/
  QUARANTINE preserved. [ ]

## Hard constraints (unchanged)

- **No cloud / no Aura / no remote URL.** Localhost-only. `grep` diff for
  `neo4j.io`/Aura/remote MCP → empty.
- **Invariant 1** — none of W1–W4 imports or modifies `fleet.epistemic.decide()`.
- **Fail-closed** — every new gate defaults to REFUSE; unreachable/unprovisioned
  ⇒ refuse. W4 memory is opt-in (`RATHNONE_HARNESS_MEMORY_URI`), disabled ==
  stateless pass-through.
- **Reproducible / provenance** — verdicts reproducible from (graph, record) +
  policy; verbatim ADR ids byte-exact; evidence keying separate from gateway.

## Blocking conditions (would require NEW user ratification)

- Adding `mcp`, `semvec`, `sentence_transformers`, or `numpy` to
  `requirements.txt` → FORBIDDEN unless user explicitly ratifies. (W3 hand-rolls
  the MCP transport; W4 uses local-Ollama HTTP, not a Python embedding lib.)
- Any `neo4j.io` / Aura / remote-MCP URL in the diff → FORBIDDEN.

## Verification gate (per mandate)

- `env -u PYTHONPATH -u VIRTUAL_ENV .venv/bin/python -m pytest` green.
- Each new gate proven fail-closed.
- `grep -rEi 'aura|neo4j\.io|https?://(?!127\.0\.0\.1|localhost)' src/ docs/ tests/ scripts/` → empty.
- User is final verification for anything UI-only.

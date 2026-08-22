# ADR 47 — Local persistent harness memory: dynamic persona MoE GraphRAG (W4)

**Status:** Proposed (uncommitted — for review)
**Builds on:** `semvec-neo4j-memory` (constant-token-cost semantic memory +
`INVESTIGATED` audit edge + verbatim `LiteralFact` + combined `is_drift` rule +
anchors/QUARANTINE). Realized on **self-hosted local Neo4j** (`bolt://127.0.0.1:
7687`, localhost-only — NOT Aura/cloud) + **local Ollama `nomic-embed-text`**
(`:11434`, 768-d) for embeddings. ADR 41–43 harness (`HarnessAuthorizer`,
`OperatorCommand`, `examples/harness_loop.py`). ADR 40 anchoring/QUARANTINE.
**Range:** Phase 2C.

## Context

`semvec-neo4j-memory` gives a multi-agent system persistent, constant-token-cost
memory backed by Neo4j: an `INVESTIGATED` audit edge from each `(:AgentSession)`
to the domain entities it touched, verbatim `LiteralFact` nodes (byte-exact,
never embed-compressed), and a combined drift rule (`is_drift`) that flags an
off-domain query. The skill assumes a hosted Neo4j + the Semvec embedding engine.

**Reframe — this is the useful one.** You want **local dynamic persona mixture-
of-experts GraphRAG** for Rathnone: a persistent memory graph where each harness
session is a persona, each ratified ADR / capability / file is an expert node,
and a query is routed to the relevant persona/expert mixture by semantic
similarity over **local** embeddings. Local Neo4j + local Ollama embeddings
deliver exactly this with **zero cloud**:
- Neo4j 2025.11.2 is **already running** on `localhost:7687` (verified: bolt
  reachable, `neo4j`/`neo4j` auth, Cypher 5; `neo4j` Python driver installed at
  5.27.0).
- Ollama on `:11434` serves `nomic-embed-text` (768-d) — real embeddings, no
  `sentence_transformers`/`numpy` needed in the venv.

So W4 becomes a **real local GraphRAG memory layer**, not a `difflib`
approximation. The Semvec capabilities (INVESTIGATED edges, verbatim facts, drift,
QUARANTINE) are all expressible in Cypher on the local instance.

## Decision

1. **`src/harness/memory.py` — `HarnessMemory` backed by local Neo4j.**
   - `(:AgentSession)-[:INVESTIGATED]->(:AdrRef|:CapabilityRef|:FileRef)` edges,
     edge `extra` carrying `query_preview`, `top_similarity`, `drift_phase`,
     `started_at`, `duration_ms` (the Semvec `INVESTIGATED` payload).
   - `:LiteralFact` nodes via `(:AgentSession)-[:EXTRACTED]->(:LiteralFact)` with a
     unique `(session_id, key)` upsert; **byte-exact** facts (ADR ids `ADR-\d+`,
     `deterministic_hash` sha256 hex, ed25519 sig hex) extracted by regex — never
     embed-compressed.
   - Every `:SemanticState` node carries a 768-d vector from local Ollama; a Neo4j
     5.11+ vector index on `SemanticState.vector` gives constant-cost retrieval
     (one operational system, like the skill's "use the vector index, not a
     separate store").
2. **Persona mixture-of-experts routing.** Each harness session is a persona
   (`(:Persona {id, role})`). Ratified ADRs/capabilities are `:Expert` nodes. A
   harness query is embedded locally (Ollama) and a Cypher vector-search returns
   the top-k relevant personas/experts → the "mixture" the session consults.
   Drift = low `top_similarity` to the persona's anchored context.
3. **Drift detection (combined rule, ported faithfully):**
   ```python
   def is_drift(result: dict) -> bool:
       if result.get("drift_detected"): return True
       return result["drift_score"] >= 0.35 and result["top_similarity"] <= 0.45
   ```
   Real `top_similarity` from the local embedding (no stand-in).
4. **QUARANTINE (prompt-injection guard, mirrors ADR 40).** Anchor a session to
   its ratified-ADR persona context; an injected off-domain query (drift flagged)
   is QUARANTINED before any downstream action and the harness BLOCKED — wired
   into the ADR 16/24 hygiene gate (drift → BLOCKED).
5. **`examples/harness_memory_demo.py`** boots two sessions, records
   investigations + extracts verbatim ADR ids, persists to local Neo4j, then
   proves: (a) a fresh session seeded from Neo4j retrieves prior ratified-ADR
   context with `top_similarity > cold-start baseline`; (b) an injected
   off-domain query is quarantined; (c) verbatim ADR ids survive a probe
   byte-exact.

## Constraints

- **Local-first / no cloud:** `bolt://127.0.0.1:7687` + `http://127.0.0.1:11434`
  only. No `neo4j.io`, no Aura, no remote embedding API. `grep` diff for
  `neo4j.io`/Aura/remote URL → empty.
- **Local embeddings via Ollama** — the `neo4j` driver is the only new *runtime*
  dep (already installed in the venv); no `semvec`/`sentence_transformers`/
  `numpy`. Embedding is an HTTP call to **localhost**, not a model import.
- **Invariant 1 untouched** — memory layer only writes audit edges/facts into
  the harness's own Neo4j graph; never imports or calls `decide()`.
- **Provenance/reproducible** — fact extraction is byte-exact regex; drift is
  deterministic from the embedding. No RNG in verdicts (Invariant 3). The single
  network call is the local Ollama embed (localhost, offline-capable).
- **Fail-closed** — a query flagged drifting is quarantined → harness BLOCKED;
  if the local Neo4j/Ollama is unreachable, the harness falls back to cold-start
  (refuse-with-context-loss signal), never assuming warm context.
- **Opt-in / gated** — W4 memory is enabled by `RATHNONE_HARNESS_MEMORY_URI`
  (defaults unset ⇒ harness runs stateless, unchanged). Disabled == pure
  pass-through, so existing suites are unaffected.

## Implementation

- `src/harness/memory.py` — `HarnessMemory` (Neo4j 5.27 driver), `record_investigation`,
  `extract_facts`, `store_facts_as_entities`, `is_drift`, `set_isolation`/
  quarantine, local-Ollama embed helper.
- `examples/harness_memory_demo.py` — two-session GraphRAG demo.
- `tests/test_harness_memory_local.py` — pytest against the **real local** Neo4j
  + Ollama (skipped if either is down, so CI without local infra still runs the
  in-memory-fallback assertions). The three acceptance checks above.

## Acceptance

1. A fresh session seeded from local Neo4j retrieves prior ratified-ADR context
   with `top_similarity` strictly greater than a cold-start baseline.
2. An injected off-domain query is QUARANTINED (drift flag → BLOCKED), does not
   reach a downstream action.
3. Verbatim ADR ids (e.g. `ADR-43`) survive a memory probe byte-exact
   (`extract_facts` round-trips via `:LiteralFact`).
4. `pytest tests/test_harness_memory_local.py -q` → green (real local Neo4j +
   Ollama; in-memory fallback path asserted when infra absent).

## Verification

- `env -u PYTHONPATH -u VIRTUAL_ENV .venv/bin/python -m pytest tests/test_harness_memory_local.py -q`
- `env -u PYTHONPATH -u VIRTUAL_ENV .venv/bin/python examples/harness_memory_demo.py`
- `grep -rEi 'aura|neo4j\.io|https?://(?!127\.0\.0\.1|localhost)' src/harness memory.py` → empty.

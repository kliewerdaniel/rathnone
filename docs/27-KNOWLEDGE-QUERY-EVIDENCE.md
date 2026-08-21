# 27 — Deterministic Knowledge-Query & Evidence Engine

**Status:** RATIFIED direction (local, uncommitted). Additive submodule `src/query/`.
**Date:** 2026-08-21.

## Thesis
Move semantic retrieval and logical constraint evaluation OUT of the
probabilistic inference layer and INTO a deterministic knowledge-execution
layer. An LLM *constructs* a logical query; Rathnone *compiles and executes*
it deterministically and returns an inspectable **evidence record**.

This makes agent reasoning auditable: instead of "the vector DB returned these
chunks", an agent can assert "I believe X because these pieces of evidence
satisfy these predicates."

## Why here (not a new repo, not SKC/SIS)
- **Rathnone's existing strength** is deterministic, provenance-bearing,
  fail-closed verification (`src/evidence/chain.py`, `src/hygiene/__init__.py`).
  The evidence-engine discipline is already in this repo; we extend it.
- **SKC / SKCEx** own *knowledge compilation* (docs → facts/decisions/graph).
  Rathnone does NOT duplicate that — it consumes a graph and answers "what does
  the knowledge actually support?"
- **SIS** owns vector GraphRAG; **SovereignSpec** owns a typed graph engine
  (impact analysis). Neither defines a *composable query algebra* with an
  inspectable evidence output. That algebra is the genuine gap this fills.

## Architecture
```
natural language ──▶ logical query (Op tree, built by LLM)
                         │
                         ▼
                   ┌──────────────┐
                   │ QueryExecutor │  deterministic, stdlib-only
                   └──────────────┘
                         │  over
                         ▼
                  KnowledgeGraph (entities + typed edges)
                         │
                         ▼
                  EvidenceRecord:
                    • included  (id, reasons, predicates, source)
                    • excluded  (id, reasons, predicates, source)
                    • plan      (human-readable execution steps)
                    • deterministic_hash()
```

The LLM is responsible for *constructing* the query (Op.to_dict() → JSON),
never for *deciding* whether it executed correctly. Rathnone reconstructs it
(`Op.from_dict`) and executes.

## Operators (first-class executable algebra)
Boolean: `AND OR NOT`
Entity:  `TYPE SOURCE MATCH SCORE TIME`
Graph:   `CONNECTED_TO DERIVED_FROM SAME_AS PATH` (depth-scoped, typed edges)
Ranking: `NEAR` (keyword-neighborhood, deterministic, no embeddings)

`NEAR`/`SCORE`/`TIME` annotate and filter; they never introduce
nondeterminism. Vector retrieval (SIS) plugs in later as a leaf operator.

## Invariants (proven by tests/test_query_evidence.py)
1. **Algebra laws** — AND/OR associativity, De Morgan (`NOT(AND)==OR(NOT,NOT)`),
   double-negation, idempotence. Pure deterministic checks, no LLM.
2. **Evidence completeness** — every entity (included OR excluded) carries ≥1
   reason + ≥1 predicate tag. No silent drops.
3. **Reproducibility** — identical (graph, query) ⇒ byte-identical
   `deterministic_hash()`, independent of insertion order.
4. **Adversarial inclusion/exclusion** — the gradient-descent example
   (exclude arXiv-primary, require convex-linked) returns the correct single
   paper with stated reasons.
5. **Graph semantics** — `CONNECTED_TO`/`DERIVED_FROM`/`SAME_AS` respect edge
   kind; `PATH` is shortest-path existence.

## Out of scope (explicitly NOT Rathnone)
- Authorization of agent actions → `sovereign-agent-fleet` (`decide()`).
- Knowledge compilation → SKC/SKCEx.
- Agent execution → Sovereign Worker.
- Generic agent framework.

Rathnone answers ONE question: **"What does the available knowledge actually
support?"** — deterministically and inspectably.

## Files
- `src/query/algebra.py` — typed, serializable Op IR + factories.
- `src/query/executor.py` — KnowledgeGraph, EvidenceRecord, QueryExecutor.
- `src/query/__init__.py` — public API.
- `tests/test_query_evidence.py` — 15 property + behavioral + adversarial tests.

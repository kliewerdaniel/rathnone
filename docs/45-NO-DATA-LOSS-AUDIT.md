# ADR 45 — No-data-loss audit traversal (W2)

**Status:** Proposed (uncommitted — for review)
**Builds on:** `src/query/executor.py` (`KnowledgeGraph`, in-memory dict+adjacency),
`src/query/purify.py` (ADR 40 source-corroboration), `src/query/service.py`,
`scripts/evidence_witness_verify.py`, `scripts/evidence_key_log.py`.
**Range:** Phase 2A (methodology hardening, no new infra).

## Context

`cypher-no-data-loss` warns about the silent-row-drop failure mode: a
MATCH/aggregation that anchors on a *relationship* instead of the *entity* drops
any entity with zero related rows. The repo's graph is the in-memory
`KnowledgeGraph` (`executor.py:53`, `_ents: dict[id, Entity]` + `_adj: dict[id,
list[Edge]]`). So we apply the *principle* to the in-memory traversals: **anchor
on the entity collection, gather joined/optional data via comprehensions that
may come back empty**, and **assert result cardinalities** so a missing row looks
like an error, not a small result.

**Why this ADR earns its keep:** the evidence witness/key-log replay tooling
(`scripts/evidence_witness_verify.py`, `evidence_key_log.py`) is operator-facing
audit output. A silently-dropped served record is a real audit-integrity bug, not
a theoretical one. The fix adds a cardinality guarantee to that replay path.

The audit/replay paths most at risk:
- `purify.py` distinct-origin quorum — an entity retained from a single origin
  must still appear in the verdict (it does: `POISONED`); any *aggregation* over
  retained/excluded sets must not drop a zero-origin entity.
- `scripts/evidence_witness_verify.py` / `evidence_key_log.py` — operator replay
  enumerating served records / key rotations; an entity or record with zero
  witness entries must survive the enumeration.

## Decision

1. Add `src/query/audit.py` with an **anchor-first** helper:
   `enumerate_entity_event_counts(graph, witness_log) -> list[EntityAudit]`.
   Iterates `graph.all()` (every entity, zero excluded) and, for each, computes
   optional subcounts (`witness_hits`, `scope_hits`) via list comprehensions over
   the log — returning `0` when none match, never dropping the row. Plus
   `assert_audit_cardinality(results, graph)` which raises if
   `len(results) != graph.entity_count()` (the cardinality assertion the skill
   demands: `User (3)`, not `User (2)`).
2. Extend `scripts/evidence_witness_verify.py` with a `--graph` option that loads
   a `KnowledgeGraph` and asserts the witness enumeration covers every entity
   (anchor-first), reporting isolated entities with `event_count=0`.

## Constraints

- **No graph store invented.** The in-memory `KnowledgeGraph` is the only store;
  we apply the empty-safe *principle* to it. (W3/W4 may add local Neo4j, but W2
  stays in-memory — lowest risk, no new infra.)
- **Stdlib only**, no new dependency.
- **Invariant 1 untouched** — purely additive audit helpers; no `decide()` import.
- **Fail-closed / honest** — a cardinality mismatch is a hard error, never a
  silently truncated result.

## Implementation

- `src/query/audit.py` — `EntityAudit`, `enumerate_entity_event_counts`,
  `assert_audit_cardinality`.
- `scripts/evidence_witness_verify.py` — `--graph` anchor-first enumeration.
- `tests/test_no_data_loss_audit.py` — graph with an **isolated entity** (no
  edges, never queried) + a witness log that doesn't mention it; asserts
  `enumerate_entity_event_counts` still returns it with count `0` and
  `assert_audit_cardinality` passes.

## Acceptance

1. An entity with zero edges and zero witness entries still appears in the audit
   enumeration (cardinality preserved).
2. `assert_audit_cardinality` catches a dropped entity (truncated result → guard
   raises).
3. `pytest tests/test_no_data_loss_audit.py -q` → green.

## Verification

- `env -u PYTHONPATH -u VIRTUAL_ENV .venv/bin/python -m pytest tests/test_no_data_loss_audit.py -q`

# ADR 28 — Natural-Language → Query-Algebra Compiler (deterministic, LLM-free)

- **Status:** RATIFIED + IMPLEMENTED (2026-08-21)
- **Extends:** ADR 27 (deterministic knowledge-query + evidence engine)
- **Depends on:** `src/query/algebra.py`, `src/query/executor.py`

## Context

The strategic thesis for Rathnone's local evolution is that an LLM should
**construct a query**, not be responsible for whether the query was correctly
executed. ADR 27 delivered the deterministic half of that contract: the
`Op` query-algebra IR and an executor that emits an inspectable `EvidenceRecord`.
The missing half was the front door — turning a natural-language request into a
compilable `Op` tree.

The canonical motivating query (from the user directive):

> "Find research about gradient descent that discusses optimization, exclude
> papers whose primary source is arXiv, and prioritize papers connected to convex
> optimization."

The interesting engineering question is **how Rathnone compiles that**, not how
an LLM would answer it. The compiled form is:

```python
And(
    Match("gradient descent"),
    Match("optimization"),
    Not(Source("arxiv")),
    ConnectedTo(Match("convex optimization"), depth=2),
)
```

## Decision

Add a **deterministic, dependency-free NL→`Op` compiler** (`src/query/compiler.py`):

- **LLM-free regex scanning**, no network/embeddings. Identical input ⇒ identical
  `Op` tree (a property asserted by `test_compile_is_deterministic`).
- **Constrained, inspectable grammar.** Each recognized connector maps to
  exactly one algebra operator; unknown input raises `CompileError` rather than
  silently degrading. The compiled plan is auditable before execution.
- **Composition handled correctly.** `but not connected to X` compiles to
  `Not(ConnectedTo(Match("X")))` — a connector that is the *object* of an
  exclusion is wrapped, not consumed as trailing text and dropped (the failure
  mode that the first implementation produced).
- **Output is pure `Op` IR**, so it round-trips through `Op.to_dict()` /
  `Op.from_dict()` — an agent emits the dict, Rathnone reconstructs it, and the
  executor proves which knowledge supports the claim.
- **Scope discipline preserved:** the model that *phrases* the request never
  *executes* the retrieval. Compilation and execution are separate, auditable
  stages.

## Connector → Operator mapping

| NL cue | Operator |
|---|---|
| exclude … primary source is X / source is X | `Not(Source(X))` |
| exclude / except / but not | `Not(...)` |
| from / published in | `Source(X)` |
| connected to / related to | `ConnectedTo(Match(X), depth=2)` |
| derived from | `DerivedFrom(Match(X))` |
| same as | `SameAs(Match(X))` |
| near / close to | `Near(X)` |
| score at least N | `ScoreAtLeast(N)` |
| after / since N | `TimeRange(lo=N)` |
| before / until N | `TimeRange(hi=N)` |
| of type / kind | `Type(X)` |
| about / regarding / on | `Match(X)` |
| that discusses / mentions / covers | `Match(X)` |

## Implementation

- `src/query/compiler.py` — `QueryCompiler.compile(text) -> Op`, `compile_query`
  convenience, `CompileError`. Ordered regex scan with a position-based parse so
  negations can capture a following connector as their object.
- `tests/test_query_compiler.py` — 9 tests: the gradient-descent example
  compiles and executes to the expected inclusion/exclusion; determinism;
  round-trip through `Op.from_dict`; single-topic; `NOT(ConnectedTo)`; source/
  score/time connectors; empty-input `CompileError`; command-verb stripping.

## Status

Integrated into `src/query/__init__.py`; full tree green (207 passed). The
engine now spans the full local-substrate pipeline:

```
NL request → Op tree (compiler) → executor → EvidenceRecord → verify()/reconcile
```

Next most-valuable step (deferred): a thin service endpoint that accepts an
`Op.to_dict()` (or NL) and returns the `EvidenceRecord`, so an agent system can
call the substrate over HTTP without any knowledge of `src/query` internals.

# ADR 48 — News Evidence Surface (objective news corroboration)

- **Status:** RATIFIED + IMPLEMENTED
- **Series context:** ratifies folding a *news* evidence surface into Rathnone using the
  existing knowledge-query + corroboration + witness machinery — no new trust logic.
- **Extends:** ADR 27 (query engine / `EvidenceRecord`), ADR 30/34/35 (evidence attestation +
  witness/trust logs), ADR 40 (distinct-origin corroboration quorum), ADR 42/43/47 (harness
  loop + drift-gated memory).
- **Depends on:** `src/query/` engine, `src/query/purify.py`, `src/service/`, `src/harness/`.
- **Invariant 1 preserved:** zero changes to `fleet.epistemic.decide()`.

## Context

The operator wants to "chat with the news" and get an *objective* view — built on the same
infrastructure already used for research artifacts (ADR 27–40) and finance prices (ADR 17–26) —
that judges the *truthfulness* of news by corroboration across independently-originated sources,
and that any agent harness can embed.

Key realization: **the truthfulness-judging machine already exists.** ADR 27 executes a
deterministic query; ADR 40 runs the distinct-origin corroboration quorum (eTLD+1 collapse, ≥N
independent outlets before a retained set is "corroborated," `POISONED` on single-source /
self-contradictory). ADR 34/35 hash-chain who-served-what-when. News is therefore **a new
loader** that turns RSS/Atom/JSON feed pulls into the same `ConceptGraph` the SKC loader consumes;
everything downstream runs unchanged. The new code is small: `src/news/ingest.py` (feeds →
snapshot → `KnowledgeGraph`) + a thin `NewsAgent` wrapper + a harness loop.

## Decision (forks ratified with user — "all good")

- **N1 truth scope = corroboration + consistency only (no model).** The verdict states
  "N outlets agree / 1 source un-corroborated / outlets diverge." It does **NOT** claim
  world-truth. This is the only version where every verdict is reproducible from
  `(graph, query) + policy` and signable — the codebase thesis.
- **N2 egress = explicit opt-in, fail-closed.** `RATHNONE_NEWS_ENABLED=0` default; feeds are
  operator-configured URLs (no bundled defaults); unset config ⇒ no news surface. Localhost-only
  if any embedding assist is later added (N5=b). No cloud egress.
- **N3 placement = `src/news/` loader feeding existing `src/query/` unchanged.** New code:
  `ingest.py` (feeds → snapshot → `KnowledgeGraph`), `agent.py` (`NewsAgent` wrapping
  `KnowledgeAgent`), one service route. Executor, `PurificationLayer`, witness/trust logs, and
  harness loops are reused verbatim.
- **N4 first surface = Python `NewsAgent` + harness loop.** Reuse `harness_loop.py` /
  `harness_memory_loop.py`; the Next.js console "News" panel is a later cosmetic additive.
- **N5 story grouping = deterministic normalized-key (v1).** `story_key` = sorted, lowercased,
  punctuation-stripped top-N named entities. Articles sharing a `story_key` are the "same story";
  corroboration/variance is computed per `story_key`. Embedding-assisted clustering (N5=b) is a
  later additive behind an opt-in flag; not in v1.

## Data model

A feed pull is frozen into a **snapshot** at time `T`, hash-chained into the witness log. Each
article becomes:

- `document` entity: `id`, `source` (registrable outlet domain, e.g. `bbc.com`), `title`,
  `published`, `url`, `text`
- `concept` entities: extracted named entities / key tokens per article
- edges: `COVERS` article → concept; `OUTLET` article → source

Produced via `graph_from_news_snapshot()` in `src/news/` (does **NOT** patch
`src/query/loader.py`), yielding the same `Entity` / `Edge` / `KnowledgeGraph` shape.

## Corroboration (reuses ADR 40 verbatim)

`PurificationLayer` collapses subdomains to eTLD+1 and counts **distinct outlets**. So:

- 3 articles on one `story_key` from `ap.org`, `bbc.com`, `reuters.com` → **3 distinct →
  CORROBORATED**.
- 1 article from `sputnik.com` → **1 → POISONED / un-corroborated**.
- `ap.org` + `ap.com` → collapse to one origin (ADR 40 `_etld1`).

No new corroboration code. We just feed it a news graph.

## Divergence (v1 unit)

Per `story_key`, when ≥2 distinct outlets share it but their extracted attributes disagree on a
key field (e.g. one "died", the other "survived"), emit a `divergent` block listing per-outlet
conflicting details. Framed as *"outlets A and B report the same event with conflicting details"*
— **not** a truth claim.

## Verdict shape (the honest output)

```
story_key: "gaza-ceasefire"
  outlets: [ap.org, bbc.com, reuters.com]   # 3 distinct → CORROBORATED
  consensus: [shared entity/claim set]
  divergent: { ap.org: [...], bbc.com: [...] }   # where they disagree
  poison: { verdict: CLEAN, reasons: [...] }
---
story_key: "nato-disband"
  outlets: [sputnik.com]   # 1 → UN_CORROBORATED
  poison: { verdict: POISONED, reason: single_origin }
```

This is what `NewsAgent` returns and what the harness "speaks." No "True/False." Only
"N outlets agree, here's where they diverge, here's what only one says."

## Flow (reuses harness infra)

```
feeds (operator-configured, opt-in)
  → src/news/ingest.py → frozen snapshot → KnowledgeGraph
  → QueryExecutor (ADR 27) → EvidenceRecord
  → PurificationLayer (ADR 40) → CLEAN/POISONED + divergence
  → witness/trust log (ADR 34/35)
  → NewsAgent.accept() narrows on poison verdict (ADR 31/40)
  → harness_loop + harness_memory_loop (ADR 42/43/47)
     "chat with the news", drift across snapshots (today vs yesterday's framing)
```

## Invariants preserved

- **Inv1:** `decide()` untouched.
- **Local-first:** fetch opt-in, no bundled feeds, localhost-only if Ollama added.
- **Fail-closed:** no feed config ⇒ no surface; un-corroborated ⇒ stamped, never assumed-true;
  verdict reproducible from `(graph, query) + policy`.
- **Honesty:** verdict states corroboration/divergence, never world-truth.

## What v1 explicitly is NOT

- Not claim-level fact-checking (no external oracle).
- Not sentiment / spin labeling (that's N5=b, a later additive).
- Not a recommendation engine.

## Consequences

- **Positive.** A new evidence surface with zero new trust logic — it reuses the proven ADR 40
  quorum. Any agent harness can embed `NewsAgent` and "chat with the news."
- **Positive.** Reproducible + signed verdicts (witness/trust log hash-chain).
- **Cost.** v1 `story_key` is coarse (groups only when outlets name the same entities). N5=b
  (embeddings) is the known fix and is deferred.

## Verification

- `tests/test_news_*.py`:
  - snapshot parse from RSS/Atom/JSON fixtures;
  - `graph_from_news_snapshot()` builds `Entity`/`Edge` graph;
  - `story_key` grouping (same entities → same key; subdomains collapse to one outlet);
  - ADR 40 quorum over news outlets (diverse → CLEAN, single → POISONED, `ap.org`+`ap.com` → 1);
  - divergence detection (shared `story_key`, conflicting attribute → divergent block);
  - witness-log hash chaining of the served snapshot;
  - `NewsAgent.accept()` narrows on `POISONED`.
- Full suite stays green (news off by default; no regression to finance / query surfaces).

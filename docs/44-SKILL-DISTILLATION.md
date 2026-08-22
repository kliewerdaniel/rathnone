# ADR 44 — Methodology hardening: ADR → portable SKILL distillation (W1)

**Status:** Proposed (uncommitted — for review)
**Builds on:** repo ADR convention (`docs/00-INDEX.md`, ADRs 41–43 harness consumer), the fork-ratification discipline from the Phase-2 mandate.
**Range:** Phase 2A (methodology hardening, no new infra, lowest risk).

## Context

The harness accumulates a large, hard-won decision surface across ADRs 17–47
(the frozen-spine invariants, fail-closed gates, evidence-domain keying, the
harness/`decide()` consumer contract). Today that surface is **recall**, not
**capability**: a future sub-agent (Hermes/Codex) can read the ADRs but is not
handed the *procedure* to ratify the next one, nor is there a governance loop
that forces re-distillation when an ADR/invariant moves. This is exactly the gap
`nams-skill-distillation` closes — but the skill assumes a Neo4j NAMS graph.

**Why this ADR earns its keep (usefulness filter):** the multi-agent harness
(ADR 41/42/43) dispatches Codex sub-agents that must comply with the ratify-an-
ADR procedure *without re-reading 40 ADRs*. Distillation is the load-bearing
handoff. We realize it on the **local filesystem** (`docs/*.md`) — no Neo4j
needed for W1, which keeps it the lowest-risk, highest-leverage item.

## Decision

- `scripts/distill_skill.py` exposes `distill_adrs(adr_ids, out_path, *,
  captured_at=None) -> Path`. Reads each referenced ADR markdown from `docs/`,
  extracts the load-bearing procedural sections (`## Decision`, `## Exit
  criteria`/`## Acceptance`, `## Constraints`) and emits a portable, loadable
  `SKILL.md` with standard frontmatter (`name`, `description` starting
  "Use when…", `version`, `metadata.hermes.tags`).
- Every distilled skill carries a **`## Provenance`** block citing, per source
  ADR: the ADR id, a sha256 content hash of the *source file at distill time*,
  and a `captured-at` date — traceable to the exact memory slice.
- **Governance / re-distill trigger:** `tests/test_distill_governance.py`
  recomputes the per-source content hashes and asserts they equal the values in
  the skill's `## Provenance` block. Editing a referenced ADR diverges the
  hashes → the test FAILS → forcing a re-distill instead of a stale skill
  persisting silently. (Local mirror of the skill's "re-distill when memory
  moves" loop, realized as a CI gate.)
- **One real distilled skill ships:** `skills/ratify-an-adr/SKILL.md`, distilled
  from the repo's ADR convention + the Phase-2 fork-ratification discipline
  (ADRs 41–43 + `docs/PHASE2-FORKS.md`).

## Constraints (non-negotiable)

- **Stdlib only** — no `neo4j`, no `mcp`, no `semvec`, no new dependency.
- **Invariant 1 untouched** — pure documentation tooling; never imports `decide()`.
- **Reproducible** — `distill_adrs` is deterministic (sorted ADR ids, stable
  section extraction). Same inputs → byte-identical `SKILL.md`.
- **Provenance mandatory** — a distilled skill without a traceable `## Provenance`
  block is rejected by the governance test.

## Implementation

- `scripts/distill_skill.py` — `distill_adrs(...)` + `main()` CLI.
- `skills/ratify-an-adr/SKILL.md` — the real distilled skill.
- `tests/test_distill_governance.py` — determinism + provenance traceability +
  re-distill governance trigger.

## Acceptance

1. Two `distill_adrs` runs over the same ADRs yield byte-identical output.
2. Emitted `SKILL.md` has a `## Provenance` block citing every referenced ADR id
   with a content hash + captured-at date; each cited ADR file exists.
3. Editing a referenced ADR and re-running the governance test FAILS until
   `distill_adrs` is re-run.
4. A future sub-agent loading `skills/ratify-an-adr/SKILL.md` can comply with the
   ratify-an-ADR procedure.

## Verification

- `env -u PYTHONPATH -u VIRTUAL_ENV .venv/bin/python -m pytest tests/test_distill_governance.py -q` → green.
- Manual: `python scripts/distill_skill.py --adrs 41,42,43 --out /tmp/skill.md`, `diff` two runs.

---
name: ratify-an-adr
description: Use when drafting or ratifying a Rathnone ADR, or deciding whether to mirror an external skill pattern locally. Enforces the fork-ratification discipline (usefulness filter, local-first, frozen-spine Invariant 1) and the re-distill governance loop.
version: 1
metadata:
  hermes:
    tags: [adr, governance, ratification, phase2]
---

# Ratify an ADR

Distilled from the repository's ratified ADRs. The procedure below is the load-bearing contract; the `## Provenance` block ties it to the exact source files so a change forces a re-distill.

## Procedure

1. **Usefulness filter.** Mirror an external skill ONLY if it adds real functionality to the multi-agent harness, evidence audit, or agent access. Do not mirror for the sake of mirroring.
2. **Local-first / sovereignty.** No cloud egress. Self-hosted surfaces only (localhost Neo4j/Ollama are in-scope; Aura/remote are forbidden). Every new gate defaults to REFUSE (fail-closed).
3. **Frozen spine.** Never import or modify `fleet.epistemic.decide()` (Invariant 1). Additive capability + registry entries only.
4. **Reproducible / provenance.** Every verdict reproducible from (graph, record) + policy; no RNG/model/network in verdicts.
5. **Stop and present.** Write the ADR + fork choices for review BEFORE implementing. Do NOT commit until ratified.
6. **Re-distill governance.** If a source ADR changes, regenerate this skill (the governance test fails on hash divergence).

## Source distillations

### ADR 41 — `41-AGENT-HARNESS-AUTHORITY.md`
_No Decision/Acceptance/Constraints sections found._

### ADR 42 — `42-HARNESS-CAPABILITY-SPLIT.md`
_No Decision/Acceptance/Constraints sections found._

### ADR 43 — `43-HARNESS-SIGNED-EXECUTE.md`
_No Decision/Acceptance/Constraints sections found._

## Provenance

- ADR 41 — `41-AGENT-HARNESS-AUTHORITY.md` — sha256:d46592de7812c0ff5ed15bc900dc93bb4f6a044b18d9348fb85b05c3a920cdd6 — captured 2026-08-21
- ADR 42 — `42-HARNESS-CAPABILITY-SPLIT.md` — sha256:c979886c934dbfe400e281a4251e635c79fa0076fe50caec6464af748176df6c — captured 2026-08-21
- ADR 43 — `43-HARNESS-SIGNED-EXECUTE.md` — sha256:adbbfe1285b8947a537982409f899c0fff531a42cf2a375b10beafa77b4d3849 — captured 2026-08-21

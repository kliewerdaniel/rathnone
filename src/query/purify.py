"""ADR 40 — knowledge-layer source corroboration (knowledge-poisoning guard).

The knowledge engine has world-class *authority* trust (ADR 30/34/35/36: the
served ``EvidenceRecord`` is authentic, signed, replayable) but **zero *content*
trust**. The loader (`loader.py`) consumes an SKC artifact and trusts every
``source`` / ``domain`` / ``authority`` / ``confidence`` string at face value.
Because the engine never imports the frozen finance spine, that face-value trust
is the *only* thing standing between a poisoned knowledge graph and a downstream
agent that reasons correctly from wrong beliefs.

This is the ADR 24 analogue (distinct-origin corroboration) applied to the
*evidence* layer instead of the *price* layer:

  - ADR 24 demands ``quorum`` **DISTINCT** price sources before a finance claim
    is believed. It explicitly kills the "one feed reporting twice" loophole.
  - ADR 40 demands ``quorum`` **DISTINCT registrable-origin** knowledge sources
    before a *retained evidence set* is treated as corroborated. It explicitly
    kills the "one poisoned principal presenting many domains" (sybil
    provenance) and "inflate ``authority``/``confidence``" loopholes.

HARD CONSTRAINTS (consistent with the substrate's frozen-spine posture):
  - Invariant 1 preserved: this layer NEVER imports or calls ``decide()``. It runs
    *after* the executor produces an ``EvidenceRecord`` and only *labels* it. It
    is the knowledge-plane mirror of ``hygiene.CorroborationLayer`` (which narrows
    the finance verdict) — narrowing-only in spirit: a clean record stays clean, a
    poisoned record is stamped ``poisoned=True`` and the downstream agent is
    expected to refuse it (see ``KnowledgeAgent.accept``).
  - The verdict is **reproducible from (graph, record) + operator quorum policy**
    — no RNG, no model, no network. It satisfies Invariant 3 (key-free
    verifiable): anyone holding the graph and the record can recompute it.
  - Fail-closed: with the layer enabled, a retained evidence set that does NOT
    meet the distinct-origin quorum is stamped POISONED, never assumed-clean.
  - Opt-in: disabled by default (local-first frictionless). Disabled == pure
    pass-through, so every existing suite is unaffected.
  - No new dependencies (stdlib only).

WHAT THIS LAYER IS NOT (honesty register):
  - It is **structural** defense only. It catches *sybil provenance*, *single-
    origin reliance*, and *total-graph capture*. It does **NOT** catch *semantic*
    poison — text that is internally consistent and sourced from genuinely
    distinct reputable origins but false in the world (the model-reasoning-from-
    wrong-fact case from ``09-OPEN-QUESTIONS.md``). We claim "the evidence set has
    enough distinct origins to not be a single-principal fabrication," not "the
    claims are true." That distinction is stated in the report and the ADR.
  - ``authority`` / ``confidence`` scores are treated as **advisory** and are
    surfaced in the report; they are NEVER trusted as corroboration (a high score
    from a poisoned principal is still one origin). We do not BLOCK on a score
    being present, because every real SKC artifact carries scores — blocking on
    that would false-positive the corpus we are trying to protect.
"""

from __future__ import annotations

import dataclasses
from typing import Optional

from .executor import EvidenceRecord, KnowledgeGraph

# Known multi-label public suffixes we must not truncate when deriving a
# registrable domain (eTLD+1). Heuristic — not a full public-suffix list. The
# point is to defeat *subdomain* sybil (a.evil.com == b.evil.com == evil.com);
# a principal controlling distinct eTLDs (evil.com, evil.net) still counts as two
# origins, which is the honest limit of structural defense.
_MULTI_LABEL_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.nz", "co.jp",
    "com.br", "co.za", "co.in",
}


def _etld1(domain: str) -> str:
    """Registrable domain (eTLD+1) of ``domain`` — groups subdomain sybil.

    ``a.evil.com`` and ``b.evil.com`` both collapse to ``evil.com``; distinct
    eTLDs (``evil.com`` vs ``evil.net``) stay distinct. Returns the input
    unchanged if it has fewer than two labels.
    """
    if not domain:
        return ""
    host = domain.split("://")[-1].split("/")[0].split(":")[0].lower()
    host = host.strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last_two = ".".join(parts[-2:])
    if last_two in _MULTI_LABEL_TLDS and len(parts) > 2:
        return ".".join(parts[-3:])
    return last_two


@dataclasses.dataclass
class PoisonViolation:
    code: str
    message: str
    detail: Optional[dict] = None


@dataclasses.dataclass
class PoisonVerdict:
    """Narrowing-only label over a served evidence record.

    ``ok=False`` => the retained evidence set did NOT meet the distinct-origin
    quorum => ``verdict == "POISONED"``. The record is still served (the engine
    does not withhold evidence — that is the consumer's narrowing step); the
    flag tells the consumer to refuse it.
    """

    ok: bool
    verdict: str                      # "CLEAN" | "POISONED"
    violations: list[PoisonViolation] = dataclasses.field(default_factory=list)
    checks_run: int = 0
    report: dict = dataclasses.field(default_factory=dict)

    @property
    def reasons(self) -> list[str]:
        return [f"{v.code}: {v.message}" for v in self.violations]

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "ok": self.ok,
            "violations": [dataclasses.asdict(v) for v in self.violations],
            "checks_run": self.checks_run,
            "report": self.report,
        }


class PurificationLayer:
    """Deterministic, narrowing-only, fail-closed knowledge-poisoning guard.

    Disabled by default. When enabled it demands ``quorum`` **distinct
    registrable-origin** sources across the retained document/claim entities of an
    ``EvidenceRecord``; any unmet quorum => POISONED.

    ADR 24 parallel: quorum is over *distinct origins*, not repeated values. A
    single poisoned principal presenting ``evil.com`` / ``evil.net`` / many
    ``*.evil.com`` subdomains collapses (via eTLD+1) to one origin and fails
    quorum.
    """

    def __init__(self, *,
                 enabled: bool = False,
                 quorum: int = 2,
                 capture_threshold: float = 0.90):
        if quorum < 1:
            raise ValueError(f"quorum must be >= 1, got {quorum}")
        self.enabled = enabled
        self.quorum = quorum
        self.capture_threshold = capture_threshold

    def evaluate(self, graph: KnowledgeGraph,
                 record: EvidenceRecord) -> PoisonVerdict:
        # Disabled => pure pass-through (narrowing holds trivially).
        if not self.enabled:
            return PoisonVerdict(ok=True, verdict="CLEAN", checks_run=0,
                                 report={"enabled": False})

        violations: list[PoisonViolation] = []
        checks = 0

        # --- resolve the retained set against the graph -------------------
        checks += 1
        retained = [graph.get(e.id) for e in record.included]
        retained = [e for e in retained if e is not None]
        # Only document/claim entities carry external-world provenance. A
        # concept-only result (no docs/claims retained) has no poison surface.
        doc_claim = [e for e in retained if e.type in ("document", "claim")]
        scored = [e for e in retained if e.score and e.score > 0.0]

        # --- 1. DISTINCT-ORIGIN QUORUM (the ADR 24 analogue) -------------
        checks += 1
        domains = [e.source for e in doc_claim if e.source]
        registrable = {_etld1(d) for d in domains}
        n_distinct = len(registrable)
        domain_counts: dict[str, int] = {}
        for d in domains:
            domain_counts[d] = domain_counts.get(d, 0) + 1
        report = {
            "enabled": True,
            "quorum": self.quorum,
            "retained_entities": len(retained),
            "retained_doc_claim": len(doc_claim),
            "distinct_domains": sorted(registrable),
            "n_distinct_origins": n_distinct,
            "domain_counts": domain_counts,
            "scores_treated_as_advisory": True,
            "n_scored_entities": len(scored),
        }

        if doc_claim and n_distinct < self.quorum:
            violations.append(PoisonViolation(
                "insufficient_source_diversity",
                f"retained evidence rests on {n_distinct} distinct origin(s); "
                f"require quorum {self.quorum}",
                {"n_distinct_origins": n_distinct,
                 "quorum": self.quorum,
                 "origins": sorted(registrable)}))

        # --- 2. TOTAL-GRAPH CAPTURE (diagnosis; same POISONED outcome) ----
        checks += 1
        total_doc_claim = sum(1 for e in graph.all()
                              if e.type in ("document", "claim"))
        if total_doc_claim:
            included_fraction = len(doc_claim) / total_doc_claim
            report["included_fraction"] = included_fraction
            # A query that scoops almost the entire (poisoned) corpus AND fails
            # the origin quorum is the classic "return everything" capture. We
            # only emit this diagnosis when BOTH hold, so a legitimate broad
            # query over a clean, diverse corpus is NOT flagged.
            if (included_fraction >= self.capture_threshold
                    and n_distinct < self.quorum):
                violations.append(PoisonViolation(
                    "total_graph_capture",
                    f"query retained {included_fraction:.0%} of the corpus "
                    f"from only {n_distinct} origin(s)",
                    {"included_fraction": included_fraction,
                     "n_distinct_origins": n_distinct}))

        verdict = "POISONED" if violations else "CLEAN"
        return PoisonVerdict(ok=not violations, verdict=verdict,
                             violations=violations, checks_run=checks,
                             report=report)


__all__ = ["PurificationLayer", "PoisonVerdict", "PoisonViolation",
           "_etld1"]

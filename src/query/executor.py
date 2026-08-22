"""Deterministic query executor + evidence record.

The executor compiles a query-algebra ``Op`` into an inspectable plan and runs it
over an in-memory ``KnowledgeGraph``. The output is an ``EvidenceRecord``: every
entity that matched, every entity that was *candidate but excluded*, the
predicates evaluated, the exact reason for each inclusion/exclusion, and the
source provenance of each retained entity — plus a reproducible content hash.

No network egress, no LLM, no embeddings. ``NEAR`` uses a precomputed
``neighbor_terms`` set; ranking predicates (SCORE/TIME) only *annotate* and
*filter*, they never introduce nondeterminism.

Determinism contract: identical (graph, query) => byte-identical
``EvidenceRecord.deterministic_hash``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional

from .algebra import Op, OpKind


# ---------------------------------------------------------------------------
# Graph model
# ---------------------------------------------------------------------------
@dataclass
class Entity:
    id: str
    type: str = "document"
    source: str = ""           # provenance: primary origin (e.g. "arxiv")
    text: str = ""             # indexable body (lower-cased internally)
    score: float = 0.0         # precomputed relevance (e.g. citation count)
    timestamp: float = 0.0
    neighbor_terms: set[str] = field(default_factory=set)
    extra: dict = field(default_factory=dict)

    def __post_init__(self):
        self.text = (self.text or "").lower()
        self.neighbor_terms = {t.lower() for t in self.neighbor_terms}


@dataclass
class Edge:
    src: str
    dst: str
    kind: str = "related"      # "related" | "derived_from" | "same_as"


class KnowledgeGraph:
    def __init__(self):
        self._ents: dict[str, Entity] = {}
        self._adj: dict[str, list[Edge]] = {}

    def add(self, e: Entity) -> Entity:
        self._ents[e.id] = e
        self._adj.setdefault(e.id, [])
        return e

    def link(self, src: str, dst: str, kind: str = "related") -> None:
        if src in self._ents and dst in self._ents:
            self._adj.setdefault(src, []).append(Edge(src, dst, kind))
            self._adj.setdefault(dst, []).append(Edge(dst, src, kind))

    def get(self, eid: str) -> Optional[Entity]:
        return self._ents.get(eid)

    def all(self) -> list[Entity]:
        return list(self._ents.values())

    def entity_count(self) -> int:
        return len(self._ents)

    def edge_count(self) -> int:
        # `link` stores both directions, so halve the adjacency footprint to
        # report undirected edges once.
        total = sum(len(v) for v in self._adj.values())
        return total // 2 if total else 0

    def neighbors(self, eid: str, kind: Optional[str] = None) -> list[Entity]:
        out = []
        for e in self._adj.get(eid, []):
            if kind is None or e.kind == kind:
                out.append(self._ents[e.dst])
        return out


# ---------------------------------------------------------------------------
# Evidence record
# ---------------------------------------------------------------------------
@dataclass
class _Entry:
    id: str
    reasons: list[str]              # why this entity is in/out
    predicates: list[str]           # predicate tags that fired
    source: str = ""

    def as_dict(self) -> dict:
        return {"id": self.id, "reasons": self.reasons,
                "predicates": self.predicates, "source": self.source}


@dataclass
class EvidenceRecord:
    included: list[_Entry] = field(default_factory=list)
    excluded: list[_Entry] = field(default_factory=list)
    plan: list[str] = field(default_factory=list)   # human-readable steps

    @property
    def included_ids(self) -> set[str]:
        return {e.id for e in self.included}

    @property
    def excluded_ids(self) -> set[str]:
        return {e.id for e in self.excluded}

    def deterministic_hash(self) -> str:
        """Reproducible: sorts ids so order of graph insertion is irrelevant."""
        payload = {
            "included": sorted(e.id for e in self.included),
            "excluded": sorted(e.id for e in self.excluded),
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()).hexdigest()

    def as_dict(self) -> dict:
        return {
            "included": [e.as_dict() for e in self.included],
            "excluded": [e.as_dict() for e in self.excluded],
            "plan": self.plan,
            "deterministic_hash": self.deterministic_hash(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "EvidenceRecord":
        rec = cls()
        rec.included = [
            _Entry(id=e["id"], reasons=list(e.get("reasons", [])),
                   predicates=list(e.get("predicates", [])),
                   source=e.get("source", ""))
            for e in d.get("included", [])
        ]
        rec.excluded = [
            _Entry(id=e["id"], reasons=list(e.get("reasons", [])),
                   predicates=list(e.get("predicates", [])),
                   source=e.get("source", ""))
            for e in d.get("excluded", [])
        ]
        rec.plan = list(d.get("plan", []))
        return rec

    # --- reconciliation -------------------------------------------------
    def verify(self, *, expect_hash: str | None = None,
               expect_included: set[str] | None = None,
               expect_excluded: set[str] | None = None) -> "VerifyResult":
        """Reconcile this EvidenceRecord against an expected prior.

        Rathnone's discipline: an agent may ASSERT "I believe X because these
        predicates held" — ``verify`` turns that claim into a checkable contract.
        It fails closed (returns ok=False, never raises) on any mismatch,
        enumerating the divergences so the reason is auditable.
        """
        divergences: list[str] = []
        if expect_hash is not None and expect_hash != self.deterministic_hash():
            divergences.append("hash mismatch")
        if expect_included is not None:
            got = self.included_ids
            missing = expect_included - got
            extra = got - expect_included
            if missing:
                divergences.append(f"included missing: {sorted(missing)}")
            if extra:
                divergences.append(f"included unexpected: {sorted(extra)}")
        if expect_excluded is not None:
            got = self.excluded_ids
            missing = expect_excluded - got
            extra = got - expect_excluded
            if missing:
                divergences.append(f"excluded missing: {sorted(missing)}")
            if extra:
                divergences.append(f"excluded unexpected: {sorted(extra)}")
        return VerifyResult(ok=not divergences, divergences=divergences,
                            observed_hash=self.deterministic_hash())

    def reconcile_with(self, other: "EvidenceRecord") -> "ReconcileResult":
        """Two independent runs over the (presumably same) graph must agree.

        Used to detect silent evidence drift: if the same query is re-run and the
        included set changes, something in the knowledge base moved. Surfaces the
        symmetric difference with per-entity reasons.
        """
        a = self.included_ids
        b = other.included_ids
        only_self = sorted(a - b)
        only_other = sorted(b - a)
        stable = sorted(a & b)
        return ReconcileResult(
            stable=stable, only_self=only_self, only_other=only_other,
            consistent=not only_self and not only_other,
            self_hash=self.deterministic_hash(), other_hash=other.deterministic_hash())


@dataclass
class VerifyResult:
    ok: bool
    divergences: list[str]
    observed_hash: str


@dataclass
class ReconcileResult:
    stable: list[str]
    only_self: list[str]
    only_other: list[str]
    consistent: bool
    self_hash: str
    other_hash: str


# ---------------------------------------------------------------------------
# Executor
# ---------------------------------------------------------------------------
class _Result:
    """Per-entity evaluation: matched predicate-set + the captured reasons."""

    __slots__ = ("matched", "reasons", "predicates")

    def __init__(self):
        self.matched: bool = True
        self.reasons: list[str] = []
        self.predicates: list[str] = []

    def fail(self, reason: str, predicate: str) -> None:
        self.matched = False
        self.reasons.append(reason)
        self.predicates.append(predicate)


class QueryExecutor:
    def __init__(self, graph: KnowledgeGraph):
        self.g = graph

    # --- public ----------------------------------------------------------
    def execute(self, op: Op) -> EvidenceRecord:
        record = EvidenceRecord()
        plan = []
        for e in self.g.all():
            r = self._eval(op, e, depth=0, plan=plan)
            if r.matched:
                rec = _Entry(id=e.id, reasons=r.reasons or ["root query satisfied"],
                             predicates=sorted(set(r.predicates)),
                             source=e.source)
                record.included.append(rec)
            else:
                rec = _Entry(id=e.id, reasons=r.reasons,
                             predicates=sorted(set(r.predicates)),
                             source=e.source)
                record.excluded.append(rec)
        record.plan = plan
        return record

    # --- recursive evaluator -------------------------------------------
    def _eval(self, op: Op, e: Entity, depth: int, plan: list[str]) -> _Result:
        kind = op.kind
        if kind == OpKind.AND:
            plan.append(f"AND(depth={depth})")
            res = _Result()
            for c in op.children:
                sub = self._eval(c, e, depth + 1, plan)
                if not sub.matched:
                    res.matched = False
                    res.reasons.extend(sub.reasons)
                res.predicates.extend(sub.predicates)
            if res.matched:
                res.reasons.append("all conjuncts satisfied")
            return res

        if kind == OpKind.OR:
            plan.append(f"OR(depth={depth})")
            res = _Result()
            any_ok = False
            reasons: list[str] = []
            for c in op.children:
                sub = self._eval(c, e, depth + 1, plan)
                res.predicates.extend(sub.predicates)
                if sub.matched:
                    any_ok = True
                else:
                    reasons.extend(sub.reasons)
            if any_ok:
                res.matched = True
                res.reasons.append("at least one disjunct satisfied")
            else:
                res.matched = False
                res.reasons.append("no disjunct satisfied: " + "; ".join(reasons))
            return res

        if kind == OpKind.NOT:
            plan.append(f"NOT(depth={depth})")
            sub = self._eval(op.children[0], e, depth + 1, plan)
            res = _Result()
            res.predicates = sub.predicates
            if sub.matched:
                res.matched = False
                res.reasons.append("inner predicate held (negated to fail)")
            else:
                res.matched = True
                res.reasons.append("inner predicate absent (negation satisfied)")
            return res

        return self._leaf(op, e, depth, plan)

    # --- leaf predicates -------------------------------------------------
    def _leaf(self, op: Op, e: Entity, depth: int, plan: list[str]) -> _Result:
        k = op.kind
        res = _Result()
        if k in (OpKind.TYPE, OpKind.SOURCE, OpKind.MATCH, OpKind.SCORE,
                 OpKind.TIME, OpKind.CONNECTED_TO, OpKind.DERIVED_FROM,
                 OpKind.SAME_AS, OpKind.PATH, OpKind.NEAR):
            plan.append(f"{k.value}({op.arg}, depth={depth})")
        else:
            plan.append(f"{k.value}(depth={depth})")

        if k == OpKind.TYPE:
            if e.type != op.arg:
                res.fail(f"type '{e.type}' != required '{op.arg}'", "TYPE")
            else:
                res.reasons.append(f"type=={op.arg}"); res.predicates.append("TYPE")
        elif k == OpKind.SOURCE:
            if e.source != op.arg:
                res.fail(f"source '{e.source}' != excluded/required '{op.arg}'",
                         "SOURCE")
            else:
                res.reasons.append(f"source=={op.arg}"); res.predicates.append("SOURCE")
        elif k == OpKind.MATCH:
            if not op.arg or op.arg.lower() not in e.text:
                res.fail(f"text lacks '{op.arg}'", "MATCH")
            else:
                res.reasons.append(f"text contains '{op.arg}'"); res.predicates.append("MATCH")
        elif k == OpKind.SCORE:
            if e.score < (op.threshold or 0.0):
                res.fail(f"score {e.score} < {op.threshold}", "SCORE")
            else:
                res.reasons.append(f"score>={op.threshold}"); res.predicates.append("SCORE")
        elif k == OpKind.TIME:
            lo, hi = op.lo, op.hi
            if lo is not None and e.timestamp < lo:
                res.fail(f"timestamp {e.timestamp} < {lo}", "TIME")
            elif hi is not None and e.timestamp > hi:
                res.fail(f"timestamp {e.timestamp} > {hi}", "TIME")
            else:
                res.reasons.append("within time range"); res.predicates.append("TIME")
        elif k in (OpKind.CONNECTED_TO, OpKind.DERIVED_FROM, OpKind.SAME_AS):
            edge_kind = {OpKind.CONNECTED_TO: None,
                         OpKind.DERIVED_FROM: "derived_from",
                         OpKind.SAME_AS: "same_as"}[k]
            found = self._bfs(e, op.children[0], op.depth, edge_kind)
            if not found:
                res.fail(f"no {k.value} match within depth {op.depth}", k.value)
            else:
                res.reasons.append(f"{k.value} match within depth {op.depth}")
                res.predicates.append("CONNECTED_TO" if k == OpKind.CONNECTED_TO
                                      else k.value)
        elif k == OpKind.PATH:
            found = self._shortest(e, op.children[0], op.depth)
            if not found:
                res.fail(f"no PATH to target within {op.depth} hops", "PATH")
            else:
                res.reasons.append(f"PATH to target within {op.depth} hops")
                res.predicates.append("PATH")
        elif k == OpKind.NEAR:
            if not op.arg or op.arg.lower() not in e.neighbor_terms:
                res.fail(f"not near term '{op.arg}'", "NEAR")
            else:
                res.reasons.append(f"near '{op.arg}'"); res.predicates.append("NEAR")
        else:
            res.fail(f"unknown operator {k.value}", "UNKNOWN")
        return res

    # --- graph traversal helpers ---------------------------------------
    def _bfs(self, start: Entity, inner: Op, max_depth: int,
             edge_kind: Optional[str]) -> bool:
        # The start node itself counts as "connected to" inner (depth 0 seed).
        if self._leaf(inner, start, 0, []).matched:
            return True
        seen = {start.id}
        frontier = [start]
        for _ in range(max_depth):
            nxt = []
            for node in frontier:
                for nb in self.g.neighbors(node.id, edge_kind):
                    if nb.id in seen:
                        continue
                    seen.add(nb.id)
                    if self._leaf(inner, nb, 0, []).matched:
                        return True
                    nxt.append(nb)
            frontier = nxt
        return False

    def _shortest(self, start: Entity, target: Op, max_len: int) -> bool:
        # The start node itself counts as a 0-hop PATH endpoint.
        if self._leaf(target, start, 0, []).matched:
            return True
        seen = {start.id}
        frontier = [start]
        for _ in range(max_len):
            nxt = []
            for node in frontier:
                for nb in self.g.neighbors(node.id):
                    if nb.id in seen:
                        continue
                    seen.add(nb.id)
                    if self._leaf(target, nb, 0, []).matched:
                        return True
                    nxt.append(nb)
            frontier = nxt
        return False


__all__ = ["Entity", "Edge", "KnowledgeGraph", "EvidenceRecord",
           "QueryExecutor", "VerifyResult", "ReconcileResult"]

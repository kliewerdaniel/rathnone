"""Typed, serializable query-algebra IR.

An LLM constructs a query by assembling ``Op`` nodes. The executor (see
``executor.py``) evaluates it deterministically. The IR is pure data so it can
be round-tripped to/from JSON: an agent emits ``Op.to_dict()`` and Rathnone
reconstructs ``Op.from_dict()`` — the model never runs the retrieval.

Operator inventory
------------------
Boolean  : AND, OR, NOT
Entity   : TYPE(t), SOURCE(s), MATCH(text)
Graph    : CONNECTED_TO(inner, depth), DERIVED_FROM(inner, depth),
           SAME_AS(inner, depth), PATH(inner, max_len)
Ranking  : SCORE(>=x), TIME([lo,hi]), NEAR(term, depth)

``NEAR`` is a keyword-neighborhood predicate over a precomputed
``neighbor_terms`` set (no embeddings required, fully deterministic). ``PATH``
is shortest-path existence to a node satisfying ``inner``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class OpKind(str, Enum):
    AND = "AND"
    OR = "OR"
    NOT = "NOT"
    TYPE = "TYPE"
    SOURCE = "SOURCE"
    MATCH = "MATCH"
    CONNECTED_TO = "CONNECTED_TO"
    DERIVED_FROM = "DERIVED_FROM"
    SAME_AS = "SAME_AS"
    NEAR = "NEAR"
    SCORE = "SCORE"
    TIME = "TIME"
    PATH = "PATH"


@dataclass
class Op:
    kind: OpKind
    arg: Optional[str] = None
    threshold: Optional[float] = None
    lo: Optional[float] = None
    hi: Optional[float] = None
    depth: int = 1
    children: list["Op"] = field(default_factory=list)

    # ---- factories -------------------------------------------------------
    @classmethod
    def composite(cls, kind: OpKind, *children: "Op", depth: int = 1) -> "Op":
        return cls(kind=kind, depth=depth, children=list(children))

    # ---- serialization (LLM -> Rathnone contract) ------------------------
    def to_dict(self) -> dict:
        d: dict = {"kind": self.kind.value}
        if self.arg is not None:
            d["arg"] = self.arg
        if self.threshold is not None:
            d["threshold"] = self.threshold
        if self.lo is not None:
            d["lo"] = self.lo
        if self.hi is not None:
            d["hi"] = self.hi
        if self.kind in (OpKind.CONNECTED_TO, OpKind.DERIVED_FROM,
                         OpKind.SAME_AS, OpKind.NEAR, OpKind.PATH):
            d["depth"] = self.depth
        if self.children:
            d["children"] = [c.to_dict() for c in self.children]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Op":
        kind = OpKind(d["kind"])
        return cls(
            kind=kind,
            arg=d.get("arg"),
            threshold=d.get("threshold"),
            lo=d.get("lo"),
            hi=d.get("hi"),
            depth=int(d.get("depth", 1)),
            children=[cls.from_dict(c) for c in d.get("children", [])],
        )


# Boolean combinators -------------------------------------------------------
def And(*children: Op) -> Op:
    return Op(kind=OpKind.AND, children=list(children))


def Or(*children: Op) -> Op:
    return Op(kind=OpKind.OR, children=list(children))


def Not(child: Op) -> Op:
    return Op(kind=OpKind.NOT, children=[child])


# Entity predicates ---------------------------------------------------------
def Type(t: str) -> Op:
    return Op(kind=OpKind.TYPE, arg=t)


def Source(s: str) -> Op:
    return Op(kind=OpKind.SOURCE, arg=s)


def Match(text: str) -> Op:
    return Op(kind=OpKind.MATCH, arg=text)


def ScoreAtLeast(x: float) -> Op:
    return Op(kind=OpKind.SCORE, threshold=float(x))


def TimeRange(lo: Optional[float] = None, hi: Optional[float] = None) -> Op:
    return Op(kind=OpKind.TIME, lo=lo, hi=hi)


# Graph predicates ----------------------------------------------------------
def ConnectedTo(child: Op, depth: int = 1) -> Op:
    return Op(kind=OpKind.CONNECTED_TO, depth=depth, children=[child])


def DerivedFrom(child: Op, depth: int = 1) -> Op:
    return Op(kind=OpKind.DERIVED_FROM, depth=depth, children=[child])


def SameAs(child: Op, depth: int = 1) -> Op:
    return Op(kind=OpKind.SAME_AS, depth=depth, children=[child])


def PathTo(child: Op, max_len: int = 3) -> Op:
    return Op(kind=OpKind.PATH, depth=max_len, children=[child])


def Near(term: str, depth: int = 1) -> Op:
    return Op(kind=OpKind.NEAR, arg=term, depth=depth)


__all__ = [
    "Op",
    "OpKind",
    "And",
    "Or",
    "Not",
    "Type",
    "Source",
    "Match",
    "ScoreAtLeast",
    "TimeRange",
    "ConnectedTo",
    "DerivedFrom",
    "SameAs",
    "PathTo",
    "Near",
]

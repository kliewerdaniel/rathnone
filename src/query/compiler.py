"""Deterministic natural-language -> query-algebra compiler.

The strategic thesis: an LLM should *construct a query*, not be responsible for
whether the query was correctly executed. This module is the "construct" side of
that contract -- it turns a natural-language request into a typed ``Op`` tree
(the engine's IR). The executor then runs that tree deterministically and emits
an inspectable ``EvidenceRecord``. If the model mis-phrases the request, the
*compiled plan* is still auditable and the *execution* is still correct -- the
model never touches retrieval.

Design constraints (per the knowledge-engine thesis):
- Deterministic and dependency-free (stdlib ``re`` only). No LLM, no network,
  no embeddings. Identical input -> identical ``Op`` tree.
- The output is pure ``Op`` IR, so it round-trips through ``Op.to_dict()`` /
  ``Op.from_dict()`` -- an agent can emit the dict and Rathnone reconstructs it.
- The grammar is intentionally constrained and inspectable: each recognized
  connector maps to exactly one algebra operator. Unknown input raises
  ``CompileError`` rather than silently degrading.
- Composition is handled: ``but not connected to X`` compiles to
  ``Not(ConnectedTo(Match("X")))``, not a dropped exclusion -- a connector that
  is the object of an exclusion is wrapped, not consumed as plain text.

Example
-------
    "Find research about gradient descent that discusses optimization,
     exclude papers whose primary source is arXiv, and prioritize papers
     connected to convex optimization."

compiles to:

    And(
        Match("gradient descent"),
        Match("optimization"),
        Not(Source("arxiv")),
        ConnectedTo(Match("convex optimization"), depth=2),
    )
"""

from __future__ import annotations

import re

from .algebra import (
    And, ConnectedTo, DerivedFrom, Match, Near, Not, Op, OpKind, SameAs,
    ScoreAtLeast, Source, TimeRange, Type,
)


class CompileError(Exception):
    """Raised when the input cannot be mapped onto the query algebra."""


# Leading command verbs that are not part of the topic.
_COMMAND_RE = re.compile(
    r"^\s*(?:find|show|research|list|get|return|search for|give me|identify|"
    r"locate|retrieve)\b(?:s)?\s*(?:me\s+)?"
    r"(?:research|papers|documents|articles|entries|records|the)\b\s*",
    re.IGNORECASE,
)

# Filler words trimmed from the edges of extracted phrases.
_TRAILING_FILLER = re.compile(
    r"\s*(?:papers|research|documents|articles|entries|records|things|"
    r"results|that|which|who|please|,|\.|\;|\:)+\s*$",
    re.IGNORECASE,
)
_LEADING_FILLER = re.compile(
    r"^\s*(?:the|all|any|some|papers|research|documents|articles|that|which|who)\b\s*",
    re.IGNORECASE,
)

# Ordered connector patterns. EXCLUDE_SRC must precede EXCLUDE so the
# "primary source is X" form wins over the generic exclude.
_PATTERNS: list[tuple[str, str]] = [
    ("EXCLUDE_SRC",
     r"\b(?:exclude|excluding|except)(?:[^.,;]*?primary source is|"
     r"[^.,;]*?source is)\s+(?P<SRC>[A-Za-z0-9_\-\.]+)"),
    ("EXCLUDE",
     r"\b(?:exclude|excluding|except|but not|not including)\b"),
    ("FROM_SRC",
     r"\b(?:from|published in|published by)\b"),
    ("CONNECTED",
     r"\b(?:connected to|related to|connect to)\b"),
    ("DERIVED",
     r"\bderived from\b"),
    ("SAMEAS",
     r"\bsame as\b"),
    ("NEAR",
     r"\b(?:near|close to)\b"),
    ("SCORE",
     r"\bscore (?:at )?least\b|\bwith score >=?\b"),
    ("AFTER",
     r"\b(?:after|since)\b"),
    ("BEFORE",
     r"\b(?:before|until)\b"),
    ("TYPE",
     r"\b(?:of )?type\b|\bkind\b"),
    ("ABOUT",
     r"\b(?:about|regarding|concerning|on)\b"),
    ("DISCUSS",
     r"\b(?:that|which|who)\s+(?:discusses|mentions|covers|talks about|"
     r"describes|addresses|explores|examines)\b"),
]
_COMBINED = re.compile(
    "|".join(f"(?P<{name}>{pat})" for name, pat in _PATTERNS),
    re.IGNORECASE,
)

_NUM_RE = re.compile(r"-?\d+(?:\.\d+)?")


def _clean(phrase: str, lowercase: bool = False) -> str:
    p = phrase.strip()
    p = _TRAILING_FILLER.sub("", p)
    p = _LEADING_FILLER.sub("", p)
    p = p.strip(" ,.;:")
    if lowercase:
        p = p.lower()
    return p


def _first_number(phrase: str) -> float | None:
    m = _NUM_RE.search(phrase)
    return float(m.group(0)) if m else None


def _strip_command(text: str) -> str:
    return _COMMAND_RE.sub("", text, count=1)


def _phrase_between(matches: list[re.Match], i: int, n: int) -> str:
    start = matches[i].end()
    end = matches[i + 1].start() if i + 1 < n else len(matches[i].string)
    return matches[i].string[start:end]


class QueryCompiler:
    """Compile a constrained natural-language request into an ``Op`` tree."""

    def compile(self, text: str) -> Op:
        if not text or not text.strip():
            raise CompileError("empty query")

        matches = list(_COMBINED.finditer(text))
        if not matches:
            # No connector recognized: treat the whole thing as a topic match.
            topic = _clean(_strip_command(text))
            if not topic:
                raise CompileError(f"no queryable content: {text!r}")
            return Match(topic)

        clauses: list[Op] = []
        head = _clean(_strip_command(text[: matches[0].start()]))
        if head:
            clauses.append(Match(head))

        i = 0
        n = len(matches)
        while i < n:
            kind = matches[i].lastgroup
            assert kind is not None
            if kind in ("EXCLUDE", "EXCLUDE_SRC"):
                op, i = self._parse_negation(matches, i, n)
            else:
                op, i = self._parse_positive(matches, i, n)
            if op is not None:
                clauses.append(op)

        if not clauses:
            raise CompileError(f"no queryable content: {text!r}")
        if len(clauses) == 1:
            return clauses[0]
        return And(*clauses)

    # --- negation (exclude) ---------------------------------------------
    def _parse_negation(self, matches: list[re.Match], i: int, n: int):
        m = matches[i]
        kind = m.lastgroup
        if kind == "EXCLUDE_SRC":
            src = (m.group("SRC") or "").strip().lower()
            if src:
                return Not(Source(src)), i + 1
            # fall through to generic EXCLUDE handling
        phrase = _clean(_phrase_between(matches, i, n))
        # A connector immediately following the exclusion is the *object* of
        # the exclusion, not trailing text: NOT(ConnectedTo(X)), not a dropped
        # clause.
        if not phrase and i + 1 < n:
            inner, j = self._parse_positive(matches, i + 1, n)
            if inner is not None:
                return Not(inner), j
        if phrase:
            return Not(Match(phrase)), i + 1
        return None, i + 1

    # --- positive connectors --------------------------------------------
    def _parse_positive(self, matches: list[re.Match], i: int, n: int):
        m = matches[i]
        kind = m.lastgroup
        assert kind is not None
        op = self._build(kind, m, _phrase_between(matches, i, n))
        return op, i + 1

    # --- clause builders -------------------------------------------------
    def _build(self, kind: str, m: re.Match, phrase: str) -> Op | None:
        if kind == "FROM_SRC":
            src = _clean(phrase, lowercase=True)
            return Source(src) if src else None
        if kind == "CONNECTED":
            topic = _clean(phrase)
            return ConnectedTo(Match(topic), depth=2) if topic else None
        if kind == "DERIVED":
            topic = _clean(phrase)
            return DerivedFrom(Match(topic)) if topic else None
        if kind == "SAMEAS":
            topic = _clean(phrase)
            return SameAs(Match(topic)) if topic else None
        if kind == "NEAR":
            term = _clean(phrase, lowercase=True)
            return Near(term) if term else None
        if kind == "SCORE":
            num = _first_number(phrase)
            return ScoreAtLeast(num) if num is not None else None
        if kind == "AFTER":
            num = _first_number(phrase)
            return TimeRange(lo=num) if num is not None else None
        if kind == "BEFORE":
            num = _first_number(phrase)
            return TimeRange(hi=num) if num is not None else None
        if kind == "TYPE":
            t = _clean(phrase, lowercase=True)
            return Type(t) if t else None
        if kind == "ABOUT":
            topic = _clean(phrase)
            return Match(topic) if topic else None
        if kind == "DISCUSS":
            topic = _clean(phrase)
            return Match(topic) if topic else None
        return None


def compile_query(text: str) -> Op:
    """Module-level convenience: compile ``text`` to an ``Op`` tree."""
    return QueryCompiler().compile(text)


__all__ = ["QueryCompiler", "CompileError", "compile_query"]

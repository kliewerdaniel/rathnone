"""Deterministic knowledge-query and evidence engine (Rathnone, additive).

This submodule is INDEPENDENT of the finance / authorization gateway. It
provides the missing artifact in the broader stack:

  * a serializable **query-algebra IR** (AND / OR / NOT / TYPE / SOURCE /
    MATCH / CONNECTED_TO / DERIVED_FROM / SAME_AS / NEAR / SCORE / TIME /
    PATH) that an LLM *constructs* but never *executes*;
  * a **deterministic executor** over an in-memory knowledge graph that compiles
    the query to an inspectable execution plan and emits an ``EvidenceRecord``
    (included / excluded entities, predicates evaluated, exact reasons for
    inclusion or exclusion, source provenance, reproducible hash).

Design principle (the research thesis): the probabilistic model builds the
query; a deterministic layer proves which knowledge actually supports it. The
LLM is responsible for *constructing* a logical query, never for *deciding*
whether the query was correctly executed.
"""

from .algebra import (
    Op,
    OpKind,
    And,
    Or,
    Not,
    Type,
    Source,
    Match,
    ConnectedTo,
    DerivedFrom,
    SameAs,
    Near,
    ScoreAtLeast,
    TimeRange,
    PathTo,
)
from .executor import (
    Entity,
    Edge,
    KnowledgeGraph,
    EvidenceRecord,
    QueryExecutor,
    VerifyResult,
    ReconcileResult,
)
from .loader import (
    graph_from_skc_artifact,
    load_artifact,
)
from .compiler import (
    QueryCompiler,
    CompileError,
    compile_query,
)

__all__ = [
    "Op",
    "OpKind",
    "And",
    "Or",
    "Not",
    "Type",
    "Source",
    "Match",
    "ConnectedTo",
    "DerivedFrom",
    "SameAs",
    "Near",
    "ScoreAtLeast",
    "TimeRange",
    "PathTo",
    "Entity",
    "Edge",
    "KnowledgeGraph",
    "EvidenceRecord",
    "QueryExecutor",
    "VerifyResult",
    "ReconcileResult",
    "graph_from_skc_artifact",
    "load_artifact",
    "QueryCompiler",
    "CompileError",
    "compile_query",
]

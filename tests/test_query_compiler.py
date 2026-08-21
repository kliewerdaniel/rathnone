"""Tests for the NL -> query-algebra compiler (Step 3 of the engine plan).

The compiler is deterministic and LLM-free: it maps a constrained natural
language request onto an ``Op`` tree. The executor then runs that tree. The key
property under test is that the *model's phrasing* never touches retrieval --
compilation is a pure, auditable transform.
"""

import pytest

from src.query.algebra import Op, OpKind
from src.query.compiler import QueryCompiler, CompileError, compile_query
from src.query.executor import Entity, KnowledgeGraph, QueryExecutor


def gd_corpus() -> KnowledgeGraph:
    g = KnowledgeGraph()
    g.add(Entity(id="p_arxiv", type="paper", source="arxiv",
                 text="gradient descent for optimization", score=0.9))
    g.add(Entity(id="p_blog", type="paper", source="blog",
                 text="gradient descent for optimization", score=0.2))
    g.add(Entity(id="p_convex", type="paper", source="conference",
                 text="convex optimization and gradient descent", score=0.8))
    g.link("p_arxiv", "p_convex", kind="related")
    g.link("p_blog", "p_convex", kind="related")
    return g


def test_gradient_descent_example_compiles_and_executes():
    text = ("Find research about gradient descent that discusses optimization, "
            "exclude papers whose primary source is arXiv, and prioritize papers "
            "connected to convex optimization.")
    op = compile_query(text)

    # Structure: AND of head Match, DISCUSS Match, EXCLUDE_SRC NOT(Source),
    # and CONNECTED_TO(Match).
    assert op.kind == OpKind.AND
    kinds = {c.kind for c in op.children}
    assert OpKind.MATCH in kinds
    assert OpKind.NOT in kinds
    assert OpKind.CONNECTED_TO in kinds

    # The exclude clause targets arXiv specifically.
    not_src = next(c for c in op.children if c.kind == OpKind.NOT)
    assert not_src.children[0].kind == OpKind.SOURCE
    assert not_src.children[0].arg == "arxiv"

    # Executing the compiled tree over the corpus: arXiv paper excluded,
    # the other two (connected to convex optimization) survive.
    rec = QueryExecutor(gd_corpus()).execute(op)
    assert "p_arxiv" not in rec.included_ids
    assert "p_blog" in rec.included_ids
    assert "p_convex" in rec.included_ids


def test_compile_is_deterministic():
    text = ("Find research about gradient descent that discusses optimization, "
            "exclude papers whose primary source is arXiv, and prioritize papers "
            "connected to convex optimization.")
    a = compile_query(text).to_dict()
    b = compile_query(text).to_dict()
    assert a == b


def test_compile_round_trips_through_op_dict():
    text = "research about gradient descent connected to convex optimization"
    op = Op.from_dict(compile_query(text).to_dict())
    rec1 = QueryExecutor(gd_corpus()).execute(compile_query(text))
    rec2 = QueryExecutor(gd_corpus()).execute(op)
    assert rec1.deterministic_hash() == rec2.deterministic_hash()


def test_simple_topic_without_connectors_is_single_match():
    op = compile_query("gradient descent")
    assert op.kind == OpKind.MATCH
    assert op.arg == "gradient descent"


def test_exclude_connected_to():
    op = compile_query("optimization, but not connected to convex")
    # head match + NOT(ConnectedTo(Match("convex")))
    assert op.kind == OpKind.AND
    not_clause = next((c for c in op.children if c.kind == OpKind.NOT), None)
    assert not_clause is not None
    assert not_clause.children[0].kind == OpKind.CONNECTED_TO


def test_from_source_connector():
    op = compile_query("research about gradient descent from arxiv")
    # head + SOURCE clause
    src = next((c for c in op.children if c.kind == OpKind.SOURCE), None)
    assert src is not None
    assert src.arg == "arxiv"


def test_score_and_time_connectors():
    op = compile_query("optimization with score at least 0.5 after 2020")
    score = next((c for c in op.children if c.kind == OpKind.SCORE), None)
    time = next((c for c in op.children if c.kind == OpKind.TIME), None)
    assert score is not None and score.threshold == 0.5
    assert time is not None and time.lo == 2020.0


def test_empty_query_raises():
    with pytest.raises(CompileError):
        compile_query("")
    with pytest.raises(CompileError):
        compile_query("   ")


def test_command_verb_stripped_from_topic():
    a = compile_query("Find research about gradient descent")
    b = compile_query("gradient descent")
    # The command verb and filler are normalized away.
    assert a.kind == b.kind
    assert a.arg == b.arg

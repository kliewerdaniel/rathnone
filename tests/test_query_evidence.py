"""Deterministic knowledge-query + evidence engine — behavioral + property tests.

These assert the research thesis: an LLM *constructs* a logical query; Rathnone
*executes* it deterministically and returns an inspectable evidence record with
explicit reasons for inclusion AND exclusion. No finance code is touched.
"""

from src.query import (
    And, Or, Not, Type, Source, Match, ScoreAtLeast, TimeRange,
    ConnectedTo, DerivedFrom, SameAs, PathTo, Near,
    KnowledgeGraph, Entity, Edge, QueryExecutor, Op, OpKind,
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------
def gd_corpus() -> KnowledgeGraph:
    """The prompt's example: gradient descent / optimization / convex, with
    arXiv as an excludable primary source and a convex-optimization link."""
    g = KnowledgeGraph()
    g.add(Entity(id="p_arxiv", type="paper", source="arxiv",
                 text="gradient descent for deep learning optimization",
                 score=0.9, timestamp=2020.0,
                 neighbor_terms={"gradient", "descent", "optimization"}))
    g.add(Entity(id="p_convex", type="paper", source="jmlr",
                 text="gradient descent and convex optimization convergence",
                 score=0.8, timestamp=2018.0,
                 neighbor_terms={"gradient", "convex", "optimization"}))
    g.add(Entity(id="p_blog", type="blog", source="personal",
                 text="a gentle intro to gradient descent",
                 score=0.2, timestamp=2023.0,
                 neighbor_terms={"gradient", "descent"}))
    g.add(Entity(id="p_crypto", type="paper", source="arxiv",
                 text="lattice cryptography post-quantum",
                 score=0.7, timestamp=2021.0,
                 neighbor_terms={"lattice", "crypto"}))
    # link: convex paper CONNECTED_TO gradient paper (via topic)
    g.link("p_convex", "p_arxiv", kind="related")
    g.link("p_convex", "p_blog", kind="related")
    g.link("p_arxiv", "p_blog", kind="related")
    return g


# ---------------------------------------------------------------------------
# 1. The prompt's example, compiled to a logical query
# ---------------------------------------------------------------------------
def test_gradient_descent_query_compiles_and_excludes_arxiv():
    g = gd_corpus()
    ex = QueryExecutor(g)

    # "research about gradient descent that discusses optimization,
    #  exclude papers whose primary source is arXiv,
    #  prioritize papers connected to convex optimization"
    q = And(
        Match("gradient descent"),
        Match("optimization"),
        Not(Source("arxiv")),                       # exclude arxiv-primary
        ConnectedTo(Match("convex"), depth=2),      # prefer convex-linked
    )

    rec = ex.execute(q)

    # Included: only p_convex (matches both MATCH, not arxiv, linked to "convex")
    included = {e.id for e in rec.included}
    assert included == {"p_convex"}, included

    # Excluded with EXPLICIT reasons:
    excluded = {e.id: e for e in rec.excluded}
    assert "p_arxiv" in excluded and "p_blog" in excluded and "p_crypto" in excluded

    # p_arxiv excluded because its PRIMARY SOURCE is arxiv (the NOT(Source) fired)
    arxiv_entry = excluded["p_arxiv"]
    assert "SOURCE" in arxiv_entry.predicates, arxiv_entry.predicates

    # p_blog fails the optimization MATCH (no "optimization" in text)
    blog_reasons = " ".join(excluded["p_blog"].reasons).lower()
    assert "optimization" in blog_reasons, blog_reasons

    # p_crypto fails both MATCH predicates
    crypto_reasons = " ".join(excluded["p_crypto"].reasons).lower()
    assert "gradient" in crypto_reasons or "optimization" in crypto_reasons, crypto_reasons

    # Every entity carries a reason (inclusion OR exclusion) -- no silent drops.
    for e in rec.included + rec.excluded:
        assert e.reasons, f"{e.id} has no reason"
        assert e.predicates, f"{e.id} has no predicate tag"


# ---------------------------------------------------------------------------
# 2. Algebra laws (pure, deterministic, no LLM)
# ---------------------------------------------------------------------------
def test_and_associativity():
    g = gd_corpus()
    a = Match("gradient"); b = Match("optimization"); c = Source("arxiv")
    lhs = QueryExecutor(g).execute(And(And(a, b), c))
    rhs = QueryExecutor(g).execute(And(a, And(b, c)))
    assert lhs.included_ids == rhs.included_ids
    assert lhs.deterministic_hash() == rhs.deterministic_hash()


def test_or_associativity():
    g = gd_corpus()
    a = Source("arxiv"); b = Source("jmlr"); c = Type("blog")
    lhs = QueryExecutor(g).execute(Or(Or(a, b), c))
    rhs = QueryExecutor(g).execute(Or(a, Or(b, c)))
    assert lhs.included_ids == rhs.included_ids


def test_demorgan_not_and_equals_or_not():
    # NOT(AND(a,b)) should accept exactly the entities that fail a OR fail b,
    # i.e. the complement of (a AND b).
    g = gd_corpus()
    a = Match("gradient"); b = Match("optimization")
    not_and = QueryExecutor(g).execute(Not(And(a, b)))
    or_not = QueryExecutor(g).execute(Or(Not(a), Not(b)))
    assert not_and.included_ids == or_not.included_ids, \
        (not_and.included_ids, or_not.included_ids)


def test_not_double_negation():
    g = gd_corpus()
    inner = Match("gradient")
    once = QueryExecutor(g).execute(Not(Not(inner)))
    twice = QueryExecutor(g).execute(inner)
    assert once.included_ids == twice.included_ids


def test_idempotent_and():
    g = gd_corpus()
    a = Match("gradient")
    one = QueryExecutor(g).execute(And(a, a))
    two = QueryExecutor(g).execute(a)
    assert one.included_ids == two.included_ids


# ---------------------------------------------------------------------------
# 3. Determinism / reproducibility
# ---------------------------------------------------------------------------
def test_reproducible_hash_without_insertion_order():
    def build() -> KnowledgeGraph:
        g = KnowledgeGraph()
        g.add(Entity(id="a", type="paper", source="jmlr",
                     text="gradient descent optimization", score=0.5))
        g.add(Entity(id="b", type="paper", source="arxiv",
                     text="gradient descent", score=0.4))
        return g
    q = And(Match("gradient"), Not(Source("arxiv")))
    h1 = QueryExecutor(build()).execute(q).deterministic_hash()
    h2 = QueryExecutor(build()).execute(q).deterministic_hash()
    assert h1 == h2


def test_serialization_roundtrip():
    q = And(Match("gradient"), Or(Source("arxiv"), Type("blog")),
            ConnectedTo(Match("convex"), depth=2))
    blob = q.to_dict()
    q2 = Op.from_dict(blob)
    assert q2.to_dict() == blob
    # and it still executes
    assert QueryExecutor(gd_corpus()).execute(q2).plan


# ---------------------------------------------------------------------------
# 4. Graph operators
# ---------------------------------------------------------------------------
def test_connected_to_finds_linked_entity():
    g = gd_corpus()
    # p_convex itself matches "convex"; p_blog and p_arxiv are 1-2 hops from it.
    q = ConnectedTo(Match("convex"), depth=2)
    rec = QueryExecutor(g).execute(q)
    # All papers are connected (within depth 2) to the convex node via p_convex.
    assert "p_convex" in rec.included_ids
    assert "p_blog" in rec.included_ids
    assert "p_arxiv" in rec.included_ids
    # Only the unrelated crypto paper is excluded.
    assert "p_crypto" not in rec.included_ids


def test_derived_from_and_same_as_scoped_by_edge_kind():
    g = KnowledgeGraph()
    g.add(Entity(id="orig", type="paper", text="orig", source="jmlr"))
    g.add(Entity(id="deriv", type="paper", text="deriv", source="jmlr"))
    g.add(Entity(id="alias", type="paper", text="alias", source="jmlr"))
    g.link("deriv", "orig", kind="derived_from")
    g.link("alias", "orig", kind="same_as")
    ex = QueryExecutor(g)
    # CONNECTED_TO(any) includes deriv+alias; DERIVED_FROM(target=orig) only deriv
    assert "deriv" in ex.execute(ConnectedTo(Match("orig"), depth=1)).included_ids
    assert "deriv" in ex.execute(DerivedFrom(Match("orig"), depth=1)).included_ids
    assert "alias" not in ex.execute(DerivedFrom(Match("orig"), depth=1)).included_ids
    assert "alias" in ex.execute(SameAs(Match("orig"), depth=1)).included_ids


def test_path_to_shortest_path():
    g = KnowledgeGraph()
    g.add(Entity(id="s", type="paper", text="start"))
    g.add(Entity(id="m", type="paper", text="mid"))
    g.add(Entity(id="t", type="paper", text="target"))
    g.link("s", "m"); g.link("m", "t")
    ex = QueryExecutor(g)
    # depth 1 from s cannot reach target (needs 2 hops); depth 2 can
    assert "s" not in ex.execute(PathTo(Match("target"), max_len=1)).included_ids
    assert "s" in ex.execute(PathTo(Match("target"), max_len=2)).included_ids


# ---------------------------------------------------------------------------
# 5. Ranking predicates annotate + filter deterministically
# ---------------------------------------------------------------------------
def test_score_threshold_filters():
    g = gd_corpus()
    q = And(Match("gradient"), ScoreAtLeast(0.5))
    rec = QueryExecutor(g).execute(q)
    # only p_arxiv(0.9) + p_convex(0.8) survive; p_blog(0.2) excluded by SCORE
    assert "p_blog" not in rec.included_ids
    assert "p_arxiv" in rec.included_ids and "p_convex" in rec.included_ids
    why = " ".join(
        r for e in rec.excluded if e.id == "p_blog" for r in e.reasons
    ).lower()
    assert "score" in why, why


def test_time_range_filters():
    g = gd_corpus()
    q = And(Match("gradient"), TimeRange(lo=2022.0))
    rec = QueryExecutor(g).execute(q)
    # only p_blog (2023) survives the time window
    assert rec.included_ids == {"p_blog"}, rec.included_ids


def test_near_keyword_neighborhood():
    g = gd_corpus()
    q = Near("crypto")
    rec = QueryExecutor(g).execute(q)
    assert rec.included_ids == {"p_crypto"}, rec.included_ids


# ---------------------------------------------------------------------------
# 6. Evidence completeness invariant
# ---------------------------------------------------------------------------
def test_every_entity_has_a_reason():
    g = gd_corpus()
    rec = QueryExecutor(g).execute(And(Match("gradient"), Not(Source("arxiv"))))
    total = len(rec.included) + len(rec.excluded)
    assert total == len(g.all()), (total, len(g.all()))
    for e in rec.included + rec.excluded:
        assert e.reasons, f"{e.id} silent"

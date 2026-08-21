"""v3 Epistemic Hygiene layer — knowledge-poisoning defense (docs/16).

These prove the layer behaves correctly when ENABLED (the default runtime is
disabled, so the v1/v2 suites are unaffected). Each test asserts a distinct
poisoning seam is caught fail-closed, plus the all-corroborated happy path and
the fail-closed-no-sources path.
"""

import pytest

from src.finance.action import FinancialAction
from src.service.pipeline import AuthorizationPipeline
from src.hygiene import CorroborationLayer


def _action(**kw) -> FinancialAction:
    base = dict(
        action_id="act1", tenant_id="t1", actor="a1", strategy_id="s1",
        capability="rathnone.chain_settle", instrument="ETH",
        side="transfer", quantity=1.0, price_limit=1000.0,
        currency="USD", settlement_asset="wei",
        destination="0x" + "cd" * 20, nonce=1, timestamp=1000, expiry=0,
        risk_class="standard", evidence={},
    )
    base.update(kw)
    return FinancialAction(**base)


# Quorum=2 DISTINCT sources clustered around 1000 (band 50bps => [995,1005]).
# ADR 24: each top-level key is an INDEPENDENT origin; two quotes from one feed
# (or a repeated value) count ONCE. These are two distinct sources.
_SOURCES = {"coinbase": {"ETH": 1000.0}, "kraken": {"ETH": 1000.0}}
_MASTER = {"ETH", "BTC"}


def _enabled(**kw) -> CorroborationLayer:
    kw.setdefault("price_sources", _SOURCES)
    kw.setdefault("instrument_master", _MASTER)
    return CorroborationLayer(
        enabled=True, price_band_bps=50, quorum=2, **kw)


def test_disabled_is_passthrough():
    """Default runtime: layer off => AUTO passes untouched (narrowing trivial)."""
    layer = CorroborationLayer(enabled=False)
    v = layer.evaluate(_action(instrument="PHANTOM", price_limit=1e9,
                               destination="0xevil"), input_verdict="AUTO")
    assert v.ok is True
    assert v.verdict == "AUTO"
    assert v.checks_run == 0


def test_instrument_unknown_blocked():
    layer = _enabled()
    v = layer.evaluate(_action(instrument="PHANTOM"), allowlist={"0x" + "cd" * 20})
    assert v.ok is False
    assert v.verdict == "BLOCKED"
    codes = {x.code for x in v.violations}
    assert "instrument_unknown" in codes


def test_price_out_of_band_blocked():
    layer = _enabled()
    v = layer.evaluate(_action(price_limit=5000.0),  # far outside [995,1005]
                       allowlist={"0x" + "cd" * 20})
    assert v.ok is False
    assert "price_out_of_band" in {x.code for x in v.violations}


def test_destination_off_allowlist_blocked():
    layer = _enabled()
    v = layer.evaluate(_action(destination="0x" + "ab" * 20),
                       allowlist={"0x" + "cd" * 20})
    assert v.ok is False
    assert "destination_off_allowlist" in {x.code for x in v.violations}


def test_destination_untrusted_when_allowlist_empty():
    """Fail-closed: hygiene on but tenant has no allowlist => block."""
    layer = _enabled()
    v = layer.evaluate(_action(destination="0x" + "cd" * 20), allowlist=set())
    assert v.ok is False
    assert "destination_untrusted" in {x.code for x in v.violations}


def test_quantity_intent_mismatch_blocked():
    layer = _enabled()
    v = layer.evaluate(_action(quantity=5.0, evidence={"intended_quantity": 1.0}),
                       allowlist={"0x" + "cd" * 20})
    assert v.ok is False
    assert "quantity_intent_mismatch" in {x.code for x in v.violations}


def test_high_risk_without_evidence_blocked():
    layer = _enabled()
    v = layer.evaluate(_action(risk_class="high", evidence={}),
                       allowlist={"0x" + "cd" * 20})
    assert v.ok is False
    assert "evidence_ungrounded" in {x.code for x in v.violations}


def test_fail_closed_no_feeds():
    """Configured feeds absent for instrument => BLOCKED, not AUTO."""
    layer = CorroborationLayer(enabled=True, instrument_master=_MASTER,
                               feeds={}, quorum=2)
    v = layer.evaluate(_action(instrument="ETH"), allowlist={"0x" + "cd" * 20})
    assert v.ok is False
    assert "price_unverifiable" in {x.code for x in v.violations}


def test_quorum_below_threshold_blocked():
    """Only 1 independent feed but quorum=2 => fail-closed."""
    layer = CorroborationLayer(enabled=True, instrument_master=_MASTER,
                               feeds={"ETH": [1000.0]}, quorum=2)
    v = layer.evaluate(_action(price_limit=1000.0),
                       allowlist={"0x" + "cd" * 20})
    assert v.ok is False
    assert "price_unverifiable" in {x.code for x in v.violations}


def test_all_corroborated_passes():
    """Valid instrument + in-band price + allowlisted dest + grounded => AUTO."""
    layer = _enabled()
    v = layer.evaluate(_action(price_limit=1000.0),
                       allowlist={"0x" + "cd" * 20})
    assert v.ok is True
    assert v.verdict == "AUTO"
    assert v.violations == []
    assert any(p["claim"] == "PRICE_QUOTE" for p in v.provenance)


def test_narrowing_never_widens_blocked():
    """A frozen BLOCKED stays BLOCKED (narrowing-only)."""
    layer = _enabled()
    v = layer.evaluate(_action(instrument="PHANTOM"),
                       allowlist={"0x" + "cd" * 20}, input_verdict="BLOCKED")
    assert v.ok is False
    assert v.verdict == "BLOCKED"


# --- pipeline-level: hygiene blocks a poisoned action through the real gate ---

def _pipe_with_hygiene(tenant, layer) -> AuthorizationPipeline:
    from src.security.operator import OperatorAuthority
    from src.security import replay as _replay
    from src.evidence.chain import EvidenceGraph
    from src.risk.engine import RiskEngine
    from src.config import TenantLimits
    from src.venue.adapter import SimulatedVenue
    return AuthorizationPipeline(
        tenant, operator=OperatorAuthority(), registry=_replay.ActionRegistry(),
        evidence=EvidenceGraph(), limits=TenantLimits(), risk_engine=RiskEngine(),
        hygiene=layer, breaker=None, velocity=None,
        venue=SimulatedVenue(), clock_now=1000)


def test_pipeline_blocks_poisoned_destination_when_hygiene_enabled():
    """End-to-end: spine returns AUTO, but hygiene (enabled) BLOCKS an off-allowlist
    destination. Proves the knowledge-poisoning gate actually fires in the pipe."""
    from src.service.tenant import TenantRegistry

    reg = TenantRegistry()
    t = reg.create(aum=10_000_000.0)
    t.settlement_allowlist = {"0x" + "cd" * 20}  # only this dest trusted
    layer = _enabled(price_sources={"coinbase": {"USDC": 1.0}, "kraken": {"USDC": 1.0}},
                    instrument_master={"USDC"})
    pipe = _pipe_with_hygiene(t, layer)

    a = FinancialAction(
        action_id="p1", tenant_id=t.tenant_id, actor="strategy-alpha",
        capability="rathnone.chain_settle", instrument="USDC", side="transfer",
        quantity=1_000_000.0, price_limit=1.0, currency="wei",
        settlement_asset="wei", destination="0x" + "ab" * 20,  # attacker dest
        nonce=1, timestamp=1000, expiry=0, risk_class="standard")
    res = pipe.run(a, denylist=())
    assert res.hygiene_ok is False
    assert res.verdict == "BLOCKED"
    assert res.state.value == "REJECTED"
    assert "destination_off_allowlist" in {v["code"] for v in res.hygiene_violations}


def test_pipeline_passes_corroborated_when_hygiene_enabled():
    """End-to-end happy path with hygiene ON: valid instrument + in-band price +
    allowlisted dest => reaches SETTLED (no poisoning)."""
    from src.service.tenant import TenantRegistry

    reg = TenantRegistry()
    t = reg.create(aum=10_000_000.0)
    t.settlement_allowlist = {"0x" + "cd" * 20}
    layer = _enabled(price_sources={"coinbase": {"USDC": 1.0}, "kraken": {"USDC": 1.0}},
                    instrument_master={"USDC"})
    pipe = _pipe_with_hygiene(t, layer)

    a = FinancialAction(
        action_id="p2", tenant_id=t.tenant_id, actor="strategy-alpha",
        capability="rathnone.chain_settle", instrument="USDC", side="transfer",
        quantity=1_000_000.0, price_limit=1.0, currency="wei",
        settlement_asset="wei", destination="0x" + "cd" * 20,
        nonce=1, timestamp=1000, expiry=0, risk_class="standard")
    res = pipe.run(a, denylist=())
    assert res.hygiene_ok is True
    assert res.state.value == "SETTLED"
    assert res.reconciliation == "MATCH"


# --- ADR 24: quorum counts DISTINCT sources, not repeated values -------------

def test_quorum_requires_distinct_sources_not_repeats():
    """ADR 24: two quotes from the SAME origin must NOT satisfy quorum=2."""
    layer = CorroborationLayer(
        enabled=True, instrument_master=_MASTER, quorum=2,
        price_sources={"coinbase": {"ETH": 1000.0, "ETH": 1000.0}})
    v = layer.evaluate(_action(price_limit=1000.0),
                       allowlist={"0x" + "cd" * 20})
    assert v.ok is False
    assert "price_unverifiable" in {x.code for x in v.violations}


def test_two_distinct_sources_satisfy_quorum():
    """ADR 24: two genuinely distinct origins => quorum met, in-band passes."""
    layer = CorroborationLayer(
        enabled=True, instrument_master=_MASTER, quorum=2,
        price_sources={"coinbase": {"ETH": 1000.0}, "kraken": {"ETH": 1000.0}})
    v = layer.evaluate(_action(price_limit=1000.0),
                       allowlist={"0x" + "cd" * 20})
    assert v.ok is True
    assert any(p.get("n_sources") == 2 for p in v.provenance)


def test_three_sources_with_one_outlier_passes():
    """ADR 24: median over 3 distinct sources ignores one bad outlier (band)."""
    layer = CorroborationLayer(
        enabled=True, instrument_master=_MASTER, quorum=3,
        price_sources={"a": {"ETH": 1000.0}, "b": {"ETH": 1000.0},
                       "c": {"ETH": 1100.0}})
    v = layer.evaluate(_action(price_limit=1000.0),
                       allowlist={"0x" + "cd" * 20})
    assert v.ok is True  # median 1000, band ±50 -> 1000 in tolerance


def test_legacy_anonymous_feed_counts_as_single_source():
    """Back-compat: a legacy `feeds` list is ONE origin; quorum=2 => BLOCKED."""
    layer = CorroborationLayer(
        enabled=True, instrument_master=_MASTER, quorum=2,
        feeds={"ETH": [999.0, 1000.0, 1001.0]})
    v = layer.evaluate(_action(price_limit=1000.0),
                       allowlist={"0x" + "cd" * 20})
    assert v.ok is False
    assert "price_unverifiable" in {x.code for x in v.violations}


# --- ADR 24: env-driven config readers (fail-closed) -------------------------

def test_hygiene_env_sources_parsed(monkeypatch):
    from src.config import hygiene_price_sources, hygiene_quorum
    monkeypatch.setenv("RATHNONE_HYGIENE_PRICE_SOURCES",
                       '{"coinbase": {"ETH": 1000.0}, "kraken": {"ETH": 1001.0}}')
    src = hygiene_price_sources()
    assert set(src.keys()) == {"coinbase", "kraken"}
    assert src["coinbase"]["ETH"] == 1000.0


def test_hygiene_env_sources_empty_by_default(monkeypatch):
    from src.config import hygiene_price_sources
    monkeypatch.delenv("RATHNONE_HYGIENE_PRICE_SOURCES", raising=False)
    assert hygiene_price_sources() == {}


def test_hygiene_env_sources_bad_json_raises(monkeypatch):
    from src.config import hygiene_price_sources
    monkeypatch.setenv("RATHNONE_HYGIENE_PRICE_SOURCES", "{not json")
    with pytest.raises(ValueError):
        hygiene_price_sources()


def test_hygiene_env_quorum_below_one_raises(monkeypatch):
    from src.config import hygiene_quorum
    monkeypatch.setenv("RATHNONE_HYGIENE_QUORUM", "0")
    with pytest.raises(ValueError):
        hygiene_quorum()

"""Direct coverage for the P1/P2 hardening added after ADR 17.

  - d9: `FinancialAction.as_intent()` emits an exact integer wei value (Decimal
        floor), never a float-rounded string.
  - d6: `assert_no_pii` recurses into nested dict/list structures (an adversary
        cannot smuggle a PII key inside a sub-object of advisory evidence).
  - d8: `Clock(monotonic=True)` advances on real time and rejects manual
        `advance()`; the manual mode is unchanged for tests.
"""
from __future__ import annotations

import pytest

from src.finance.action import FinancialAction
from src.security.guards import assert_no_pii, Clock


def _settle_action(quantity, price_limit) -> FinancialAction:
    return FinancialAction(
        action_id="a", tenant_id="t", actor="s",
        capability="rathnone.chain_settle", side="settle",
        quantity=quantity, price_limit=price_limit,
        currency="wei", settlement_asset="wei",
        destination="0x" + "ab" * 20, nonce=1,
    )


def test_as_intent_wei_value_is_exact_integer():
    # 1.1 * 1.1 == 1.21 in real math; a naive float*int() would yield a token
    # with fractional wei. We floor to an exact integer and emit a digit string.
    a = _settle_action(1.1, 1.1)
    intent = a.as_intent()
    assert intent["value"] == "1"  # floor(1.21) = 1 wei, exact
    assert intent["value"].isdigit()


def test_as_intent_wei_rounding_is_floor_not_float_artifact():
    # 3.0 * 0.1 = 0.30000000000000004 in binary float; floor must be 0, not 1.
    a = _settle_action(3.0, 0.1)
    assert a.as_intent()["value"] == "0"


def test_as_intent_non_wei_keeps_quantity_string():
    a = FinancialAction(
        action_id="b", tenant_id="t", actor="s",
        capability="rathnone.trade_execute", side="buy",
        quantity=2.5, price_limit=10.0, currency="USD",
        instrument="ETH", destination="0x" + "ab" * 20, nonce=1)
    intent = a.as_intent()
    assert intent["value"] == "2.5"


def test_recursive_pii_scan_rejects_nested_key():
    # top-level safe, but a PII key is buried inside a nested dict
    nested = {
        "to": "0x" + "ab" * 20,
        "evidence": {"market": "ok", "subject": {"email": "a@b.com"}},
    }
    with pytest.raises(ValueError):
        assert_no_pii(nested)


def test_recursive_pii_scan_rejects_list_nested_key():
    nested = {
        "to": "0x" + "ab" * 20,
        "records": [{"kyc": "id-123"}, {"ok": True}],
    }
    with pytest.raises(ValueError):
        assert_no_pii(nested)


def test_recursive_pii_scan_allows_clean_nested():
    clean = {
        "to": "0x" + "ab" * 20,
        "evidence": {"market": "ok", "depth": {"bid": 1, "ask": 2}},
    }
    assert_no_pii(clean)  # no raise


def test_clock_monotonic_advances_real_time():
    clk = Clock(monotonic=True)
    t0 = clk.now()
    import time
    time.sleep(0.01)
    assert clk.now() > t0  # real time advances
    with pytest.raises(ValueError):
        clk.advance(1)  # manual advance unavailable in monotonic mode


def test_clock_manual_mode_unchanged():
    clk = Clock()
    assert clk.now() == 0
    clk.advance(5)
    assert clk.now() == 5

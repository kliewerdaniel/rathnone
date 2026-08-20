"""Cross-action reconciliation view (v2 P2).

The /reconciliation endpoint aggregates the durable per-action reconciliation
codes already committed to the tenant ledger. It must:
  - report all_matched=True when every pipeline action settled as authorized
  - treat an unrecognized reconciliation code as a divergence (fail-closed)
  - list each divergence referencing the action it concerns
The aggregator itself is exercised directly (no venue needed) AND through the
real HTTP endpoint.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from src.service.app import app, _registry, _meters, _breaker
from src.venue.adapter import summarize_reconciliation, ReconciliationCode


def _reset():
    _breaker.resume()
    _registry._tenants.clear()
    _meters.clear()


def test_summarize_fails_closed_on_unknown_code():
    recs = [
        {"event": "v2_pipeline", "action_id": "a1", "capability": "rathnone.chain_settle",
         "reconciliation": ReconciliationCode.MATCH.value},
        {"event": "v2_pipeline", "action_id": "a2", "capability": "rathnone.chain_settle",
         "reconciliation": "TOTALLY_UNEXPECTED_CODE"},
        {"event": "authorization", "request_id": "x"},  # legacy, ignored
    ]
    s = summarize_reconciliation(recs)
    assert s["total_actions"] == 2, s
    assert s["matched"] == 1
    assert s["divergence_count"] == 1
    assert s["divergences"][0]["action_id"] == "a2"
    assert s["all_matched"] is False


def test_summarize_divergence_listing():
    recs = [
        {"event": "v2_pipeline", "action_id": "a1", "capability": "rathnone.chain_settle",
         "reconciliation": ReconciliationCode.UNEXPECTED_DESTINATION.value,
         "reconciliation_detail": "venue dest 0x99.. != expected 0xab..",
         "venue_state": "SETTLED"},
        {"event": "v2_pipeline", "action_id": "a2", "capability": "rathnone.trade_execute",
         "reconciliation": ReconciliationCode.MATCH.value},
    ]
    s = summarize_reconciliation(recs)
    assert s["total_actions"] == 2 and s["matched"] == 1
    assert s["divergence_count"] == 1
    d = s["divergences"][0]
    assert d["action_id"] == "a1" and d["code"] == "UNEXPECTED_DESTINATION"
    assert d["detail"] == "venue dest 0x99.. != expected 0xab.."
    assert s["per_code"].get("MATCH") == 1
    assert s["per_code"].get("UNEXPECTED_DESTINATION") == 1


def test_reconciliation_endpoint_all_matched():
    _reset()
    c = TestClient(app)
    r = c.post("/tenants", json={"aum": 5_000_000})
    tid = r.json()["tenant_id"]
    # Run a faithful pipeline action -> MATCH committed.
    payload = {"action_id": "act1", "actor": "a", "capability": "rathnone.chain_settle",
               "instrument": "USDC", "side": "transfer", "quantity": 1.0,
               "price_limit": 1.0, "currency": "wei", "settlement_asset": "wei",
               "destination": "0x" + "ab" * 20, "nonce": 1, "timestamp": 1000}
    au = c.post(f"/tenants/{tid}/authorize_action", json={"action": payload, "denylist": []})
    assert au.status_code == 200, au.text

    s = c.get(f"/tenants/{tid}/reconciliation").json()
    assert s["tenant_id"] == tid
    assert s["total_actions"] == 1
    assert s["matched"] == 1
    assert s["divergence_count"] == 0
    assert s["all_matched"] is True

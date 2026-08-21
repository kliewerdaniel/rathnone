"""ADR 18 — operator downgrade of a hygiene-BLOCKED action.

These prove the safety valve behaves fail-closed and preserves every invariant:

  - a valid signed downgrade (single operator) releases a price/evidence
    hygiene-BLOCKED action and re-enters at the HUMAN band -> SETTLED;
  - a DESTINATION_OWNERSHIP override REQUIRES a 2nd operator signature;
  - a spine-BLOCKED action can NEVER be downgraded;
  - a bad signature / wrong violation set / replayed nonce is refused;
  - the DowngradeRecord verifies key-free from the ledger (Inv 3).
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.finance.action import FinancialAction
from src.hygiene import CorroborationLayer, DowngradeRecord, validate_downgrade
from src.hygiene.downgrade import _SECOND_OP_CODES
from src.service.pipeline import AuthorizationPipeline
from src.service.tenant import TenantRegistry
from src.security.operator import OperatorAuthority, OperatorKeyRing
from cryptography.hazmat.primitives import serialization as _ser


def _pem(key):
    return key.public_key().public_bytes(
        encoding=_ser.Encoding.PEM,
        format=_ser.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


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


_FEEDS = {"ETH": [999.0, 1000.0, 1001.0]}
_MASTER = {"ETH", "BTC"}


def _enabled(**kw) -> CorroborationLayer:
    kw.setdefault("feeds", _FEEDS)
    kw.setdefault("instrument_master", _MASTER)
    return CorroborationLayer(enabled=True, price_band_bps=50, quorum=2, **kw)


def _op_keys(n=2):
    return [Ed25519PrivateKey.generate() for _ in range(n)]


def _pipe(tenant, layer) -> AuthorizationPipeline:
    return AuthorizationPipeline(
        tenant, operator=OperatorAuthority(), registry=__import__("src.security.replay", fromlist=["ActionRegistry"]).ActionRegistry(),
        evidence=__import__("src.evidence.chain", fromlist=["EvidenceGraph"]).EvidenceGraph(),
        limits=__import__("src.config", fromlist=["TenantLimits"]).TenantLimits(),
        risk_engine=__import__("src.risk.engine", fromlist=["RiskEngine"]).RiskEngine(),
        hygiene=layer, breaker=None, velocity=None,
        venue=__import__("src.venue.adapter", fromlist=["SimulatedVenue"]).SimulatedVenue(),
        clock_now=1000)


def _build_tenant(allowlist):
    reg = TenantRegistry()
    t = reg.create(aum=10_000_000.0)
    t.settlement_allowlist = allowlist
    return t


# --------------------------------------------------------------------------
# 1. Valid single-operator downgrade releases a price hygiene-BLOCKED action.
# --------------------------------------------------------------------------
def test_valid_downgrade_reenters_human_and_settles():
    t = _build_tenant({"0x" + "cd" * 20})
    layer = _enabled(feeds={}, instrument_master=_MASTER)  # no feed => price unverifiable BLOCK
    pipe = _pipe(t, layer)
    op = _op_keys(1)[0]
    t.operator_keys = OperatorKeyRing.from_pems([_pem(op)])

    a = _action(instrument="ETH", price_limit=1000.0, destination="0x" + "cd" * 20)
    # First confirm it is BLOCKED with no downgrade.
    res0 = pipe.run(a, denylist=())
    assert res0.hygiene_ok is False
    assert res0.verdict == "BLOCKED"

    # Now a signed operator downgrade releasing the price_unverifiable violation.
    dg = layer.sign_downgrade(a, operator_key=op,
                              violation_ids=["price_unverifiable"],
                              reason="feed outage confirmed; manual price check OK",
                              nonce=1)
    downgrade = dg
    res = pipe.run(a, denylist=(), downgrade=downgrade)
    assert res.downgraded is True
    assert res.verdict == "HUMAN"  # re-entered at HUMAN band
    assert res.state.value == "SETTLED"
    assert res.reconciliation == "MATCH"


# --------------------------------------------------------------------------
# 2. DESTINATION_OWNERSHIP override REQUIRES 2-of-2 operators.
# --------------------------------------------------------------------------
def test_destination_override_requires_second_operator():
    t = _build_tenant(set())  # empty allowlist => destination_untrusted BLOCK
    layer = _enabled()
    pipe = _pipe(t, layer)
    o1, o2 = _op_keys(2)
    t.operator_keys = OperatorKeyRing.from_pems([_pem(o1), _pem(o2)])

    a = _action(instrument="ETH", price_limit=1000.0, destination="0x" + "cd" * 20)
    res0 = pipe.run(a, denylist=())
    assert res0.hygiene_ok is False
    assert "destination_untrusted" in {v["code"] for v in res0.hygiene_violations}

    # Single operator: requires_second => refused by the pipeline. Build the
    # record directly (no second_sig) to simulate an operator attempting a solo
    # destination override.
    from src.hygiene.downgrade import _canonical
    _canon = _canonical({
        "released_hash": a.action_hash,
        "violation_ids": ["destination_untrusted"],
        "operator_id": "op-1", "reason": "benign dest",
        "timestamp": 0, "nonce": 2, "second_operator_id": ""})
    single = DowngradeRecord(
        action_hash=a.action_hash, violation_ids=["destination_untrusted"],
        operator_id="op-1", reason="benign dest", nonce=2,
        sig=o1.sign(_canon).hex(), pubkey_pem=_pem(o1))
    res1 = pipe.run(a, denylist=(), downgrade=single)
    assert res1.downgraded is False
    assert res1.verdict == "BLOCKED"
    assert "2-of-2" in (res1.blocked_reason or "")

    # Two operators: released. To fully clear the action EVERY blocking hygiene
    # code must be in the released set (F1: partial release stays BLOCKED). The
    # action is blocked on both destination_untrusted (2-of-2) and
    # price_unverifiable, so the dual downgrade releases both — and because
    # destination_untrusted requires a second sig, the dual signature supplies it.
    dual = layer.sign_downgrade(a, operator_key=o1, second_key=o2,
                                violation_ids=["destination_untrusted",
                                                "price_unverifiable"],
                                reason="benign dest", nonce=3,
                                second_operator_id="op-2")
    res2 = pipe.run(a, denylist=(), downgrade=dual)
    assert res2.downgraded is True
    assert res2.state.value == "SETTLED"


# --------------------------------------------------------------------------
# 3. Spine-BLOCKED can NEVER be downgraded (narrowing invariant).
# --------------------------------------------------------------------------
def test_spine_blocked_cannot_be_downgraded():
    t = _build_tenant({"0x" + "cd" * 20})
    layer = _enabled()
    pipe = _pipe(t, layer)
    op = _op_keys(1)[0]
    t.operator_keys = OperatorKeyRing.from_pems([_pem(op)])

    a = _action(instrument="ETH", price_limit=1000.0, destination="0x" + "cd" * 20,
                risk_class="forbidden")
    # Force a spine BLOCKED by deny-listing the capability.
    res0 = pipe.run(a, denylist=("rathnone.chain_settle",))
    assert res0.verdict == "BLOCKED"
    assert res0.hygiene_ok is True  # hygiene never ran (epistemic BLOCK short-circuits)

    dg = layer.sign_downgrade(a, operator_key=op,
                              violation_ids=[], reason="try anyway", nonce=4)
    res = pipe.run(a, denylist=("rathnone.chain_settle",), downgrade=dg)
    assert res.verdict == "BLOCKED"
    assert res.downgraded is False


# --------------------------------------------------------------------------
# 4. Bad signature / wrong violation set / replayed nonce refused (fail-closed).
# --------------------------------------------------------------------------
def test_bad_signature_refused():
    t = _build_tenant({"0x" + "cd" * 20})
    layer = _enabled(feeds={}, instrument_master=_MASTER)
    pipe = _pipe(t, layer)
    op, rogue = _op_keys(2)
    t.operator_keys = OperatorKeyRing.from_pems([_pem(op)])

    a = _action(instrument="ETH", price_limit=1000.0, destination="0x" + "cd" * 20)
    # Signature from an operator NOT on the allowlist.
    forged = layer.sign_downgrade(a, operator_key=rogue,
                                  violation_ids=["price_unverifiable"], reason="x", nonce=5)
    res = pipe.run(a, denylist=(), downgrade=forged)
    assert res.downgraded is False
    assert res.verdict == "BLOCKED"


def test_replayed_nonce_refused():
    t = _build_tenant({"0x" + "cd" * 20})
    layer = _enabled(feeds={}, instrument_master=_MASTER)
    pipe = _pipe(t, layer)
    op = _op_keys(1)[0]
    t.operator_keys = OperatorKeyRing.from_pems([_pem(op)])

    a = _action(instrument="ETH", price_limit=1000.0, destination="0x" + "cd" * 20)
    dg = layer.sign_downgrade(a, operator_key=op,
                              violation_ids=["price_unverifiable"], reason="r", nonce=6)
    res1 = pipe.run(a, denylist=(), downgrade=dg)
    assert res1.downgraded is True
    # Reuse the same nonce on a fresh action => replay refused.
    a2 = _action(action_id="act2", instrument="ETH", price_limit=1000.0,
                 destination="0x" + "cd" * 20)
    dg2 = layer.sign_downgrade(a2, operator_key=op,
                               violation_ids=["price_unverifiable"], reason="r", nonce=6)
    res2 = pipe.run(a2, denylist=(), downgrade=dg2)
    assert res2.downgraded is False
    assert "replay" in (res2.blocked_reason or "")


# --------------------------------------------------------------------------
# 5. DowngradeRecord verifies key-free from the ledger (Inv 3).
# --------------------------------------------------------------------------
def test_downgrade_key_free_verifiable_from_ledger():
    t = _build_tenant({"0x" + "cd" * 20})
    layer = _enabled(feeds={}, instrument_master=_MASTER)
    pipe = _pipe(t, layer)
    op = _op_keys(1)[0]
    t.operator_keys = OperatorKeyRing.from_pems([_pem(op)])

    a = _action(instrument="ETH", price_limit=1000.0, destination="0x" + "cd" * 20)
    dg = layer.sign_downgrade(a, operator_key=op,
                              violation_ids=["price_unverifiable"], reason="audit", nonce=7)
    pipe.run(a, denylist=(), downgrade=dg)

    # The immutability ledger carries the hygiene_downgrade record; verify it
    # key-free (reconstruct the record from recorded pubkeys and re-verify).
    recs = t.audit()
    dg_rec = next((r for r in recs if r.get("event") == "hygiene_downgrade"), None)
    assert dg_rec is not None
    # Reconstruct a DowngradeRecord from the recorded fields + verify with the
    # recorded public key only.
    recon = DowngradeRecord(
        action_hash=dg_rec["action_hash"],
        violation_ids=dg_rec["released_violations"],
        operator_id=dg_rec["operator_id"], reason=dg_rec["reason"],
        nonce=dg_rec["nonce"], sig=dg.sig, pubkey_pem=dg_rec["operator_pubkey_pem"])
    ok = recon.verify(primary_pem=dg_rec["operator_pubkey_pem"])
    assert ok is True
    # And the tenant ledger itself verifies key-free.
    assert t.verify_locally()[0] is True


# --------------------------------------------------------------------------
# 6. Unit: validate_downgrade refuses releasing a violation the action was NOT
#    blocked on (closes "downgrade benign, execute poisoned").
# --------------------------------------------------------------------------
def test_validate_refuses_unrelated_violation_release():
    t = _build_tenant({"0x" + "cd" * 20})
    layer = _enabled(feeds={}, instrument_master=_MASTER)
    op = _op_keys(1)[0]
    t.operator_keys = OperatorKeyRing.from_pems([_pem(op)])

    a = _action(instrument="ETH", price_limit=1000.0, destination="0x" + "cd" * 20)
    # Hygiene blocks ONLY price_unverifiable (no feed). Try to release a
    # different code that was never asserted.
    dg = layer.sign_downgrade(a, operator_key=op,
                              violation_ids=["instrument_unknown"], reason="x", nonce=8)
    ok, why = validate_downgrade(
        dg, action=a,
        hygiene_violations=[{"code": "price_unverifiable", "message": "m"}],
        operator_allowlist=t.operator_keys.active_pems(),
        used_nonces=set())
    assert ok is False
    assert "not blocked on" in (why or "")

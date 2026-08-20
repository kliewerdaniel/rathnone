"""Rathnone eval + integration tests.

  * test_audit_mirror_keyfree_verify         (SC3) — mirror verifies with ONLY public key
  * test_audit_mirror_detects_tamper         (Invariant 4 / A4) — fail-closed on tamper
  * test_settlement_record_verify            (Invariant 3 / A5) — independent recompute
  * test_end_to_end_gateway_adapters_mirror  — full finance path, local-first + mirror
"""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from exchange.epistemic_adapter import GovernanceAuthority
from src.finance.proposal import RathnoneFinanceProposal
from src.finance.adapters import execute_chain_settle, ExecutionRefused
from src.finance.settlement import SettlementAuthRecord
from src.gateway import GatewayContext
from src.mirror import AuditMirror, make_ledger_entry, GENESIS, load_public_key
from src.finance.capabilities import CAP_FIN_CHAIN_SETTLE


def test_audit_mirror_keyfree_verify():
    """SC3: the cloud mirror holds ONLY the public key and verifies a pushed
    chain. No signing key present on the verify path."""
    gov = GovernanceAuthority(Ed25519PrivateKey.generate())
    mirror = AuditMirror(load_public_key(gov.public_key_pem))  # public key only

    # Gateway side (local-first, holds the key) produces signed records.
    prev = GENESIS
    for i, action in enumerate(["trade-AUTO", "rebalance-AUTO", "settle-AUTO"], start=1):
        rec = make_ledger_entry(
            i, prev,
            {"event": "finance_auth", "action": action,
             "capability": CAP_FIN_CHAIN_SETTLE},
            gov.private_key)
        mirror.ingest(rec)
        prev = __import__("hashlib").sha256(
            prev + _body(rec)).digest()

    ok, reason = mirror.verify_chain()
    assert ok, reason


def _body(rec: dict) -> bytes:
    from src.mirror import _entry_body
    return _entry_body(rec)


def test_audit_mirror_detects_tamper():
    """Invariant 4 / A4: altering a record after the fact is detected."""
    gov = GovernanceAuthority(Ed25519PrivateKey.generate())
    mirror = AuditMirror(load_public_key(gov.public_key_pem))
    prev = GENESIS
    for i, action in enumerate(["a", "b"], start=1):
        rec = make_ledger_entry(i, prev, {"event": "e", "action": action}, gov.private_key)
        mirror.ingest(rec)
        prev = __import__("hashlib").sha256(prev + _body(rec)).digest()

    # Attacker tampers with a stored record's content (no re-sign).
    mirror._records[0]["action"] = "MALICIOUS"
    ok, reason = mirror.verify_chain()
    assert ok is False
    assert "signature" in reason or "chain" in reason


def test_settlement_record_verify():
    """Invariant 3 / A5: an independent verifier recomputes and matches."""
    rec = SettlementAuthRecord.build(
        decision_ref="dec-abc", capability=CAP_FIN_CHAIN_SETTLE,
        intent_hash="h-intent", verdict="AUTO", chain="evm_l2",
        contract_address="0xABC", epoch=1, ledger_prev="prev0")
    assert rec.verify(expected_intent_hash="h-intent", expected_ledger_prev="prev0")

    # Executor deception: actual calldata differs from intent_hash -> reject.
    assert not rec.verify(expected_intent_hash="h-TAMPERED", expected_ledger_prev="prev0")

    # Non-AUTO record must never carry a signature, and its integrity still
    # verifies (it is a valid ledger entry recording a BLOCKED action).
    blk = SettlementAuthRecord.build(
        decision_ref="dec-z", capability=CAP_FIN_CHAIN_SETTLE,
        intent_hash="h-intent", verdict="BLOCKED", ledger_prev="prev0")
    assert blk.signer_commitment == ""
    assert blk.verify(expected_intent_hash="h-intent", expected_ledger_prev="prev0")


def test_end_to_end_gateway_adapters_mirror():
    """Full finance path: proposal -> decide() -> adapter -> settlement record
    -> mirror. Authorization BLOCKED paths refuse execution."""
    gov = GatewayContext(GovernanceAuthority(Ed25519PrivateKey.generate()))
    mirror = AuditMirror(load_public_key(gov.gov.public_key_pem))

    # 1) Authorized settlement
    p = RathnoneFinanceProposal(
        producer="strategy", request_id="r1", capability=CAP_FIN_CHAIN_SETTLE,
        action_descriptor="transfer(USDC,50000,L2)",
        advisory_evidence={"kelly_fraction": 0.12, "regime": "trending"})
    d = gov.authorize(p, allowlist=(CAP_FIN_CHAIN_SETTLE,))
    assert d.verdict == "AUTO"

    res = execute_chain_settle(p, d.verdict, simulated=True)
    assert res.authorized and res.simulated

    rec = SettlementAuthRecord.build(
        decision_ref=d.compute_hash(), capability=CAP_FIN_CHAIN_SETTLE,
        intent_hash="h-intent", verdict=d.verdict, chain="evm_l2",
        ledger_prev="prev0")
    # Push a mirror record representing this authorization.
    ledger_rec = make_ledger_entry(
        1, GENESIS, {"event": "settlement_auth", "decision_ref": rec.compute_hash()},
        gov.gov.private_key)
    mirror.ingest(ledger_rec)
    ok, _ = mirror.verify_chain()
    assert ok

    # 2) Unauthorized path: requesting a capability not in the grant's scope
    # escalates to HUMAN (default-deny-as-escalation), and the adapter refuses
    # execution without a human approval record.
    p2 = RathnoneFinanceProposal(
        producer="attacker", request_id="r2", capability="rathnone.other",
        action_descriptor="hostile")
    d2 = gov.authorize(p2, allowlist=(CAP_FIN_CHAIN_SETTLE,))
    assert d2.verdict in ("HUMAN", "BLOCKED")  # never AUTO without authorization
    try:
        execute_chain_settle(p2, d2.verdict)
        assert False, "adapter must refuse unauthorized execution"
    except ExecutionRefused:
        pass

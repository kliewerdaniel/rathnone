"""ADR 36 — rotation-aware witness log (key binding + anchored verify).

The witness log is signed by the evidence-domain key the operator anchors via
ADR 34. ADR 36 makes each witness entry cryptographically bound to the EXACT
evidence key that served it (``key_seq`` / ``key_fingerprint`` from the ADR 34
trust log), so the log stays verifiable AFTER an evidence-key rotation:

  * a rotated witness log verifies rotation-aware (old entries under the
    rotated-out key, new entries under the rotated-in key);
  * the single-key ``verify_witness_log`` REJECTS a rotated log (it must, by
    design -- it only accepts one pinned key);
  * a forged re-attribution (entry claims key_seq=K but is signed by a different
    key) is rejected, because the binding lives inside the signed bytes;
  * a tampered historical record hash still breaks the chain.

The original single-key path and all prior ADR 35 behavior are preserved.
"""

import hashlib

import pytest

from src.query.witness import (
    WitnessLog,
    WitnessEntry,
    append_entry,
    verify_witness_log,
    verify_witness_log_anchored,
)
from src.query.authority import (
    build_bootstrap_log,
    append_rotate,
    _pem_fingerprint,
)
from src.query.attest import generate_keypair, load_private_key


def _fp(sk) -> str:
    from cryptography.hazmat.primitives import serialization
    return _pem_fingerprint(sk.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))


def _key():
    priv, pub = generate_keypair()
    return load_private_key(priv), pub


def test_entry_records_key_binding_fields():
    sk, _ = _key()
    log = append_entry(
        WitnessLog(authority_id="ev"),
        query_hash="q1", record_hash="r1", agent_id="a1",
        capabilities=[], sk=sk, authority_id="ev",
        key_seq=0, key_fingerprint="FP")
    e = log.entries[0]
    assert e.key_seq == 0 and e.key_fingerprint == "FP"
    # The binding is inside the signed bytes.
    assert "key_seq" in e.canonical_bytes().decode()
    assert "key_fingerprint" in e.canonical_bytes().decode()


def test_rotated_log_verifies_anchored_but_not_single_key():
    sk_a, pub_a = _key()
    trust = build_bootstrap_log(sk_a, signer_id="ev")
    log = append_entry(
        WitnessLog(authority_id="ev"),
        query_hash="q1", record_hash="r1", agent_id="a1",
        capabilities=[], sk=sk_a, authority_id="ev",
        key_seq=0, key_fingerprint=_fp(sk_a))

    # Rotate the evidence key.
    sk_b, pub_b = _key()
    trust = append_rotate(trust, sk_b, sk_a, signer_id="ev")
    log = append_entry(
        log, query_hash="q2", record_hash="r2", agent_id="a2",
        capabilities=[], sk=sk_b, authority_id="ev",
        key_seq=1, key_fingerprint=_fp(sk_b))

    # Rotation-aware verify: each entry resolves to its bound key.
    ok, reason = verify_witness_log_anchored(log, trust)
    assert ok, reason

    # Single-key verify (every entry under ONE pinned key) must REJECT a log
    # that spans two keys -- by design, it is the non-rotation path.
    ok_single, _ = verify_witness_log(log, pub_a)
    assert not ok_single, "single-key verify must reject a rotated log"
    ok_single_b, _ = verify_witness_log(log, pub_b)
    assert not ok_single_b, "single-key verify must reject a rotated log"


def test_anchored_verify_rejects_forged_key_rebinding():
    sk_a, _ = _key()
    trust = build_bootstrap_log(sk_a, signer_id="ev")
    log = append_entry(
        WitnessLog(authority_id="ev"),
        query_hash="q1", record_hash="r1", agent_id="a1",
        capabilities=[], sk=sk_a, authority_id="ev",
        key_seq=0, key_fingerprint=_fp(sk_a))

    sk_b, _ = _key()
    trust = append_rotate(trust, sk_b, sk_a, signer_id="ev")
    log = append_entry(
        log, query_hash="q2", record_hash="r2", agent_id="a2",
        capabilities=[], sk=sk_b, authority_id="ev",
        key_seq=1, key_fingerprint=_fp(sk_b))

    # Attack: rewrite entry 1 to CLAIM key_seq=0 (old key) WITHOUT re-signing.
    tampered = WitnessLog.from_dict(log.as_dict())
    tampered.entries[1].key_seq = 0
    ok, reason = verify_witness_log_anchored(tampered, trust)
    assert not ok, "forged re-attribution (claim old key_seq) must be rejected"
    # The claim key_seq=0 points at the bootstrap key; its fingerprint won't
    # match the entry's key_fingerprint (which is still fp_b), so resolution
    # fails. Either path must reject.
    assert "key_seq" in (reason or "")


def test_tampering_with_history_still_breaks_chain():
    sk_a, _ = _key()
    trust = build_bootstrap_log(sk_a, signer_id="ev")
    log = append_entry(
        WitnessLog(authority_id="ev"),
        query_hash="q1", record_hash="r1", agent_id="a1",
        capabilities=[], sk=sk_a, authority_id="ev",
        key_seq=0, key_fingerprint=_fp(sk_a))
    log = append_entry(
        log, query_hash="q2", record_hash="r2", agent_id="a2",
        capabilities=[], sk=sk_a, authority_id="ev",
        key_seq=0, key_fingerprint=_fp(sk_a))
    tampered = WitnessLog.from_dict(log.as_dict())
    tampered.entries[0].record_hash = "FORGED"
    ok, reason = verify_witness_log_anchored(tampered, trust)
    assert not ok, "rewriting a historical record hash must break the chain"


def test_anchored_verify_rejects_unknown_key_seq():
    sk_a, _ = _key()
    trust = build_bootstrap_log(sk_a, signer_id="ev")
    # Entry claims key_seq=9 but the trust log only has entries 0..1.
    log = append_entry(
        WitnessLog(authority_id="ev"),
        query_hash="q1", record_hash="r1", agent_id="a1",
        capabilities=[], sk=sk_a, authority_id="ev",
        key_seq=9, key_fingerprint=_fp(sk_a))
    ok, reason = verify_witness_log_anchored(log, trust)
    assert not ok, "an entry naming a key the trust log never introduced must fail"


def test_anchored_verify_accepts_all_bootstrap_key_entries():
    sk_a, _ = _key()
    trust = build_bootstrap_log(sk_a, signer_id="ev")
    log = append_entry(
        WitnessLog(authority_id="ev"),
        query_hash="q1", record_hash="r1", agent_id="a1",
        capabilities=[], sk=sk_a, authority_id="ev",
        key_seq=0, key_fingerprint=_fp(sk_a))
    ok, reason = verify_witness_log_anchored(log, trust)
    assert ok, reason

"""ADR 34 — evidence-authority trust log (hash-chained anchor/rotate/revoke).

These tests pin the trust-log discipline WITHOUT touching the frozen finance
gateway: the log is a pure evidence-domain construct (src/query/authority.py).

Coverage:
  * bootstrap log verifies against its own anchor PEM;
  * a rotated log verifies and the current trusted key advances;
  * a revoked log verifies but has NO current trusted key;
  * tampering with any historical entry / forging a root / wrong anchor => reject;
  * the live service exposes the log, and KnowledgeAgent.verify_authority()
    accepts a correctly-pinned anchor and REJECTS a mismatched one (no TOFU).
"""

import importlib

import pytest

from src.query.authority import (
    AuthorityLog,
    build_bootstrap_log,
    append_rotate,
    append_revoke,
    verify_trust_log,
    _pem_fingerprint,
)
from src.query.attest import generate_keypair, load_private_key


def _sk(pem: bytes):
    return load_private_key(pem)


def test_bootstrap_log_verifies_against_its_anchor():
    priv, pub = generate_keypair()
    log = build_bootstrap_log(_sk(priv))
    ok, reason = verify_trust_log(log, pub)
    assert ok, reason
    assert log.current_pem() == pub.decode("utf-8")
    assert log.anchor_fingerprint == _pem_fingerprint(pub)


def test_rotate_advances_current_key_and_stays_valid():
    priv_a, pub_a = generate_keypair()
    log = build_bootstrap_log(_sk(priv_a))
    priv_b, pub_b = generate_keypair()
    rotated = append_rotate(log, _sk(priv_b), _sk(priv_a))
    ok, reason = verify_trust_log(rotated, pub_a)
    assert ok, reason
    # The chain is now rooted at A; current trusted key is the rotated-in B.
    assert rotated.current_pem() == pub_b.decode("utf-8")
    assert rotated.anchor_fingerprint == _pem_fingerprint(pub_a)


def test_rotate_requires_signing_by_prior_trusted_key():
    priv_a, pub_a = generate_keypair()
    log = build_bootstrap_log(_sk(priv_a))
    priv_b, pub_b = generate_keypair()
    # Sign the rotate entry with the WRONG key (B instead of A).
    forged = append_rotate(log, _sk(priv_b), _sk(priv_b))
    ok, reason = verify_trust_log(forged, pub_a)
    assert not ok, "rotate signed by non-prior key must be rejected"


def test_revoke_ends_with_no_current_key_but_log_still_valid():
    priv_a, pub_a = generate_keypair()
    log = build_bootstrap_log(_sk(priv_a))
    revoked = append_revoke(log, _sk(priv_a))
    ok, reason = verify_trust_log(revoked, pub_a)
    assert ok, reason
    assert revoked.current_pem() is None


def test_tampering_with_history_breaks_chain():
    priv_a, pub_a = generate_keypair()
    log = build_bootstrap_log(_sk(priv_a))
    priv_b, pub_b = generate_keypair()
    rotated = append_rotate(log, _sk(priv_b), _sk(priv_a))
    # Tamper: rewrite the bootstrap PEM text (pretend A was a different key).
    tampered = AuthorityLog.from_dict(rotated.as_dict())
    tampered.entries[0].pem = pub_b.decode("utf-8")
    ok, reason = verify_trust_log(tampered, pub_a)
    assert not ok, "rewriting a historical entry must break the chain"


def test_wrong_anchor_is_rejected():
    priv_a, pub_a = generate_keypair()
    log = build_bootstrap_log(_sk(priv_a))
    _, pub_other = generate_keypair()  # a different, unattested root
    ok, reason = verify_trust_log(log, pub_other)
    assert not ok, "an unpinned anchor must be rejected (no TOFU)"


def test_agent_rejects_unpinned_anchor_over_wire():
    from src.query.agent import KnowledgeAgent
    from src.query.service import create_app

    mod = importlib.import_module("src.query.service")
    importlib.reload(mod)
    app = mod.create_app()
    from fastapi.testclient import TestClient

    agent = KnowledgeAgent(TestClient(app))
    _, pub_other = generate_keypair()  # not the served anchor
    assert agent.verify_authority(pub_other) is False


def test_agent_accepts_pinned_anchor_over_wire():
    from src.query.agent import KnowledgeAgent
    from src.query.service import create_app

    mod = importlib.import_module("src.query.service")
    importlib.reload(mod)
    app = mod.create_app()
    from fastapi.testclient import TestClient

    agent = KnowledgeAgent(TestClient(app))
    # The served anchor is the bootstrap key; fetch + pin it.
    anchor_pem = agent.authority_public_key()
    assert agent.verify_authority(anchor_pem) is True

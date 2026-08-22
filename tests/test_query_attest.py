"""ADR 30 — evidence attestation (unit + HTTP).

Proves the EvidenceRecord can be signed by an evidence-domain authority that is
*separate* from the frozen finance gateway keyring, and that verification is
fail-closed: a tampered record, a wrong key, or malformed input all reject.

The signature covers ONLY the deterministic hash, so re-serializing non-binding
fields (reasons/plan) never invalidates an attestation -- Rathnone's
key-free-verifiable discipline (Invariant 3).
"""

import os

import pytest
from fastapi.testclient import TestClient

from src.query.attest import (
    Attestation,
    EvidenceAuthority,
    generate_keypair,
    verify_attestation,
)
from src.query.executor import EvidenceRecord, QueryExecutor
from src.query.service import create_app
from src.query.algebra import Match, And


def _make_record() -> EvidenceRecord:
    g = _graph()
    return QueryExecutor(g).execute(And(Match("alpha"), Match("beta")))


def _graph():
    from src.query.executor import Entity, KnowledgeGraph
    g = KnowledgeGraph()
    g.add(Entity(id="a", type="document", text="alpha beta gamma", source="x"))
    g.add(Entity(id="b", type="document", text="alpha delta", source="y"))
    g.add(Entity(id="c", type="concept", text="unrelated zeta", source="z"))
    return g


# --- library -----------------------------------------------------------


def test_sign_and_verify_round_trip():
    sk_pem, pub = generate_keypair()
    auth = EvidenceAuthority.from_pem("auth-1", sk_pem)
    rec = _make_record()
    att = auth.sign(rec)
    assert att.signed_hash == rec.deterministic_hash()
    assert verify_attestation(rec, att, pub) is True


def test_wrong_key_rejects():
    sk_a, _ = generate_keypair()          # A's signing key
    sk_b, pub_b = generate_keypair()      # B's key (what the verifier knows)
    auth_a = EvidenceAuthority.from_pem("auth-a", sk_a)
    rec = _make_record()
    att = auth_a.sign(rec)
    # Verifier only knows B's public key, so A's attestation must reject.
    assert verify_attestation(rec, att, pub_b) is False


def test_tampered_record_rejects():
    sk_pem, pub = generate_keypair()
    auth = EvidenceAuthority.from_pem("auth-1", sk_pem)
    rec = _make_record()
    att = auth.sign(rec)
    # Mutate the evidence set (drop an included entity).
    rec.included = rec.included[:-1]
    assert verify_attestation(rec, att, pub) is False


def test_attestation_survives_nonbinding_reserialize():
    """Re-serializing reasons/plan must NOT invalidate the signature, because
    the signature covers only the deterministic hash."""
    sk_pem, pub = generate_keypair()
    auth = EvidenceAuthority.from_pem("auth-1", sk_pem)
    rec = _make_record()
    att = auth.sign(rec)

    dumped = rec.as_dict()
    # Scramble a non-binding field before rehydrating.
    dumped["included"][0]["reasons"] = ["reordered", "reason"]
    dumped["plan"] = list(reversed(dumped["plan"]))

    rehydrated = EvidenceRecord.from_dict(dumped)
    assert verify_attestation(rehydrated, att, pub) is True


def test_malformed_attestation_fails_closed():
    sk_pem, pub = generate_keypair()
    rec = _make_record()
    bad = Attestation(
        signer_id="x", signed_hash=rec.deterministic_hash(),
        signature="deadbeef", algorithm="ed25519")
    assert verify_attestation(rec, bad, pub) is False


# --- HTTP --------------------------------------------------------------


@pytest.fixture
def client():
    return TestClient(create_app())


def test_public_key_exposed(client):
    r = client.get("/authority/public-key")
    assert r.status_code == 200
    body = r.json()
    assert body["algorithm"] == "ed25519"
    assert "BEGIN PUBLIC KEY" in body["public_key_pem"]


def test_attested_nl_query_is_verifiable(client):
    path = os.environ.get(
        "RATHNONE_SKC_ARTIFACT",
        "/Users/danielkliewer/Projects/research-compiler-agent/"
        "build-research/research-knowledge-artifact.json")
    load = client.post("/graphs/load",
                       json={"artifact_path": path, "graph_name": "skc"})
    assert load.status_code == 200

    r = client.post("/query/nl/attested", json={
        "graph_name": "skc", "text": "research about learning"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "attestation" in body

    # A caller verifies off-line using the exposed public key.
    pub = client.get("/authority/public-key").json()["public_key_pem"].encode()
    rec = EvidenceRecord.from_dict(body)
    att = Attestation.from_dict(body["attestation"])
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    pub_key = serialization.load_pem_public_key(pub)
    assert isinstance(pub_key, Ed25519PublicKey)
    assert verify_attestation(rec, att, pub) is True


def test_attested_query_tamper_detected(client):
    path = os.environ.get(
        "RATHNONE_SKC_ARTIFACT",
        "/Users/danielkliewer/Projects/research-compiler-agent/"
        "build-research/research-knowledge-artifact.json")
    client.post("/graphs/load",
                json={"artifact_path": path, "graph_name": "skc"})
    r = client.post("/query/nl/attested", json={
        "graph_name": "skc", "text": "research about learning"})
    body = r.json()
    rec = EvidenceRecord.from_dict(body)
    att = Attestation.from_dict(body["attestation"])
    pub = client.get("/authority/public-key").json()["public_key_pem"].encode()

    # Attacker drops an excluded entity from the delivered record (the hash
    # covers excluded ids too, so this must invalidate the attestation).
    assert rec.excluded
    rec.excluded = rec.excluded[:-1]
    assert verify_attestation(rec, att, pub) is False

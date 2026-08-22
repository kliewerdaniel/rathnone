"""ADR 37 — gateway read-only operator public-key endpoint.

The frozen finance gateway exposes its CURRENT operator signing key at
``GET /operator/public-key`` so an out-of-band auditor can build a cross-surface
attestation manifest against the key the gateway is *actually* serving -- not a
key it merely claims about itself. This endpoint must be READ-ONLY (no writes,
no authz mutation) and must never reference the frozen ``decide()`` spine.

Coverage:
  * the endpoint returns 200 and a well-formed ed25519 PEM + fingerprint,
  * it reads from the live operator authority (``_operator``), not a constant,
    so a post-boot key swap is reflected,
  * it writes nothing -- calling it leaves the operator keyring untouched.
"""

import hashlib

from fastapi.testclient import TestClient

from src.service.app import app, _operator


def test_operator_public_key_endpoint_is_readonly_and_well_formed():
    c = TestClient(app)
    before = _operator.public_key_pem
    r = c.get("/operator/public-key")
    assert r.status_code == 200
    body = r.json()
    assert body["algorithm"] == "ed25519"
    assert body["operator_id"] == _operator.operator_id
    # The served PEM equals the live operator authority's current key.
    assert body["public_key_pem"] == before
    # Deterministic fingerprint over the (whitespace-normalized) PEM.
    expect_fp = hashlib.sha256(
        "".join(before.split()).encode("utf-8")).hexdigest()
    assert body["key_fingerprint"] == expect_fp
    # Read-only: the keyring is unchanged after the call.
    assert _operator.public_key_pem == before


def test_operator_public_key_changes_with_authority():
    """The endpoint reflects the LIVE operator authority, not a frozen constant."""
    import importlib
    svc = importlib.import_module("src.service.app")
    from src.security.operator import OperatorAuthority

    c = TestClient(app)
    first = c.get("/operator/public-key").json()["public_key_pem"]

    # Swap the in-process operator authority to a freshly-generated key.
    saved = svc._operator
    svc._operator = OperatorAuthority()
    try:
        second = c.get("/operator/public-key").json()["public_key_pem"]
        assert second != first
        # Still well-formed ed25519 PEM.
        assert second.startswith("-----BEGIN PUBLIC KEY-----")
    finally:
        svc._operator = saved

"""ADR 22 — operator-key lifecycle management surface tests.

Prove the runtime key-management endpoints (add / revoke / rotate / list) are:
  - gated by BOTH the ADR 17 control-plane key AND the ADR 22 key-ops secret,
  - able to mutate the live keyring (no redeploy),
  - fail-closed: a missing second factor is refused, an unknown key revoke 404s.

The auth module reads env at CALL time, so we toggle RATHNONE_ENFORCE_AUTH=1 plus
both secrets mid-process and restore in teardown (the shared app module persists).
"""

import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from fastapi.testclient import TestClient

from src.service.app import app, _registry, _meters, _breaker, _SAFETY_TENANT
from src.security.operator import OperatorKeyRing


_CP_KEY = "test-control-plane-key"
_KO_KEY = "test-key-ops-secret"
_CP_HEADERS = {"Authorization": f"Bearer {_CP_KEY}"}
_KO_HEADERS = {"X-Key-Ops": _KO_KEY}
_BOTH = {**_CP_HEADERS, **_KO_HEADERS}


def _pem(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


@pytest.fixture(autouse=True)
def gate():
    prev_enforce = os.environ.get("RATHNONE_ENFORCE_AUTH")
    prev_cp = os.environ.get("RATHNONE_API_KEY")
    prev_ko = os.environ.get("RATHNONE_KEY_OPS")
    os.environ["RATHNONE_ENFORCE_AUTH"] = "1"
    os.environ["RATHNONE_API_KEY"] = _CP_KEY
    os.environ["RATHNONE_KEY_OPS"] = _KO_KEY
    _registry._tenants.clear(); _meters.clear(); _breaker.resume()
    yield
    _registry._tenants.clear(); _meters.clear(); _breaker.resume()
    _SAFETY_TENANT.operator_keys = OperatorKeyRing()
    if prev_enforce is None:
        os.environ.pop("RATHNONE_ENFORCE_AUTH", None)
    else:
        os.environ["RATHNONE_ENFORCE_AUTH"] = prev_enforce
    if prev_cp is None:
        os.environ.pop("RATHNONE_API_KEY", None)
    else:
        os.environ["RATHNONE_API_KEY"] = prev_cp
    if prev_ko is None:
        os.environ.pop("RATHNONE_KEY_OPS", None)
    else:
        os.environ["RATHNONE_KEY_OPS"] = prev_ko


def _client():
    return TestClient(app)


# --- two-factor gating -----------------------------------------------------

def test_key_mgmt_requires_both_factors():
    c = _client()
    # no auth at all
    assert c.get("/operator-keys", params={"scope": "safety"}).status_code == 401
    # control-plane key only (missing key-ops)
    assert c.get("/operator-keys", params={"scope": "safety"},
                 headers=_CP_HEADERS).status_code == 401
    # key-ops only (missing control-plane key)
    assert c.get("/operator-keys", params={"scope": "safety"},
                 headers=_KO_HEADERS).status_code == 401
    # both -> 200
    assert c.get("/operator-keys", params={"scope": "safety"},
                 headers=_BOTH).status_code == 200


def test_key_ops_wrong_secret_refused():
    c = _client()
    r = c.post("/operator-keys/revoke",
               params={"scope": "safety"},
               headers={**_CP_HEADERS, "X-Key-Ops": "wrong"},
               json={"key_id": "whatever"})
    assert r.status_code == 401


# --- mutation behavior ------------------------------------------------------

def test_add_key_to_safety_scope():
    c = _client()
    k = Ed25519PrivateKey.generate()
    r = c.post("/operator-keys", params={"scope": "safety"}, headers=_BOTH,
               json={"public_key_pem": _pem(k), "operator_id": "op-1"})
    assert r.status_code == 200, r.text
    kid = r.json()["key_id"]
    assert r.json()["active"] is True
    # it is now in the live ring
    assert _pem(k) in _SAFETY_TENANT.operator_keys.active_pems()
    # and listed
    lst = c.get("/operator-keys", params={"scope": "safety"}, headers=_BOTH)
    assert any(e["key_id"] == kid for e in lst.json()["keys"])


def test_revoke_key_by_id():
    c = _client()
    k = Ed25519PrivateKey.generate()
    kid = c.post("/operator-keys", params={"scope": "safety"}, headers=_BOTH,
                 json={"public_key_pem": _pem(k)}).json()["key_id"]
    # safety scope now has one active key -> signed-command layer in force
    assert _SAFETY_TENANT.operator_keys.active_pems()
    r = c.post("/operator-keys/revoke", params={"scope": "safety"}, headers=_BOTH,
               json={"key_id": kid})
    assert r.status_code == 200
    assert r.json()["layer_active"] is False  # reverts to ADR 17 path (fail-closed)
    assert _pem(k) not in _SAFETY_TENANT.operator_keys.active_pems()


def test_revoke_unknown_key_404():
    c = _client()
    r = c.post("/operator-keys/revoke", params={"scope": "safety"}, headers=_BOTH,
               json={"key_id": "deadbeef"})
    assert r.status_code == 404


def test_rotate_key_graceful():
    c = _client()
    old = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate()
    c.post("/operator-keys", params={"scope": "safety"}, headers=_BOTH,
           json={"public_key_pem": _pem(old)})
    r = c.post("/operator-keys/rotate", params={"scope": "safety"}, headers=_BOTH,
               json={"new_public_key_pem": _pem(new),
                     "old_public_key_pem": _pem(old),
                     "expire_old_in_s": 60})
    assert r.status_code == 200, r.text
    # new key active
    assert _pem(new) in _SAFETY_TENANT.operator_keys.active_pems()
    # old key still active during grace window
    assert _pem(old) in _SAFETY_TENANT.operator_keys.active_pems()


def test_tenant_scoped_key_mgmt():
    c = _client()
    # create a tenant (control-plane key only, no key-ops needed for provisioning)
    tid = c.post("/tenants", json={"aum": 1.0}, headers=_CP_HEADERS).json()["tenant_id"]
    k = Ed25519PrivateKey.generate()
    r = c.post("/operator-keys", params={"scope": "tenant", "tenant_id": tid},
               headers=_BOTH, json={"public_key_pem": _pem(k)})
    assert r.status_code == 200
    from src.service.app import _registry as _reg
    t = _reg.get(tid)
    assert _pem(k) in t.operator_keys.active_pems()
    # missing tenant_id -> 400
    assert c.post("/operator-keys", params={"scope": "tenant"}, headers=_BOTH,
                  json={"public_key_pem": _pem(k)}).status_code == 400
    # bad scope -> 400
    assert c.post("/operator-keys", params={"scope": "bogus"}, headers=_BOTH,
                  json={"public_key_pem": _pem(k)}).status_code == 400

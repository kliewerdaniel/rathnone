"""ADR 23 — durable operator-key persistence tests.

Prove the keyring survives a "restart" (a fresh store/connection over the same
file) so runtime key changes are not lost when the process exits. We exercise:

  - add a key via the management endpoint (write-through),
  - build a SECOND store/keyring over the same file and confirm the key is present
    (durability across connections),
  - revoke via the surface, confirm the second store now sees it revoked,
  - rotate, confirm both new + old (grace) persist,
  - a tenant key added via the surface persists and a fresh tenant fetch re-hydrates,
  - fail-closed: unknown tenant scope => 404 (not 500); unset RATHNONE_KEY_DB => no store.

The durable store is enabled by setting RATHNONE_KEY_DB to a temp file; the app
resolves the store lazily (call-time env read), so we toggle it here and reset in
teardown. Auth two-factor is enforced via the gate fixture.
"""

import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fastapi.testclient import TestClient

from src.security.operator import OperatorKeyRing
from src.security.keystore import DurableOperatorKeyStore
from src.service.app import app, _registry, _meters, _breaker, _SAFETY_TENANT
import importlib

# The package __init__ rebinds the name `app`; grab the real module via importlib.
_appmod = importlib.import_module("src.service.app")


_CP_KEY = "test-control-plane-key"
_KO_KEY = "test-key-ops-secret"
_BOTH = {"Authorization": f"Bearer {_CP_KEY}", "X-Key-Ops": _KO_KEY}


def _pem(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


@pytest.fixture(autouse=True)
def gate(tmp_path):
    # enable durability + auth for this session
    prev = {k: os.environ.get(k) for k in (
        "RATHNONE_ENFORCE_AUTH", "RATHNONE_API_KEY",
        "RATHNONE_KEY_OPS", "RATHNONE_KEY_DB")}
    db_file = tmp_path / "keys.db"
    os.environ["RATHNONE_ENFORCE_AUTH"] = "1"
    os.environ["RATHNONE_API_KEY"] = _CP_KEY
    os.environ["RATHNONE_KEY_OPS"] = _KO_KEY
    os.environ["RATHNONE_KEY_DB"] = str(db_file)
    # reset keyring state so each test starts clean against the new DB
    _registry._tenants.clear()
    _meters.clear()
    _breaker.resume()
    _SAFETY_TENANT.operator_keys = OperatorKeyRing()
    _SAFETY_TENANT._keys_hydrated = False
    _appmod._key_store = None  # force lazy rebuild against the new DB file
    yield
    _registry._tenants.clear()
    _meters.clear()
    _breaker.resume()
    _SAFETY_TENANT.operator_keys = OperatorKeyRing()
    _SAFETY_TENANT._keys_hydrated = False
    for k, v in prev.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def _fresh_store() -> DurableOperatorKeyStore:
    """Simulate a restart: a brand-new connection reading the same file."""
    return DurableOperatorKeyStore(db_path=os.environ["RATHNONE_KEY_DB"])


# --- durability: safety scope survives a fresh store -------------------------

def test_safety_key_persists_across_restart():
    c = TestClient(app)
    pem = _pem(Ed25519PrivateKey.generate())
    r = c.post("/operator-keys?scope=safety", json={"public_key_pem": pem},
               headers=_BOTH)
    assert r.status_code == 200, r.text
    # a fresh store over the same file must see the key
    ring = _fresh_store().load_scope("safety")
    assert pem in ring.active_pems(), "added safety key missing after 'restart'"


def test_safety_revoke_persists_across_restart():
    c = TestClient(app)
    pem = _pem(Ed25519PrivateKey.generate())
    c.post("/operator-keys?scope=safety", json={"public_key_pem": pem},
           headers=_BOTH)
    kid = c.get("/operator-keys?scope=safety", headers=_BOTH).json()["keys"][0]["key_id"]
    r = c.post("/operator-keys/revoke?scope=safety", json={"key_id": kid},
               headers=_BOTH)
    assert r.status_code == 200, r.text
    assert r.json()["layer_active"] is False
    ring = _fresh_store().load_scope("safety")
    assert not ring.active_pems(), "revoked key still active after 'restart'"


def test_safety_rotate_persists_new_and_grace_old():
    c = TestClient(app)
    old_pem = _pem(Ed25519PrivateKey.generate())
    new_pem = _pem(Ed25519PrivateKey.generate())
    c.post("/operator-keys?scope=safety", json={"public_key_pem": old_pem},
           headers=_BOTH)
    r = c.post("/operator-keys/rotate?scope=safety",
               json={"new_public_key_pem": new_pem,
                     "old_public_key_pem": old_pem,
                     "expire_old_in_s": 3600},
               headers=_BOTH)
    assert r.status_code == 200, r.text
    ring = _fresh_store().load_scope("safety")
    pems = {e.public_key_pem for e in ring}
    assert {old_pem, new_pem} <= pems
    active = set(ring.active_pems())
    assert new_pem in active and old_pem in active  # grace window keeps old active


# --- durability: tenant scope ------------------------------------------------

def test_tenant_key_persists_and_hydrates():
    c = TestClient(app)
    tid = c.post("/tenants", json={"aum": 1.0},
                 headers={"Authorization": f"Bearer {_CP_KEY}"}).json()["tenant_id"]
    pem = _pem(Ed25519PrivateKey.generate())
    r = c.post(f"/operator-keys?scope=tenant&tenant_id={tid}",
               json={"public_key_pem": pem}, headers=_BOTH)
    assert r.status_code == 200, r.text
    # a brand-new store over the same file sees the tenant key
    ring = _fresh_store().load_scope(tid)
    assert pem in ring.active_pems(), "tenant key not persisted"
    # a fresh tenant object fetched via the app re-hydrates from the store
    info = c.get(f"/tenants/{tid}",
                 headers={"Authorization": f"Bearer {_CP_KEY}"}).json()
    assert info["operator_gated"] is True


def test_unknown_tenant_scope_is_empty_not_fatal():
    c = TestClient(app)
    r = c.get("/operator-keys?scope=tenant&tenant_id=does-not-exist",
              headers=_BOTH)
    # tenant 404 (no such tenant) — fail-closed, not a 500
    assert r.status_code == 404


# --- fail-closed: missing store => still works in-memory ---------------------

def test_no_db_env_stays_in_memory():
    prev = os.environ.get("RATHNONE_KEY_DB")
    os.environ.pop("RATHNONE_KEY_DB", None)
    _appmod._key_store = None
    assert _appmod._key_store_singleton() is None
    if prev is None:
        os.environ.pop("RATHNONE_KEY_DB", None)
    else:
        os.environ["RATHNONE_KEY_DB"] = prev

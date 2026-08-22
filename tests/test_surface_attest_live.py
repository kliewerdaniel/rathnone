"""ADR 37 — live cross-surface consumer test.

This is the deployability gate for the cross-surface root-of-trust: it proves
the operator-issued manifest can be CHECKED AGAINST BOTH RUNNING SURFACES, not
just demonstrated in the standalone PoC (scripts/surface_attest.py). Two real
uvicorn servers (finance gateway + knowledge engine) are started on TCP sockets;
the manifest is built vouching for their ACTUAL served keys; then
``surface_attest verify-live`` fetches both surfaces over HTTP and confirms the
manifest matches what is deployed. A manifest that vouchers for a SUBSTITUTED
gateway key must fail-closed (non-zero exit).

Env is set via monkeypatch so nothing leaks into the rest of the suite.
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

import httpx
import pytest
import uvicorn

from src.query.attest import generate_keypair
from src.surface_attest import (
    SurfaceAttestationManifest,
    SurfaceKeyBinding,
    build_manifest,
    generate_root_keypair,
)
from src.query.service import create_app as create_query_app
from src.service.app import app as gateway_app
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typing import cast


_SKC_DEFAULT = (
    "/Users/danielkliewer/Projects/research-compiler-agent/"
    "build-research/research-knowledge-artifact.json"
)


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _serve(app, port, stop):
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)

    def _watchdog():
        while not stop.is_set():
            time.sleep(0.02)
        server.should_exit = True

    threading.Thread(target=_watchdog, daemon=True).start()
    server.run()


def _start(app, stop, probe_path="/health"):
    port = _free_port()
    t = threading.Thread(target=_serve, args=(app, port, stop), daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 10.0
    while time.time() < deadline:
        try:
            with httpx.Client(base_url=base, timeout=1.0) as probe:
                if probe.get(probe_path).status_code == 200:
                    return base, t
        except Exception:  # noqa: BLE001
            time.sleep(0.02)
    stop.set()
    pytest.fail(f"live server did not start on {base}")


def _priv(pem_bytes: bytes) -> "Ed25519PrivateKey":
    return cast(Ed25519PrivateKey,
                serialization.load_pem_private_key(pem_bytes, password=None))


@pytest.fixture
def two_surfaces(monkeypatch):
    """Start gateway + knowledge engine; yield their base URLs."""
    att_sk, _ = generate_keypair()
    op_sk, _ = generate_keypair()
    monkeypatch.setenv("RATHNONE_EVIDENCE_KEY_PEM", att_sk.decode("utf-8"))
    monkeypatch.setenv("RATHNONE_EVIDENCE_OP_KEY_PEM", op_sk.decode("utf-8"))

    stop = threading.Event()
    gw_base, _ = _start(gateway_app, stop, probe_path="/operator/public-key")
    q_app = create_query_app()
    q_base, _ = _start(q_app, stop)
    try:
        yield gw_base, q_base
    finally:
        stop.set()


def test_adr37_verify_live_matches_both_running_surfaces(two_surfaces):
    """The operator manifest, vouched against the ACTUAL served keys, verifies
    live against BOTH running surfaces via surface_attest verify-live."""
    gw_base, q_base = two_surfaces

    # Fetch the two surfaces' current served keys.
    with httpx.Client(base_url=gw_base, timeout=5) as c:
        gw_pem = c.get("/operator/public-key").json()["public_key_pem"]
    with httpx.Client(base_url=q_base, timeout=5) as c:
        q_pem = c.get("/authority/public-key").json()["public_key_pem"]

    # Generate an operator root key-pair (pinned out-of-band).
    root_sk, root_pk = generate_root_keypair()
    root_priv = _priv(root_sk)
    d = tempfile.mkdtemp()
    root_path = os.path.join(d, "root.pem")
    root_pub_path = os.path.join(d, "root.pub.pem")
    open(root_path, "wb").write(root_sk)
    open(root_pub_path, "wb").write(root_pk)

    bindings = [
        SurfaceKeyBinding("gateway", "operator", gw_pem, issued_at=1),
        SurfaceKeyBinding("knowledge-query", "evidence-anchor", q_pem,
                          issued_at=1),
    ]
    manifest = build_manifest("rathnone-operator", root_priv, bindings)
    manifest_path = os.path.join(d, "manifest.json")
    open(manifest_path, "w", encoding="utf-8").write(
        json.dumps(manifest.as_dict()))

    env = dict(os.environ, PYTHONPATH=os.path.abspath("."))
    r = subprocess.run(
        [sys.executable, "scripts/surface_attest.py", "verify-live",
         "--root", root_pub_path, "--manifest", manifest_path,
         "--gateway-url", gw_base, "--knowledge-url", q_base],
        capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr + "\n" + r.stdout
    report = json.loads(r.stdout)
    assert report["manifest_signature_ok"] is True
    assert report["surface:gateway:matches_vouched"] is True
    assert report["surface:knowledge-query:matches_vouched"] is True


def test_adr37_verify_live_rejects_substituted_key(two_surfaces):
    """A manifest that vouchers for a SUBSTITUTED gateway key must fail-closed."""
    gw_base, q_base = two_surfaces

    with httpx.Client(base_url=gw_base, timeout=5) as c:
        gw_pem = c.get("/operator/public-key").json()["public_key_pem"]
    with httpx.Client(base_url=q_base, timeout=5) as c:
        q_pem = c.get("/authority/public-key").json()["public_key_pem"]

    root_sk, root_pk = generate_root_keypair()
    root_priv = _priv(root_sk)
    d = tempfile.mkdtemp()
    root_pub_path = os.path.join(d, "root.pub.pem")
    open(root_pub_path, "wb").write(root_pk)

    # WRONG key vouched for the gateway: a random freshly-generated PEM.
    wrong_sk, wrong_pk = generate_keypair()
    bindings = [
        SurfaceKeyBinding("gateway", "operator", wrong_pk.decode("utf-8"),
                          issued_at=1),
        SurfaceKeyBinding("knowledge-query", "evidence-anchor", q_pem,
                          issued_at=1),
    ]
    manifest = build_manifest("rathnone-operator", root_priv, bindings)
    manifest_path = os.path.join(d, "bad.json")
    open(manifest_path, "w", encoding="utf-8").write(
        json.dumps(manifest.as_dict()))

    env = dict(os.environ, PYTHONPATH=os.path.abspath("."))
    r = subprocess.run(
        [sys.executable, "scripts/surface_attest.py", "verify-live",
         "--root", root_pub_path, "--manifest", manifest_path,
         "--gateway-url", gw_base, "--knowledge-url", q_base],
        capture_output=True, text=True, env=env)
    assert r.returncode != 0, "substituted gateway key must fail-closed"


def test_adr37_verify_live_rejects_unknown_surface(two_surfaces):
    """A manifest missing the knowledge-query surface must not pass verify-live."""
    gw_base, q_base = two_surfaces

    with httpx.Client(base_url=gw_base, timeout=5) as c:
        gw_pem = c.get("/operator/public-key").json()["public_key_pem"]

    root_sk, root_pk = generate_root_keypair()
    root_priv = _priv(root_sk)
    d = tempfile.mkdtemp()
    root_pub_path = os.path.join(d, "root.pub.pem")
    open(root_pub_path, "wb").write(root_pk)

    # Only the gateway is vouched -- knowledge-query is absent.
    bindings = [SurfaceKeyBinding("gateway", "operator", gw_pem, issued_at=1)]
    manifest = build_manifest("rathnone-operator", root_priv, bindings)
    manifest_path = os.path.join(d, "partial.json")
    open(manifest_path, "w", encoding="utf-8").write(
        json.dumps(manifest.as_dict()))

    env = dict(os.environ, PYTHONPATH=os.path.abspath("."))
    r = subprocess.run(
        [sys.executable, "scripts/surface_attest.py", "verify-live",
         "--root", root_pub_path, "--manifest", manifest_path,
         "--gateway-url", gw_base, "--knowledge-url", q_base],
        capture_output=True, text=True, env=env)
    # Fails because knowledge-query:matches_vouched is False.
    assert r.returncode != 0

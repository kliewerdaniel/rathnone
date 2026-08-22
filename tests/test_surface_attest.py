"""ADR 37 — cross-surface root-of-trust (operator-attested surface ancestry).

This module is surface-agnostic and READ-ONLY: it imports nothing from the
gateway (``src.service`` / ``src.security`` / ``fleet.epistemic``) or the engine
beyond its own crypto helper. These tests prove the manifest crypto and the
cross-surface check WITHOUT touching either surface's authz code -- the
isolation invariant is preserved by construction.

Coverage:
  * operator root keypair generated;
  * manifest builds + signs; verifies against the root and REJECTS a wrong root;
  * ``check_surface`` matches a served key to the vouched key, and REJECTS a
    mismatched (substituted) surface key;
  * a manifest that omits a surface fails the surface check;
  * the end-to-end CLI (gen-root / sign / verify) runs and exits non-zero on a
    key substitution (fail-closed).
"""

import json
import os
import subprocess
import sys
import tempfile

import pytest

from src.surface_attest import (
    SurfaceKeyBinding,
    SurfaceAttestationManifest,
    generate_root_keypair,
    build_manifest,
    verify_manifest,
    check_surface,
)
from src.query.attest import generate_keypair, load_private_key


def _pub(pem_bytes: bytes) -> bytes:
    return pem_bytes  # already PEM; kept for clarity at call sites


def test_root_keypair_roundtrip_and_signs_manifest():
    root_priv, root_pub = generate_root_keypair()
    gw_priv, gw_pub = generate_keypair()
    kn_priv, kn_pub = generate_keypair()
    binds = [
        SurfaceKeyBinding("gateway", "operator", gw_pub.decode(), issued_at=1),
        SurfaceKeyBinding("knowledge", "evidence-anchor", kn_pub.decode(),
                          issued_at=1),
    ]
    m = build_manifest("rathnone-operator", load_private_key(root_priv), binds)
    ok, reason = verify_manifest(m, root_pub)
    assert ok, reason
    # The manifest fingerprints its own canonical bytes.
    assert "manifest_fingerprint" in m.as_dict()


def test_manifest_rejects_wrong_root():
    root_priv, root_pub = generate_root_keypair()
    other_priv, other_pub = generate_root_keypair()
    gw_priv, gw_pub = generate_keypair()
    binds = [SurfaceKeyBinding("gateway", "operator", gw_pub.decode(),
                               issued_at=1)]
    m = build_manifest("op", load_private_key(root_priv), binds)
    ok, reason = verify_manifest(m, other_pub)
    assert not ok, "a manifest signed by one root must fail under another"


def test_check_surface_matches_and_rejects_substitution():
    root_priv, root_pub = generate_root_keypair()
    gw_priv, gw_pub = generate_keypair()
    kn_priv, kn_pub = generate_keypair()
    binds = [
        SurfaceKeyBinding("gateway", "operator", gw_pub.decode(), issued_at=1),
        SurfaceKeyBinding("knowledge", "evidence-anchor", kn_pub.decode(),
                          issued_at=1),
    ]
    m = build_manifest("op", load_private_key(root_priv), binds)
    ok, _ = check_surface(m, "knowledge", kn_pub)
    assert ok
    # A substituted knowledge key (the gateway's pub) must be rejected.
    ok_bad, reason = check_surface(m, "knowledge", gw_pub)
    assert not ok_bad, "a substituted surface key must be rejected"
    assert "fingerprint" in (reason or "")


def test_check_surface_missing_binding_fails():
    root_priv, root_pub = generate_root_keypair()
    gw_priv, gw_pub = generate_keypair()
    binds = [SurfaceKeyBinding("gateway", "operator", gw_pub.decode(),
                               issued_at=1)]
    m = build_manifest("op", load_private_key(root_priv), binds)
    ok, reason = check_surface(m, "knowledge", gw_pub)
    assert not ok, "a surface the manifest does not vouch for must fail"
    assert "does not vouch" in (reason or "")


def test_cli_gen_root_sign_verify_end_to_end():
    """The operator tool must run as a real CLI and fail-closed on a key
    substitution."""
    with tempfile.TemporaryDirectory() as d:
        root = os.path.join(d, "root.pem")
        root_pub = os.path.join(d, "root.pub.pem")
        gw = os.path.join(d, "gw.pem")
        kn = os.path.join(d, "kn.pem")
        kn_served = os.path.join(d, "kn_served.pem")
        manifest = os.path.join(d, "manifest.json")

        # Real key material.
        _, gw_pub = generate_keypair()
        kn_priv, kn_pub = generate_keypair()
        with open(gw, "wb") as fh:
            fh.write(gw_pub)
        with open(kn, "wb") as fh:
            fh.write(kn_pub)
        with open(kn_served, "wb") as fh:
            fh.write(kn_pub)  # served == vouched -> should pass

        script = os.path.join("scripts", "surface_attest.py")
        env = dict(os.environ, PYTHONPATH=".")
        # gen-root
        r = subprocess.run([sys.executable, script, "gen-root", "--out", root,
                           "--out-pub", root_pub], capture_output=True, text=True,
                          env=env)
        assert r.returncode == 0, r.stderr
        # sign
        r = subprocess.run([sys.executable, script, "sign",
                            "--root", root, "--operator-id", "op",
                            "--surface", "gateway", "--kind", "operator",
                            "--pubkey-pem", gw,
                            "--surface", "knowledge", "--kind", "evidence-anchor",
                            "--pubkey-pem", kn,
                            "--out", manifest], capture_output=True, text=True,
                           env=env)
        assert r.returncode == 0, r.stderr
        # verify (served matches vouched) -> exit 0
        r = subprocess.run([sys.executable, script, "verify",
                            "--root", root_pub, "--manifest", manifest,
                            "--surface", "knowledge",
                            "--served-pubkey-pem", kn_served],
                           capture_output=True, text=True, env=env)
        assert r.returncode == 0, r.stderr

        # Now substitute the served knowledge key with the gateway key.
        r = subprocess.run([sys.executable, script, "verify",
                            "--root", root_pub, "--manifest", manifest,
                            "--surface", "knowledge",
                            "--served-pubkey-pem", gw],
                           capture_output=True, text=True, env=env)
        assert r.returncode != 0, "substituted (wrong) served key must fail"


def test_module_does_not_import_gateway_or_fleet():
    """ADR 37 hard invariant: the surface-attest module must remain read-only
    over the two surfaces. Assert it imports NO gateway/fleet/engine authz
    module, so it can never mutate either surface's trust path. We scan only
    import statements (not docstrings, which may name the surfaces in prose)."""
    import importlib
    import re
    mod = importlib.import_module("src.surface_attest")
    src = mod.__file__
    assert src
    with open(src, "r", encoding="utf-8") as fh:
        text = fh.read()
    # Only consider actual import lines (avoid matching docstring prose that
    # names the surfaces, e.g. "the frozen finance gateway (src.service.app)").
    import_lines = "\n".join(
        line for line in text.splitlines()
        if re.match(r"\s*(from|import)\s", line))
    forbidden = ["src.service", "src.security", "fleet.epistemic"]
    for f in forbidden:
        assert f not in import_lines, (
            f"surface_attest must not import {f!r}")

"""ADR 37 — cross-surface root-of-trust proof-of-concept (standalone).

This PoC demonstrates the core ADR 37 mechanism WITHOUT importing either
surface's authz code (the module it exercises, ``src.surface_attest``, is
read-only by construction). It shows how a single operator-root key vouches for
the public keys of BOTH the frozen finance gateway and the knowledge-query
engine, so an auditor can:

  * derive each surface's trusted public key from the operator-signed manifest
    (not from what each surface *claims* about itself), and
  * detect a substituted/compromised surface key (a surface serving a key that
    is not the one the operator vouched for).

Run (no network, no gateway):
    env -u PYTHONPATH -u VIRTUAL_ENV .venv/bin/python examples/cross_surface_attest.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.query.attest import generate_keypair, load_private_key
from src.surface_attest import (
    SurfaceKeyBinding,
    SurfaceAttestationManifest,
    generate_root_keypair,
    build_manifest,
    verify_manifest,
    check_surface,
)


def main() -> int:
    # Operator root-of-trust keypair (one meta key vouches for both surfaces).
    root_priv, root_pub = generate_root_keypair()
    root_sk = load_private_key(root_priv)

    # Each surface generates its own keys independently.
    _, gw_pub = generate_keypair()
    _, kn_pub = generate_keypair()

    bindings = [
        SurfaceKeyBinding("finance-gateway", "operator", gw_pub.decode(),
                          issued_at=1),
        SurfaceKeyBinding("knowledge-query", "evidence-anchor", kn_pub.decode(),
                          issued_at=1),
    ]
    manifest = build_manifest("rathnone-operator", root_sk, bindings)

    checks: dict[str, bool] = {}

    # 1. The manifest verifies under the operator root.
    ok, reason = verify_manifest(manifest, root_pub)
    checks["manifest_verifies_under_root"] = ok
    assert ok, reason

    # 2. Each surface's SERVED key matches the operator-vouched key.
    ok_kn, _ = check_surface(manifest, "knowledge-query", kn_pub)
    ok_gw, _ = check_surface(manifest, "finance-gateway", gw_pub)
    checks["knowledge_key_matches_vouched"] = ok_kn
    checks["gateway_key_matches_vouched"] = ok_gw

    # 3. A substituted surface key is DETECTED (a surface cannot silently swap
    #    its key for one the operator did not vouch for).
    ok_sub, _ = check_surface(manifest, "knowledge-query", gw_pub)
    checks["substituted_key_rejected"] = not ok_sub

    # 4. Tamper: rewriting a binding's key in the manifest breaks the signature.
    forged = manifest.as_dict()
    forged["bindings"][1]["pubkey_pem"] = gw_pub.decode()
    ok_forged, _ = verify_manifest(
        SurfaceAttestationManifest.from_dict(forged), root_pub)
    checks["tampered_manifest_rejected"] = not ok_forged

    passed = sum(1 for v in checks.values() if v)
    failed = [n for n, ok in checks.items() if not ok]
    width = max(len(n) for n in checks)
    for name, ok in checks.items():
        print(f"  {name:<34} {'OK' if ok else 'FAIL'}")
    print()
    print(f"ADR 37 cross-surface PoC: {passed} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

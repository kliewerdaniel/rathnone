#!/usr/bin/env python3
"""ADR 37 — operator tool for the cross-surface root-of-trust manifest.

This tool signs and verifies a *surface-attestation manifest*: the operator's
root Ed25519 key vouching, out-of-band, for the CURRENT public key of each
independent Rathnone surface (the frozen finance gateway and the evidence-domain
knowledge engine). The two surfaces share no code-level trust path; this manifest
lets the operator prove, with a single signature, that both surfaces are
currently signing with keys the operator actually trusts.

The tool is READ-ONLY over the surfaces: it never imports the gateway or the
engine. The caller supplies each surface's current public key on the command
line (read from a gateway health endpoint, an ADR 34 trust-log anchor, or a
pinned PEM file). The module therefore cannot mutate gateway authz or the frozen
spine — the isolation invariant holds.

Usage:
    # Generate an operator root key (pin the public PEM out-of-band):
    python scripts/surface_attest.py gen-root --out /secure/oproot_ed25519.pem

    # Sign a manifest vouching for both surfaces' current keys:
    python scripts/surface_attest.py sign \\
        --root /secure/oproot_ed25519.pem \\
        --operator-id rathnone-operator \\
        --surface gateway --kind operator \\
            --pubkey-pem /secure/gateway_op_current.pem \\
        --surface knowledge --kind evidence-anchor \\
            --pubkey-pem /secure/evidence_anchor.pem \\
        --out /secure/surface_manifest.json

    # Verify a manifest against the pinned operator root, and confirm a LIVE
    # served key matches what was vouched:
    python scripts/surface_attest.py verify \\
        --root /secure/oproot_ed25519.pub.pem \\
        --manifest /secure/surface_manifest.json \\
        --surface knowledge --served-pubkey-pem /secure/evidence_anchor_served.pem

Exit non-zero on any error or verification failure.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.surface_attest import (  # noqa: E402
    SurfaceKeyBinding,
    SurfaceAttestationManifest,
    generate_root_keypair,
    build_manifest,
    verify_manifest,
    check_surface,
)


def _load_priv(path: str) -> "Ed25519PrivateKey":
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return cast(
        Ed25519PrivateKey,
        serialization.load_pem_private_key(open(path, "rb").read(), password=None))


def _load_pub(path: str) -> bytes:
    return open(path, "rb").read().strip()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Manage the cross-surface root-of-trust manifest (ADR 37).")
    sub = ap.add_subparsers(required=True, dest="cmd")

    g = sub.add_parser("gen-root", help="generate an operator root key pair")
    g.add_argument("--out", required=True, help="where to write the private PEM")
    g.add_argument("--out-pub", default=None,
                   help="optional: where to also write the public PEM")

    s = sub.add_parser("sign", help="sign a surface-attestation manifest")
    s.add_argument("--root", required=True, help="operator root Ed25519 PEM")
    s.add_argument("--operator-id", default="rathnone-operator")
    s.add_argument("--out", required=True, help="manifest output JSON")
    # repeatable surface group:
    s.add_argument("--surface", action="append", default=[],
                   help="surface id (e.g. gateway / knowledge)")
    s.add_argument("--kind", action="append", default=[],
                   help="key kind for the preceding --surface (parallel list)")
    s.add_argument("--pubkey-pem", action="append", default=[],
                   help="pubkey PEM path for the preceding --surface (parallel)")

    v = sub.add_parser("verify", help="verify a manifest + live served keys")
    v.add_argument("--root", required=True, help="operator root PUBLIC PEM")
    v.add_argument("--manifest", required=True, help="manifest JSON")
    v.add_argument("--surface", action="append", default=[],
                   help="surface id to check against a live served key")
    v.add_argument("--served-pubkey-pem", action="append", default=[],
                   help="path to the surface's currently-served pubkey PEM "
                        "(parallel to --surface)")
    v.add_argument("--live-url", action="append", default=[],
                   help="base URL of a running surface to FETCH the served key "
                        "from (e.g. http://127.0.0.1:8765 for gateway, "
                        "http://127.0.0.1:8791 for knowledge). Parallel to "
                        "--surface. The key is read from /operator/public-key "
                        "(gateway) or /authority/public-key (knowledge).")

    vl = sub.add_parser("verify-live",
                        help="fetch live served keys over HTTP and check the "
                             "manifest against BOTH running surfaces")
    vl.add_argument("--root", required=True, help="operator root PUBLIC PEM")
    vl.add_argument("--manifest", required=True, help="manifest JSON")
    vl.add_argument("--gateway-url", required=True,
                    help="base URL of the running finance gateway")
    vl.add_argument("--knowledge-url", required=True,
                    help="base URL of the running knowledge-query engine")

    args = ap.parse_args()

    if args.cmd == "gen-root":
        priv, pub = generate_root_keypair()
        with open(args.out, "wb") as fh:
            fh.write(priv)
        if args.out_pub:
            with open(args.out_pub, "wb") as fh:
                fh.write(pub)
        print(json.dumps({"action": "gen-root", "out": args.out,
                          "out_pub": args.out_pub}, indent=2))
        return 0

    if args.cmd == "sign":
        if not (len(args.surface) == len(args.kind) == len(args.pubkey_pem)):
            print("ERROR: --surface/--kind/--pubkey-pem must be parallel lists",
                  file=sys.stderr)
            return 2
        bindings = []
        for sid, kind, pk_path in zip(args.surface, args.kind, args.pubkey_pem):
            pem = _load_pub(pk_path).decode("utf-8")
            bindings.append(SurfaceKeyBinding(
                surface_id=sid, key_kind=kind, pubkey_pem=pem,
                issued_at=int(__import__("time").time())))
        root = _load_priv(args.root)
        manifest = build_manifest(args.operator_id, root, bindings)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(manifest.as_dict(), fh, indent=2)
            fh.write("\n")
        print(json.dumps({"action": "sign", "out": args.out,
                          "manifest_fingerprint": manifest.as_dict()
                          ["manifest_fingerprint"]}, indent=2))
        return 0

    if args.cmd == "verify":
        if len(args.surface) != len(args.served_pubkey_pem):
            print("ERROR: --surface/--served-pubkey-pem must be parallel lists",
                  file=sys.stderr)
            return 2
        # Optional: fetch served keys from live URLs instead of PEM files.
        live_keys: dict[str, bytes] = {}
        if getattr(args, "live_url", None):
            if len(args.surface) != len(args.live_url):
                print("ERROR: --surface/--live-url must be parallel lists",
                      file=sys.stderr)
                return 2
            for sid, url in zip(args.surface, args.live_url):
                live_keys[sid] = _fetch_served_key(url, sid)
        with open(args.manifest, "r", encoding="utf-8") as fh:
            manifest = SurfaceAttestationManifest.from_dict(json.load(fh))
        ok, reason = verify_manifest(manifest, _load_pub(args.root))
        report = {"manifest_signature_ok": ok, "manifest_reason": reason}
        if ok:
            for sid in args.surface:
                served = live_keys.get(sid) or _load_pub(
                    # served-pubkey-pem parallel to --surface
                    dict(zip(args.surface, args.served_pubkey_pem))[sid])
                s_ok, s_reason = check_surface(manifest, sid, served)
                report[f"surface:{sid}:matches_vouched"] = s_ok
                report[f"surface:{sid}:reason"] = s_reason
        print(json.dumps(report, indent=2))
        # Fail closed: any problem => non-zero exit.
        return 0 if ok and all(
            report.get(f"surface:{sid}:matches_vouched") for sid in args.surface
        ) else 1

    if args.cmd == "verify-live":
        # Fetch BOTH running surfaces' served keys over HTTP and check the
        # manifest against the operator-vouched keys. This is the live consumer
        # of the ADR 37 manifest: it proves the deployed gateway and knowledge
        # engine are both currently signing with keys the operator trusts --
        # not keys they merely claim about themselves.
        import httpx
        gw_key = _fetch_served_key(args.gateway_url, "gateway")
        kn_key = _fetch_served_key(args.knowledge_url, "knowledge")
        with open(args.manifest, "r", encoding="utf-8") as fh:
            manifest = SurfaceAttestationManifest.from_dict(json.load(fh))
        ok, reason = verify_manifest(manifest, _load_pub(args.root))
        report = {"manifest_signature_ok": ok, "manifest_reason": reason}
        if ok:
            for sid, served in (("gateway", gw_key), ("knowledge-query", kn_key)):
                s_ok, s_reason = check_surface(manifest, sid, served)
                report[f"surface:{sid}:matches_vouched"] = s_ok
                report[f"surface:{sid}:reason"] = s_reason
        print(json.dumps(report, indent=2))
        all_ok = ok and report.get("surface:gateway:matches_vouched", False) \
            and report.get("surface:knowledge-query:matches_vouched", False)
        return 0 if all_ok else 1

    return 2


def _fetch_served_key(base_url: str, surface_id: str) -> bytes:
    """READ-ONLY: fetch a running surface's currently-served public key over HTTP.

    Gateway exposes its operator key at /operator/public-key; the knowledge
    engine exposes its evidence key at /authority/public-key. Both are public,
    ungated endpoints that write nothing. Returns the raw PEM bytes.
    """
    import httpx
    path = "/operator/public-key" if surface_id == "gateway" else \
        "/authority/public-key"
    with httpx.Client(base_url=base_url, timeout=5.0) as c:
        r = c.get(path)
        r.raise_for_status()
        data = r.json()
    return data["public_key_pem"].encode("utf-8")


if __name__ == "__main__":
    raise SystemExit(main())

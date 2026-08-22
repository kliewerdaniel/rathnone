#!/usr/bin/env python3
"""ADR 34 — operator-side tool for the evidence-authority trust log.

The knowledge engine's attestation key (``RATHNONE_EVIDENCE_KEY_PEM``) is the
evidence-domain root of trust. Until ADR 34 there was no way to ROTATE or
REVOKE it without redeploying, and an agent fetched the public key
trust-on-first-fetch. This tool lets an operator manage a small, self-certifying,
anchorable trust log:

    bootstrap   create a log rooted at a key (the anchor). Pin its fingerprint.
    rotate      emit a new trusted key + a 'rotate' entry signed by the CURRENT
                trusted key. The operator deploys the NEW key as
                RATHNONE_EVIDENCE_KEY_PEM; the log proves the transition was
                authorized by the prior key.
    revoke      emit a 'revoke' entry signed by the CURRENT trusted key, retiring
                it (e.g. suspected compromise). After revoke the service must be
                given a fresh bootstrapped log + key before it can sign again.

The agent verifies the served log against the PINNED anchor PEM -- not the
served root -- so a compromised service cannot forge a log. The log file this
tool writes is what the operator pins (out-of-band, file-permission-gated, never
the console).

Usage:
    # Start a log rooted at the provisioned key (anchor):
    python scripts/evidence_key_log.py bootstrap \\
        --key /secure/evidence_ed25519.pem --out /secure/evidence_trust_log.json
    # -> prints the anchor fingerprint; pin it in agent config.

    # Rotate to a freshly generated key:
    python scripts/evidence_key_log.py rotate \\
        --key /secure/evidence_ed25519.pem \\
        --log /secure/evidence_trust_log.json \\
        --out-key /secure/evidence_ed25519_next.pem
    # -> writes the new key PEM + appends a rotate entry; deploy evidence_ed25519_next.pem.

    # Revoke the current key (incident response):
    python scripts/evidence_key_log.py revoke \\
        --key /secure/evidence_ed25519.pem \\
        --log /secure/evidence_trust_log.json

Exit non-zero on any error.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.query.authority import (  # noqa: E402
    AuthorityLog,
    build_bootstrap_log,
    append_rotate,
    append_revoke,
)


def _load_key(path: str) -> Ed25519PrivateKey:
    from typing import cast
    return cast(
        Ed25519PrivateKey,
        serialization.load_pem_private_key(open(path, "rb").read(), password=None))


def _load_log(path: str) -> AuthorityLog:
    with open(path, "r", encoding="utf-8") as fh:
        return AuthorityLog.from_dict(json.load(fh))


def _write_log(path: str, log: AuthorityLog) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(log.as_dict(), fh, indent=2)
        fh.write("\n")


def _write_key(path: str, sk: Ed25519PrivateKey) -> None:
    pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as fh:
        fh.write(pem)


def main() -> int:
    ap = argparse.ArgumentParser(description="Manage the evidence-authority trust log (ADR 34).")
    sub = ap.add_subparsers(required=True, dest="cmd")

    b = sub.add_parser("bootstrap", help="create a log rooted at --key (the anchor)")
    b.add_argument("--key", required=True, help="evidence Ed25519 PEM (out-of-band)")
    b.add_argument("--out", required=True, help="where to write the trust log JSON")
    b.add_argument("--signer-id", default="evidence-authority")

    r = sub.add_parser("rotate", help="rotate to a new key, signed by the current key")
    r.add_argument("--key", required=True, help="CURRENT evidence Ed25519 PEM (signer)")
    r.add_argument("--log", required=True, help="existing trust log JSON")
    r.add_argument("--out-key", required=True, help="where to write the NEW key PEM")
    r.add_argument("--signer-id", default="evidence-authority")

    v = sub.add_parser("revoke", help="revoke the current key (incident response)")
    v.add_argument("--key", required=True, help="CURRENT evidence Ed25519 PEM (signer)")
    v.add_argument("--log", required=True, help="existing trust log JSON")
    v.add_argument("--signer-id", default="evidence-authority")

    args = ap.parse_args()

    if args.cmd == "bootstrap":
        sk = _load_key(args.key)
        log = build_bootstrap_log(sk, signer_id=args.signer_id)
        _write_log(args.out, log)
        print(json.dumps({"anchor_fingerprint": log.anchor_fingerprint,
                          "action": "bootstrap", "out": args.out}, indent=2))
        return 0

    if args.cmd == "rotate":
        sk = _load_key(args.key)
        log = _load_log(args.log)
        new_sk = Ed25519PrivateKey.generate()
        log2 = append_rotate(log, new_sk, sk, signer_id=args.signer_id)
        _write_key(args.out_key, new_sk)
        _write_log(args.log, log2)
        print(json.dumps({"action": "rotate",
                          "new_key_pem": args.out_key,
                          "log": args.log,
                          "current_pem_fingerprint":
                              _fp(new_sk.public_key().public_bytes(
                                  encoding=serialization.Encoding.PEM,
                                  format=serialization.PublicFormat.SubjectPublicKeyInfo))},
                         indent=2))
        return 0

    if args.cmd == "revoke":
        sk = _load_key(args.key)
        log = _load_log(args.log)
        log2 = append_revoke(log, sk, signer_id=args.signer_id)
        _write_log(args.log, log2)
        print(json.dumps({"action": "revoke", "log": args.log,
                          "current_trusted_key": log2.current_pem()}, indent=2))
        return 0

    return 2


def _fp(pem: bytes) -> str:
    import hashlib
    text = "".join(pem.decode("utf-8").split())
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())

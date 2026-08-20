#!/usr/bin/env python3
"""ADR 20 ops-side signing tool for live settlement (authorize_action).

The console deliberately never holds a signing key (custody design in
console/lib/api.ts). For a tenant that has an ``operator_allowlist`` configured,
POST /tenants/{tid}/authorize_action requires a signed OperatorCommand (verb=
"authorize") in the X-Operator-Command header, binding the exact request body.
This tool loads an operator Ed25519 key from an OUT-OF-BAND, file-permission-
gated path (never the console, never chat) and emits that header.

This is the operator-side counterpart to the gateway's _require_command gate. It
does not change any gateway behavior; it only produces a valid signed command so
live settlement works for operator-gated tenants without exposing the key to the
UI.

Usage:
    RATHNONE_ENFORCE_AUTH=1 RATHNONE_API_KEY=<key> \\
        python scripts/operator_sign.py \\
            --tenant TID --key /secure/path/operator_ed25519.pem \\
            --action '{"to":"0xAB","value":"1000000000000000000","nonce":1}' \\
            [--approve] [--downgrade '<downgrade json>'] [--require-human] \\
            [--nonce 1] [--operator-id op-1] [--gateway http://127.0.0.1:8765]

Exit non-zero on any refusal (missing command, bad sig, replay, body mismatch).
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from urllib import request as _ureq

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Local path so the script can be run from the repo root without install.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.security.operator import OperatorCommand, body_hash_of  # noqa: E402


def _load_key(path: str) -> "Ed25519PrivateKey":
    with open(path, "rb") as fh:
        return serialization.load_pem_private_key(fh.read(), password=None)


def _body_bytes(payload: dict) -> bytes:
    # Must match the gateway's canonicalization in app.authorize_action exactly:
    # json.dumps(body.model_dump(), sort_keys=True, separators=(",", ":")).
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def main() -> int:
    ap = argparse.ArgumentParser(description="Sign an authorize_action operator command (ADR 20).")
    ap.add_argument("--tenant", required=True)
    ap.add_argument("--key", required=True, help="path to operator Ed25519 PEM (out-of-band)")
    ap.add_argument("--action", required=True, help="JSON authorize_action body (the 'action' field)")
    ap.add_argument("--downgrade", default=None, help="JSON signed DowngradeRecord (ADR 18)")
    ap.add_argument("--approval", default=None,
                    help="JSON signed ApprovalRecord (operator-issued, binds to action_hash)")
    ap.add_argument("--require-human", action="store_true")
    ap.add_argument("--denylist", default="", help="comma-separated denylist entries")
    ap.add_argument("--nonce", type=int, default=0, help="replay-guarded command nonce")
    ap.add_argument("--operator-id", default="op-1")
    ap.add_argument("--gateway", default=os.environ.get("RATHNONE_GATEWAY", "http://127.0.0.1:8765"))
    ap.add_argument("--api-key", default=os.environ.get("RATHNONE_API_KEY", ""))
    args = ap.parse_args()

    key = _load_key(args.key)
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    action = json.loads(args.action)
    payload: dict = {"action": action}
    if args.approval:
        payload["approval"] = json.loads(args.approval)
    if args.downgrade:
        payload["downgrade"] = json.loads(args.downgrade)
    if args.require_human:
        payload["require_human_approval"] = True
    if args.denylist:
        payload["denylist"] = tuple(args.denylist.split(","))

    body = _body_bytes(payload)
    timestamp = time.monotonic_ns() if hasattr(time, "monotonic_ns") else int(time.time() * 1e9)
    cmd = OperatorCommand(
        verb="authorize", tenant_id=args.tenant,
        body_hash=body_hash_of(body), nonce=args.nonce,
        timestamp=timestamp, operator_id=args.operator_id,
        pubkey_pem=pub_pem)
    cmd.sig = key.sign(cmd.canonical_bytes()).hex()
    header = base64.b64encode(json.dumps({
        "verb": cmd.verb, "tenant_id": cmd.tenant_id, "body_hash": cmd.body_hash,
        "nonce": cmd.nonce, "timestamp": cmd.timestamp, "operator_id": cmd.operator_id,
        "pubkey_pem": cmd.pubkey_pem, "sig": cmd.sig,
    }).encode()).decode()

    url = f"{args.gateway}/tenants/{args.tenant}/authorize_action"
    req = _ureq.Request(
        url, data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Operator-Command": header,
            **({"Authorization": f"Bearer {args.api_key}"} if args.api_key else {}),
        })
    try:
        with _ureq.urlopen(req, timeout=30) as resp:
            out = resp.read().decode()
    except _ureq.HTTPError as e:
        sys.stderr.write(f"REFUSED {e.code}: {e.read().decode()}\n")
        return 1
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

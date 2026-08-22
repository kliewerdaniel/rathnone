#!/usr/bin/env python3
"""ADR 43 operator-side signing tool for harness `execute` (harness_apply).

The harness `explore` surface is silent AUTO and needs no signature. But the
`execute` surface is hard-blocked until a SIGNED operator command arrives
(verb="harness_apply"), bound to the exact /harness/authorize request body.

This tool is the out-of-band operator counterpart: an operator reviews the
harness's *proposed* request body (which includes the action string), signs it
with an Ed25519 key held OUT-OF-BAND (never the console, never chat), and emits
the value to put in the `X-Operator-Command` header. The harness then presents
that header when it calls HarnessAuthorizer.may_apply(action, kind="apply",
operator_command=...).

It mirrors scripts/operator_sign.py but for the harness scope. No new crypto:
it reuses OperatorCommand + body_hash_of from src/security/operator.py.

Usage:
    python scripts/harness_sign.py \\
        --key /secure/path/operator_ed25519.pem \\
        --body '{"kind":"apply","policy_allow":true,"action":"git commit -m wip"}' \\
        [--nonce 1] [--operator-id op-1] [--scope-id harness]

Exit non-zero on any refusal (bad key, malformed body).
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
from src.service.harness_auth import canonical_harness_body  # noqa: E402


def _load_key(path: str) -> "Ed25519PrivateKey":
    with open(path, "rb") as fh:
        return serialization.load_pem_private_key(fh.read(), password=None)


def main() -> int:
    ap = argparse.ArgumentParser(description="Sign a harness_apply operator command (ADR 43).")
    ap.add_argument("--key", required=True, help="path to operator Ed25519 PEM (out-of-band)")
    ap.add_argument("--body", required=True,
                    help="JSON of the exact /harness/authorize body the harness will POST")
    ap.add_argument("--scope-id", default="harness", help="harness scope id (must match the gateway)")
    ap.add_argument("--nonce", type=int, default=0, help="replay-guarded command nonce")
    ap.add_argument("--operator-id", default="op-1")
    ap.add_argument("--gateway", default=os.environ.get("RATHNONE_GATEWAY", "http://127.0.0.1:8765"))
    ap.add_argument("--api-key", default=os.environ.get("RATHNONE_API_KEY", ""))
    args = ap.parse_args()

    key = _load_key(args.key)
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    body = json.loads(args.body)
    # F5 (ADR 19): command timestamp uses wall-clock EPOCH nanoseconds, the same
    # domain the gateway verifies against (its _command_clock = Clock(epoch_ns)).
    timestamp = int(time.time() * 1_000_000_000)
    cmd = OperatorCommand(
        verb="harness_apply",
        tenant_id=args.scope_id,
        body_hash=body_hash_of(canonical_harness_body(body)),
        nonce=args.nonce,
        timestamp=timestamp,
        operator_id=args.operator_id,
        pubkey_pem=pub_pem,
    )
    cmd.sig = key.sign(cmd.canonical_bytes()).hex()

    header = base64.b64encode(json.dumps({
        "verb": cmd.verb, "tenant_id": cmd.tenant_id, "body_hash": cmd.body_hash,
        "nonce": cmd.nonce, "timestamp": cmd.timestamp, "operator_id": cmd.operator_id,
        "pubkey_pem": cmd.pubkey_pem, "sig": cmd.sig,
    }).encode()).decode()

    # Optionally push straight to the gateway if --gateway was given and the
    # operator wants to apply immediately (proves the round-trip end-to-end).
    if "--push" in sys.argv:
        url = f"{args.gateway}/harness/authorize"
        req = _ureq.Request(
            url, data=json.dumps(body).encode(), method="POST",
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

    # Default: emit the header value for the operator to hand to the harness.
    print(header)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

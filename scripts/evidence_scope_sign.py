#!/usr/bin/env python3
"""ADR 32 — operator-side minting tool for evidence-operation scopes.

The knowledge-query service, when its evidence-operation authority is
provisioned (``RATHNONE_EVIDENCE_OP_KEY_PEM``), requires a signed ``QueryScope``
on every query (``X-Evidence-Scope`` header). This tool loads the
evidence-OPERATION Ed25519 key from an OUT-OF-BAND, file-permission-gated path
(never the console, never chat) and emits the scope JSON.

Parallel to ``scripts/operator_sign.py`` but in the evidence domain: a separate
key, a separate trust domain. Mints a bearer, body-bound, replay-guarded,
time-windowed permission envelope for one graph + one agent.

Usage:
    python scripts/evidence_scope_sign.py \
        --key /secure/path/evidence_op_ed25519.pem \
        --graph skc --agent agent-1 \
        --op '{"kind":"MATCH","arg":"optimization"}' \
        [--capabilities MATCH,SOURCE] [--max-results 50] \
        [--ttl 3600] [--nonce 1] [--operator-id evidence-op]

The --op is the EXACT Op plan the agent will submit (or raw NL text with
--nl-text). The emitted scope's body_hash binds to that plan (or text), so it
cannot be replayed against a different query.

Exit non-zero on any error.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.query.scope import (  # noqa: E402
    QueryScope,
    EvidenceOpAuthority,
    op_body_hash,
    body_hash_of,
)


def _load_key(path: str) -> Ed25519PrivateKey:
    from typing import cast
    return cast(
        Ed25519PrivateKey,
        serialization.load_pem_private_key(
            open(path, "rb").read(), password=None))


def main() -> int:
    ap = argparse.ArgumentParser(description="Mint a signed evidence QueryScope (ADR 32).")
    ap.add_argument("--key", required=True,
                    help="path to evidence-OP Ed25519 PEM (out-of-band)")
    ap.add_argument("--graph", required=True, help="graph_name this scope is valid for")
    ap.add_argument("--agent", required=True, help="agent_id this scope authorizes")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--op", help="JSON Op plan the scope binds to (exact)")
    g.add_argument("--nl-text", help="raw NL query text the scope binds to (exact)")
    ap.add_argument("--capabilities", default="",
                    help="comma-separated allowed OpKind names; empty = all")
    ap.add_argument("--max-results", type=int, default=None,
                    help="cap on (included+excluded) entities; omit = unlimited")
    ap.add_argument("--ttl", type=int, default=3600,
                    help="scope lifetime in seconds (TTL window)")
    ap.add_argument("--nonce", type=int, default=0, help="replay-guard nonce")
    ap.add_argument("--operator-id", default="evidence-op")
    args = ap.parse_args()

    key = _load_key(args.key)
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    authority = EvidenceOpAuthority("evidence-op-authority", key)

    if args.op is not None:
        op_dict = json.loads(args.op)
        binding = op_body_hash(op_dict)
    else:
        binding = body_hash_of(args.nl_text.encode("utf-8"))

    now = int(time.time() * 1_000_000_000)  # epoch-ns, same domain as the gateway
    scope = QueryScope(
        graph_name=args.graph,
        agent_id=args.agent,
        capabilities=[c for c in args.capabilities.split(",") if c],
        max_results=args.max_results,
        not_before=now,
        not_after=now + int(args.ttl * 1_000_000_000),  # TTL in epoch-ns
        nonce=args.nonce,
        operator_id=args.operator_id,
        pubkey_pem=pub_pem,
        body_hash=binding,
    )
    authority.sign(scope)  # sets sig over the canonical record

    print(json.dumps(scope.as_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

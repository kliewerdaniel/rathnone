#!/usr/bin/env python3
"""ADR 35 — operator-side audit of the evidence-serving witness log.

ADR 30 attests each ``EvidenceRecord`` and ADR 35 records, server-side, *which*
record hash was served to *which* agent under *which* scope. But the log is
server-held: a compromised service can DROP entries before serving (it cannot
forge them — that would need the pinned evidence key). The audit defense is
*auditability*: the operator pins the expected evidence key so a substituted log
fails signature verification, and can archive the log to replay later.

This tool lets an operator run that audit off-line against a live service:

    verify     pull /witness/log and verify the hash chain + every signature
               off-line against the operator-pinned ADR 34 evidence PEM. Prints an
               audit table (seq, agent, capabilities, record hash, time).
    export     pull /witness/log and write it to a local file for archival / later
               off-line verification.

The tool never trusts the served public key; it uses the operator-pinned
``--evidence-key`` PEM (the same anchor used for ADR 34). Verification is
fail-closed: any chain break, bad signature, or unloadable PEM => exit 1.

Drift detection (does a served record still match a fresh execution?) is a
*separate* check and lives in the reference agent harness
(``KnowledgeAgent.assert_stable`` / ``reconcile`` / attested ``expect_hash``),
because the witness log deliberately stores only the record hash, not the query
spec (privacy-by-design — see ADR 35). The harness re-issues the query and
compares against the served hash.

Usage:
    # Audit the chain + signatures of a live deployment:
    python scripts/evidence_witness_verify.py verify \\
        --base-url http://127.0.0.1:8765 \\
        --evidence-key /secure/evidence_ed25519.pem

    # With the control-plane key if the service enforces RATHNONE_QUERY_API_KEY:
    python scripts/evidence_witness_verify.py verify \\
        --base-url https://evidence.internal \\
        --token $RATHNONE_QUERY_API_KEY \\
        --evidence-key /secure/evidence_ed25519.pem

    # Archive the log for later off-line replay:
    python scripts/evidence_witness_verify.py export \\
        --base-url http://127.0.0.1:8765 --out /audit/witness_$(date +%F).json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.query.witness import WitnessLog, verify_witness_log  # noqa: E402
from src.query.audit import (  # noqa: E402
    EntityAudit,
    assert_audit_cardinality,
    canonical_audit_hash,
    enumerate_entity_event_counts,
)


def _load_evidence_pem(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _client_get(base_url: str, token: str | None):
    """Real httpx GET bound to the operator-audited base URL."""
    import httpx

    base = base_url.rstrip("/")
    headers = {"X-Control-Plane-Key": token} if token else {}

    def get(url: str):
        return httpx.get(base + url, headers=headers, timeout=30)

    return get


def _fetch_json(client_get, url: str) -> dict:
    r = client_get(url)
    if r.status_code >= 400:
        raise SystemExit(f"GET {url} -> {r.status_code}: {r.text}")
    return r.json()


def _fmt_ts(ns: int) -> str:
    try:
        return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).isoformat()
    except (OSError, ValueError):
        return f"{ns}ns"


def _cmd_verify(args: argparse.Namespace) -> int:
    client_get = _client_get(args.base_url, args.token)
    evidence_pem = _load_evidence_pem(args.evidence_key)

    log_json = _fetch_json(client_get, "/witness/log")
    log = WitnessLog.from_dict(log_json)
    if not log.entries:
        print("witness log: EMPTY (nothing has been served yet)")
        return 0

    ok, reason = verify_witness_log(log, evidence_pem)
    if not ok:
        print(f"FAIL: witness log verification failed: {reason}")
        return 1

    print(f"witness log: VERIFIED — {len(log.entries)} entries, "
          f"authority '{log.authority_id}'")
    print(f"{'seq':>3}  {'agent':<16} {'capabilities':<28} "
          f"{'record_hash':<16} issued_at")
    print("-" * 90)
    for e in log.entries:
        caps = ",".join(e.capabilities) if e.capabilities else "<allow-all>"
        print(f"{e.seq:>3}  {e.agent_id:<16} {caps:<28} "
              f"{e.record_hash[:14]}… {_fmt_ts(e.issued_at)}")
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    client_get = _client_get(args.base_url, args.token)
    log_json = _fetch_json(client_get, "/witness/log")
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(log_json, fh, indent=2)
    n = len(log_json.get("entries", []))
    print(f"exported {n} entries -> {args.out}")
    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    """ADR 45 — anchor-first audit of an in-memory KnowledgeGraph.

    Loads a graph from an SKC artifact and enumerates EVERY entity (even ones
    with zero edges / zero served records), asserting result cardinality so an
    isolated entity is reported with event_count=0 rather than being silently
    dropped. Optionally cross-checks against a live witness log pulled from a
    running service, to confirm no entity was dropped between graph load and
    served-record replay.
    """
    from src.query.loader import graph_from_skc_artifact

    g = graph_from_skc_artifact(args.graph)
    rows: list[EntityAudit] = enumerate_entity_event_counts(g)
    assert_audit_cardinality(rows, g)  # fail-closed: raises on drop

    print(f"audit: {len(rows)} entities (cardinality == graph entity_count)")

    witness_log = None
    if args.base_url:
        client_get = _client_get(args.base_url, args.token)
        log_json = _fetch_json(client_get, "/witness/log")
        witness_log = WitnessLog.from_dict(log_json)
        # Re-enumerate with the live witness log bound (empty-safe per entity).
        rows = enumerate_entity_event_counts(g, witness_log=witness_log)
        assert_audit_cardinality(rows, g)
        print(f"cross-checked against witness log: "
              f"{len(witness_log.entries)} entries")

    print(f"{'entity_id':<20} {'type':<12} {'events':<7} {'witness':<8}")
    print("-" * 52)
    for r in rows:
        print(f"{r.entity_id:<20} {r.entity_type:<12} "
              f"{r.event_count:<7} {r.witness_hits:<8}")
    print(f"\naudit hash: {canonical_audit_hash(rows)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="ADR 35 witness-log operator audit")
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="verify chain + signatures off-line")
    v.add_argument("--base-url", required=True,
                   help="service base URL (e.g. http://127.0.0.1:8765)")
    v.add_argument("--evidence-key", required=True,
                   help="operator-pinned evidence-domain PEM (ADR 34 anchor)")
    v.add_argument("--token", default=None,
                   help="X-Control-Plane-Key (if service enforces one)")
    v.set_defaults(func=_cmd_verify)

    x = sub.add_parser("export", help="archive /witness/log to a local file")
    x.add_argument("--base-url", required=True)
    x.add_argument("--token", default=None)
    x.add_argument("--out", required=True, help="output JSON path")
    x.set_defaults(func=_cmd_export)

    a = sub.add_parser("audit", help="ADR 45 anchor-first entity audit of a graph")
    a.add_argument("--graph", required=True,
                   help="SKC artifact path to load as a KnowledgeGraph")
    a.add_argument("--base-url", default=None,
                   help="optional: cross-check against a live /witness/log")
    a.add_argument("--token", default=None,
                   help="X-Control-Plane-Key (if the service enforces one)")
    a.set_defaults(func=_cmd_audit)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

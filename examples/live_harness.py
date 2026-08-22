"""ADR 33 — live-transport knowledge-query harness (real network boundary).

This is the same contract as examples/agent_harness.py, but driven across a
REAL socket instead of in-process TestClient. It:

  1. builds the query service with an EVIDENCE-OPERATION authority provisioned
     (RATHNONE_EVIDENCE_OP_KEY_PEM) and an attestation authority,
  2. serves it on a real TCP socket via uvicorn (background server thread),
  3. talks to it with a real httpx.Client over http://127.0.0.1:PORT,
  4. for every query, presents a signed QueryScope bound to that exact query
     body (the ADR 32 envelope, enforced live across the wire),
  5. verifies every returned attestation OFF-LINE against the public key it
     fetched over the wire,
  6. proves the envelope bites: a narrow MATCH-only scope succeeds for a MATCH
     query, while an unscoped request to the provisioned server is refused (401),
  7. verifies the ADR 34 evidence-authority trust log against the PINNED anchor
     (no trust-on-first-fetch) and the ADR 35 witness log off-line against the
     SAME evidence key -- proving the served evidence is auditable end-to-end
     over a real socket, not just in unit tests.

Note on the envelope's granularity: a QueryScope binds to ONE query body (its
body_hash). The realistic operator pattern is therefore per-query: the operator
signs "agent may run THIS exact query, with THESE capabilities, for THIS long."
This harness mints a fresh scope for each query it issues.

Run:
    env -u PYTHONPATH -u VIRTUAL_ENV .venv/bin/python examples/live_harness.py

Optional env:
    RATHNONE_SKC_ARTIFACT  path to a research-knowledge-artifact/1.0 JSON
    RATHNONE_QUERY_PORT    TCP port to bind (default 8765)

A non-zero number of failures means a trust regression at the transport layer.
"""

from __future__ import annotations

import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx  # noqa: E402
import uvicorn  # noqa: E402

from src.query.agent import KnowledgeAgent  # noqa: E402
from src.query.attest import generate_keypair  # noqa: E402
from src.query.scope import (  # noqa: E402
    EvidenceOpAuthority,
    QueryScope,
    body_hash_of,
    nl_binding_bytes,
    op_body_hash,
)
from src.query.service import create_app  # noqa: E402
from src.query.algebra import Op  # noqa: E402

_SKC_DEFAULT = (
    "/Users/danielkliewer/Projects/research-compiler-agent/"
    "build-research/research-knowledge-artifact.json"
)


def _mint_scope(authority: EvidenceOpAuthority, *, graph_name: str,
                agent_id: str, body_hash: str, capabilities: list[str],
                max_results: int, nonce: int, ttl_ns: int = 3_600_000_000_000
                ) -> QueryScope:
    """Mint a fresh scope bound to a specific query body_hash."""
    now = time.time_ns()
    scope = QueryScope(
        graph_name=graph_name, agent_id=agent_id, capabilities=list(capabilities),
        max_results=max_results, not_before=now, not_after=now + ttl_ns,
        nonce=nonce, operator_id="evidence-op", pubkey_pem=authority.public_pem(),
        body_hash=body_hash)
    authority.sign(scope)
    return scope


def _serve(app, port: int, stop: threading.Event) -> None:
    """Run uvicorn in a background thread on a real TCP socket."""
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)

    def _watchdog():
        while not stop.is_set():
            time.sleep(0.05)
        server.should_exit = True

    threading.Thread(target=_watchdog, daemon=True).start()
    server.run()


def main() -> int:
    artifact = os.environ.get("RATHNONE_SKC_ARTIFACT", _SKC_DEFAULT)
    port = int(os.environ.get("RATHNONE_QUERY_PORT", "8765"))

    # Provision BOTH the attestation authority and the evidence-operation
    # authority by setting env BEFORE build (create_app reads env at call time).
    att_sk, att_pub = generate_keypair()
    op_sk, _ = generate_keypair()
    os.environ["RATHNONE_EVIDENCE_KEY_PEM"] = att_sk.decode("utf-8")
    os.environ["RATHNONE_EVIDENCE_OP_KEY_PEM"] = op_sk.decode("utf-8")
    _pub = att_pub  # public PEM of the evidence key; the operator-pinned anchor

    app = create_app()
    stop = threading.Event()
    t = threading.Thread(target=_serve, args=(app, port, stop), daemon=True)
    t.start()

    # Wait for the socket to actually accept connections (poll /health).
    base = f"http://127.0.0.1:{port}"
    up = False
    deadline = time.time() + 10.0
    while time.time() < deadline:
        try:
            with httpx.Client(base_url=base, timeout=1.0) as probe:
                if probe.get("/health").status_code == 200:
                    up = True
                    break
        except Exception:  # noqa: BLE001 -- socket not bound yet
            time.sleep(0.05)
    if not up:
        stop.set()
        print("ERROR: live server did not come up on", base)
        return 1

    results: dict[str, bool] = {}
    try:
        client = httpx.Client(base_url=base, timeout=5.0)
        agent = KnowledgeAgent(client)
        op_authority = EvidenceOpAuthority.from_pem("evidence-op-authority", op_sk)

        # 1. Load a real graph over the wire (load_graph is under require_key
        #    only, not require_scope, so no scope is needed here).
        load = agent.load_graph(artifact, graph_name="skc")
        results["graph_loaded_over_wire"] = (
            load["entities"] > 0 and load["edges"] > 0
        )

        # 2. NL query (attested) under a broad scope bound to THIS text.
        nl_text = "research about optimization connected to convex"
        nl_scope = _mint_scope(
            op_authority, graph_name="skc", agent_id="live-agent",
            body_hash=body_hash_of(nl_binding_bytes(nl_text)),
            capabilities=[], max_results=1000, nonce=1)
        agent.set_scope(nl_scope)
        nl = agent.query_nl(nl_text, graph_name="skc")
        agent.set_scope(None)
        results["nl_scoped_attested_signature_ok"] = bool(nl.signature_ok)
        results["nl_record_has_shape"] = bool(nl.included_ids or nl.excluded_ids) \
            and "compiled_op" in nl.raw

        # 3. Op query (attested, broad scope) with a fail-closed verify contract.
        op = {"kind": "MATCH", "arg": "learning"}
        op_scope = _mint_scope(
            op_authority, graph_name="skc", agent_id="live-agent",
            body_hash=op_body_hash(Op.from_dict(op).to_dict()),
            capabilities=[], max_results=1000, nonce=2)
        agent.set_scope(op_scope)
        op_res = agent.query_op(op, graph_name="skc", attested=True)
        results["op_scoped_attested_signature_ok"] = bool(op_res.signature_ok)
        # Contract-check reuses the SAME body but must present a FRESH nonce
        # (the replay guard consumed nonce 2 above). The operator pattern is
        # one scope per presentation; same permission, new nonce.
        op_scope2 = _mint_scope(
            op_authority, graph_name="skc", agent_id="live-agent",
            body_hash=op_body_hash(Op.from_dict(op).to_dict()),
            capabilities=[], max_results=1000, nonce=4)
        agent.set_scope(op_scope2)
        op_contract = agent.query_op(
            op, graph_name="skc", attested=True,
            expect_included=op_res.included_ids,
            expect_hash=op_res.raw["deterministic_hash"])
        results["op_contract_evaluated"] = bool(op_contract.contract_ok) \
            and op_contract.contract_ok is True
        agent.set_scope(None)

        # 4. Off-line re-verify from held JSON, independent of the server.
        rechecked = agent.verify_signature(nl)
        results["offline_reverify_independent"] = rechecked == nl.signature_ok

        # 5. ADR 32 over the wire: a NARROW MATCH-only scope bound to the MATCH
        #    op succeeds; an unscoped request to the provisioned server is
        #    refused (401).
        narrow = _mint_scope(
            op_authority, graph_name="skc", agent_id="live-agent",
            body_hash=op_body_hash(Op.from_dict(op).to_dict()),
            capabilities=["MATCH"], max_results=50, nonce=3)
        agent.set_scope(narrow)
        scoped_ok = agent.query_op(op, graph_name="skc", attested=False)
        results["scope_allows_in_capability_query"] = bool(scoped_ok.raw) \
            and "included" in scoped_ok.raw
        agent.set_scope(None)
        refused = client.post(
            "/query/op", json={"graph_name": "skc", "op": op},
            headers=agent._headers())
        results["scope_required_when_provisioned"] = refused.status_code == 401

        # 6. ADR 34 + 35 LIVE audit, over the real socket. The queries above were
        #    served attested, so they populated the witness log. Now prove the
        #    whole trust chain is verifiable off-line against the PINNED evidence
        #    key the operator holds out-of-band (NOT the served public key).
        #
        #    - ADR 34: the served authority trust log must verify against the
        #      pinned anchor PEM (no trust-on-first-fetch), and the key the
        #      service is currently signing with must equal the chain's current
        #      trusted key.
        anchor_pem = _pub  # public PEM of the evidence key we provisioned
        results["adr34_authority_anchor_verifies"] = agent.verify_authority(anchor_pem)
        #    - ADR 35: the served witness log must verify off-line against the
        #      same evidence key, and must actually contain the entries our
        #      attested queries produced (auditability, not just integrity).
        witness_ok = agent.verify_witness_log(anchor_pem)
        served = agent.fetch_witness_log()
        entries = served.get("entries", [])
        results["adr35_witness_log_verifies"] = bool(witness_ok) and len(entries) >= 2
        # The served record hashes must match what our own queries returned --
        # i.e. the log is not just internally valid, it records what we saw.
        served_hashes = {e.get("record_hash") for e in entries}
        results["adr35_witness_records_match_served"] = (
            nl.raw["deterministic_hash"] in served_hashes
            and op_res.raw["deterministic_hash"] in served_hashes
        )

        # 7. ADR 36 LIVE key rotation (no redeploy) + rotation-aware audit.
        #    Rotate the evidence key over the wire, then prove:
        #      - the NEW trust-log tip still verifies against the SAME pinned
        #        anchor (rotation was authorized by the prior key, not a forged
        #        root), which also refreshes the agent's pinned key;
        #      - re-serving an attested query after rotation still verifies
        #        off-line (under the rotated-in key);
        #      - the witness log verifies ROTATION-AWARE (spans both keys),
        #        while the single-key verify now REJECTS it (by design).
        rot = agent.rotate_authority()
        results["adr36_rotate_live_succeeds"] = bool(rot.get("rotated")) \
            and rot.get("current_key_seq") == 1
        results["adr34_authority_anchor_verifies_post_rotate"] = \
            agent.verify_authority(anchor_pem)
        post_trust = agent.fetch_trust_log()
        # Re-serve an attested op query under the rotated-in key.
        rot_scope = _mint_scope(
            op_authority, graph_name="skc", agent_id="live-agent",
            body_hash=op_body_hash(Op.from_dict(op).to_dict()),
            capabilities=[], max_results=1000, nonce=5)
        agent.set_scope(rot_scope)
        rot_res = agent.query_op(op, graph_name="skc", attested=True)
        agent.set_scope(None)
        results["adr36_post_rotation_attestation_verifies"] = \
            bool(rot_res.signature_ok)
        # Rotation-aware witness verify (spans bootstrap seq 0 + rotate seq 1).
        results["adr36_witness_log_anchored_verifies"] = \
            agent.verify_witness_log_anchored(post_trust)
        served2 = agent.fetch_witness_log()
        entries2 = served2.get("entries", [])
        key_seqs = {e.get("key_seq") for e in entries2}
        results["adr36_witness_spans_two_keys"] = (0 in key_seqs and 1 in key_seqs)
        # The single-key verify must now REJECT the rotated log (by design).
        results["adr36_singlekey_verify_rejects_rotated"] = \
            (agent.verify_witness_log(anchor_pem) is False)
    finally:
        stop.set()
        t.join(timeout=5.0)

    # --- report --------------------------------------------------------
    passed = sum(1 for v in results.values() if v)
    failed = [name for name, ok in results.items() if not ok]
    width = max(len(n) for n in results)
    for name, ok in results.items():
        print(f"  {name:<{width}}  {'OK' if ok else 'FAIL'}")
    print()
    print(f"SUMMARY: {passed} passed, {len(failed)} failed")
    if failed:
        print("FAILED CHECKS: " + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""ADR 31 — runnable reference agent harness (knowledge-query substrate).

Run:
    env -u PYTHONPATH -u VIRTUAL_ENV .venv/bin/python examples/agent_harness.py

Optional env:
    RATHNONE_SKC_ARTIFACT  path to a research-knowledge-artifact/1.0 JSON
                          (defaults to the real fixture used by the loader tests)

This is the demonstrable end-to-end agent: it loads a graph, submits queries,
and -- critically -- verifies every evidence record OFF-LINE against the
evidence-domain public key before trusting it. The final SUMMARY line reports
how many checks passed/failed, mirroring the repo's other PoC harnesses
(tests/poc_findings.py). A non-zero number of failures means a trust regression.
"""

from __future__ import annotations

import os
import sys

# Make the repo importable when run as a flat script (examples/ sits outside the
# package).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

from src.query.agent import KnowledgeAgent  # noqa: E402
from src.query.service import create_app  # noqa: E402


_SKC_DEFAULT = (
    "/Users/danielkliewer/Projects/research-compiler-agent/"
    "build-research/research-knowledge-artifact.json"
)


def main() -> int:
    artifact = os.environ.get("RATHNONE_SKC_ARTIFACT", _SKC_DEFAULT)
    client = TestClient(create_app())
    agent = KnowledgeAgent(client)
    results: dict[str, bool] = {}

    # 1. Load a real graph.
    load = agent.load_graph(artifact, graph_name="skc")
    results["graph_loaded"] = load["entities"] > 0 and load["edges"] > 0

    # 2. NL query (attested) -- the agent verifies the signature off-line.
    nl = agent.query_nl(
        "research about optimization connected to convex", graph_name="skc")
    results["nl_attested_signature_ok"] = bool(nl.signature_ok)
    results["nl_record_has_shape"] = bool(nl.included_ids or nl.excluded_ids) \
        and "compiled_op" in nl.raw

    # 3. Op query (attested) using a pre-built plan; assert a contract.
    op = {
        "kind": "MATCH",
        "arg": "learning",
    }
    op_res = agent.query_op(op, graph_name="skc", attested=True)
    results["op_attested_signature_ok"] = bool(op_res.signature_ok)
    # Re-run the same plan with an explicit expectation (the included ids we just
    # got) so the service's fail-closed verify() contract is exercised and the
    # agent can confirm it holds.
    op_contract = agent.query_op(
        op, graph_name="skc", attested=True,
        expect_included=op_res.included_ids,
        expect_hash=op_res.raw["deterministic_hash"])
    results["op_contract_evaluated"] = bool(op_contract.contract_ok) \
        and op_contract.contract_ok is True

    # 4. Non-attested route still returns a record (signature absent).
    plain = agent.query_nl("research about learning", graph_name="skc",
                           attested=False)
    results["plain_route_no_attestation"] = plain.attestation is None \
        and plain.signature_ok is None

    # 5. Drift detection -- re-run and confirm the included set is stable.
    stable = agent.assert_stable(
        "research about optimization connected to convex", graph_name="skc")
    results["evidence_drift_checked_stable"] = stable

    # 6. Re-derivation independence -- verify the last attested record again
    #    purely from the JSON we hold, with no further contact with the service.
    rechecked = agent.verify_signature(nl)
    results["offline_reverify_independent"] = rechecked == nl.signature_ok

    # 7. ADR 32 -- evidence-operation scope. Provision the op authority, mint a
    #    signed scope (MATCH only, cap 50 results) with the app's key, set it on
    #    the agent, and prove a scoped query succeeds. We also prove the service
    #    refuses a request that lacks a scope header (401) when provisioned.
    from src.query.attest import generate_keypair
    from src.query.scope import EvidenceOpAuthority, QueryScope, op_body_hash
    from src.query.algebra import Op

    sk_pem, _ = generate_keypair()
    os.environ["RATHNONE_EVIDENCE_OP_KEY_PEM"] = sk_pem.decode("utf-8")
    scoped_client = TestClient(create_app())
    del os.environ["RATHNONE_EVIDENCE_OP_KEY_PEM"]
    scoped_agent = KnowledgeAgent(scoped_client)
    scoped_agent.load_graph(artifact, graph_name="skc")

    now = __import__("time").time_ns()
    authority = EvidenceOpAuthority.from_pem("evidence-op-authority", sk_pem)
    op = {"kind": "MATCH", "arg": "learning"}
    bound = Op.from_dict(op).to_dict()
    scope = QueryScope(
        graph_name="skc", agent_id="harness-agent", capabilities=["MATCH"],
        max_results=50, not_before=now, not_after=now + 3_600_000_000_000,
        nonce=1, operator_id="evidence-op",
        pubkey_pem=authority.public_pem(), body_hash=op_body_hash(bound))
    authority.sign(scope)
    scoped_agent.set_scope(scope)
    scoped_ok = scoped_agent.query_op(op, graph_name="skc", attested=False)
    results["scope_allows_in_capability_query"] = bool(scoped_ok.raw) \
        and "included" in scoped_ok.raw
    scoped_agent.set_scope(None)
    # Without a scope header the provisioned service must refuse (401).
    refused = scoped_client.post(
        "/query/op", json={"graph_name": "skc", "op": op},
        headers=scoped_agent._headers())
    results["scope_required_when_provisioned"] = refused.status_code == 401

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

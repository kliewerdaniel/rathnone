"""ADR 31 — reference agent harness for the knowledge-query substrate.

A downstream agent consumes the Rathnone knowledge engine as a *service*: it
formulates a query, submits it, and must treat the returned ``EvidenceRecord`` as
an **attested, verifiable claim** -- not raw data. This module is the reference
client that does exactly that, end to end:

  1. load a graph from an SKC artifact;
  2. submit a query (NL text or an ``Op`` dict), asking for an attestation;
  3. verify the attestation OFF-LINE against the evidence-domain public key
     (fetched once from ``/authority/public-key``);
  4. optionally assert a reconciliation contract (expect_included / hash) and
     re-run to detect silent evidence drift.

Design invariants (mirror the substrate's posture):

  * The agent NEVER trusts the returned record on faith. It re-derives the
    record from the JSON and verifies the signature over the deterministic hash.
  * Verification is independent of the service that produced the record -- once
    the public key is known, verification needs only the record + attestation.
  * The agent prefers the **attested** routes; plain routes are available for
    services that don't need attribution.

The ``client`` is duck-typed: any object exposing ``.post(url, json=...)`` and
``.get(url)`` returning a response with ``.status_code`` and ``.json()`` works.
``fastapi.testclient.TestClient`` and ``httpx.Client`` both qualify, so the same
harness runs in-process (tests) or against a live deployment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .algebra import Op
from .attest import Attestation, EvidenceAuthority, verify_attestation
from .executor import EvidenceRecord


@dataclass
class QueryResult:
    """Everything an agent needs to adjudicate one query response."""
    graph_name: str
    raw: dict                                   # full service response JSON
    record: EvidenceRecord                       # re-derived from raw
    attestation: Optional[Attestation]           # None on non-attested routes
    signature_ok: Optional[bool] = None          # None until verified
    contract_ok: Optional[bool] = None           # None unless a contract was set

    @property
    def included_ids(self) -> list[str]:
        return [e.id for e in self.record.included]

    @property
    def excluded_ids(self) -> list[str]:
        return [e.id for e in self.record.excluded]


class KnowledgeAgent:
    """Reference client for the knowledge-query service.

    ``client`` is any httpx-like client (TestClient / httpx.Client). ``token`` is
    the optional ``X-Control-Plane-Key`` used if the service enforces
    ``RATHNONE_QUERY_API_KEY``.
    """

    def __init__(self, client: Any, token: Optional[str] = None):
        self._client = client
        self._token = token
        self._public_pem: Optional[bytes] = None
        self._history: list[QueryResult] = []

    # --- low-level request ----------------------------------------------
    def _headers(self) -> dict[str, str]:
        if self._token:
            return {"X-Control-Plane-Key": self._token}
        return {}

    def _post(self, url: str, json: dict) -> dict:
        r = self._client.post(url, json=json, headers=self._headers())
        if r.status_code >= 400:
            raise RuntimeError(f"{url} -> {r.status_code}: {r.text}")
        return r.json()

    # --- graph loading --------------------------------------------------
    def load_graph(self, artifact_path: str, graph_name: str = "default") -> dict:
        return self._post("/graphs/load", {
            "artifact_path": artifact_path, "graph_name": graph_name})

    # --- public-key bootstrap (off-line verification anchor) -------------
    def authority_public_key(self) -> bytes:
        """Fetch + cache the evidence-domain public key (PEM)."""
        if self._public_pem is None:
            r = self._client.get("/authority/public-key")
            if r.status_code >= 400:
                raise RuntimeError(
                    f"/authority/public-key -> {r.status_code}: {r.text}")
            self._public_pem = r.json()["public_key_pem"].encode("utf-8")
        assert self._public_pem is not None
        return self._public_pem

    # --- querying -------------------------------------------------------
    def query_nl(self, text: str, graph_name: str = "default",
                 *, attested: bool = True,
                 expect_hash: Optional[str] = None,
                 expect_included: Optional[list[str]] = None,
                 expect_excluded: Optional[list[str]] = None) -> QueryResult:
        url = "/query/nl/attested" if attested else "/query/nl"
        body = {
            "graph_name": graph_name, "text": text,
            "expect_hash": expect_hash,
            "expect_included": expect_included,
            "expect_excluded": expect_excluded,
        }
        raw = self._post(url, body)
        return self._wrap(raw, graph_name, attested)

    def query_op(self, op: Op | dict, graph_name: str = "default",
                 *, attested: bool = True,
                 expect_hash: Optional[str] = None,
                 expect_included: Optional[list[str]] = None,
                 expect_excluded: Optional[list[str]] = None) -> QueryResult:
        url = "/query/op/attested" if attested else "/query/op"
        op_dict = op.to_dict() if isinstance(op, Op) else op
        body = {
            "graph_name": graph_name, "op": op_dict,
            "expect_hash": expect_hash,
            "expect_included": expect_included,
            "expect_excluded": expect_excluded,
        }
        raw = self._post(url, body)
        return self._wrap(raw, graph_name, attested)

    def _wrap(self, raw: dict, graph_name: str, attested: bool) -> QueryResult:
        record = EvidenceRecord.from_dict(raw)
        att = Attestation.from_dict(raw["attestation"]) if attested else None
        res = QueryResult(graph_name=graph_name, raw=raw, record=record,
                          attestation=att)
        if attested:
            res.signature_ok = self.verify_signature(res)
        if raw.get("verify") is not None:
            res.contract_ok = bool(raw["verify"]["ok"])
        self._history.append(res)
        return res

    # --- off-line verification ------------------------------------------
    def verify_signature(self, result: QueryResult) -> bool:
        """Re-derive the record and check the attestation against the known
        evidence-domain public key. This is the core trust step: it does NOT
        depend on the service being honest at read time."""
        if result.attestation is None:
            return False
        return verify_attestation(result.record, result.attestation,
                                 self.authority_public_key())

    # --- drift detection -------------------------------------------------
    def reconcile(self, a: QueryResult, b: QueryResult) -> bool:
        """True iff two runs over the same query agree on the included set."""
        rr = a.record.reconcile_with(b.record)
        return rr.consistent

    def assert_stable(self, text: str, graph_name: str = "default",
                      *, attested: bool = True) -> bool:
        """Re-run a query and confirm the included set has not drifted versus
        the most recent prior result for the same graph. Returns True if
        stable (or if there was no prior result to compare)."""
        prior = next((h for h in reversed(self._history)
                      if h.graph_name == graph_name), None)
        fresh = self.query_nl(text, graph_name, attested=attested)
        if prior is None:
            return True
        return self.reconcile(prior, fresh)


__all__ = ["KnowledgeAgent", "QueryResult"]

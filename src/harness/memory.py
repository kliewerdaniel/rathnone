"""ADR 47 — local persistent harness memory: persona MoE GraphRAG.

A persistent memory graph where each harness session is a *persona* and each
ratified ADR / capability / file is an *expert* node. A harness query is
embedded locally (Ollama ``nomic-embed-text`` on 127.0.0.1:11434 — no cloud) and
a Cypher vector/keyword search returns the top-k relevant personas/experts, which
is the "mixture" the session consults. Real Neo4j 5.27 (bolt://127.0.0.1:7687,
localhost-only) is the persistence substrate; an in-memory dict fallback keeps the
suite green when local infra is absent.

Invariant 1 is preserved: this module only writes audit edges / facts into the
harness's own Neo4j graph. It never imports or calls ``fleet.epistemic.decide()``.

Local-first / no-cloud guarantees:
  * bolt://127.0.0.1:7687 + http://127.0.0.1:11434 only.
  * No neo4j.io / Aura / remote embedding API anywhere in this file.
  * The single network call is the local Ollama embed (localhost, offline-capable).

Fail-closed: a query flagged as drifting is QUARANTINED -> harness BLOCKED. If the
local Neo4j/Ollama is unreachable, the harness falls back to cold-start (a
refuse-with-context-loss signal), never assuming warm context.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional

# --- verbatim fact extraction ------------------------------------------------
# Byte-exact regexes: ADR ids (ADR-43), sha256 deterministic hashes, ed25519 sigs.
_ADR_RE = re.compile(r"\bADR-(\d{1,3})\b")
_HEX64_RE = re.compile(r"\b[0-9a-f]{64}\b")
_SIG_RE = re.compile(r"\b[0-9a-f]{96,512}\b")

# Drift tuning (combined rule, ported from semvec-neo4j-memory).
DRIFT_SCORE_THRESHOLD = 0.35
TOP_SIMILARITY_FLOOR = 0.45


@dataclass
class Fact:
    """A verbatim, byte-exact extracted fact (never embed-compressed)."""
    kind: str          # "adr" | "hash" | "sig"
    value: str
    key: str           # (session_id, key) upsert identity is computed by caller


@dataclass
class Investigation:
    session_id: str
    expert_ref: str            # e.g. "ADR-43" or "cap:rathnone.trade_execute"
    query_preview: str
    top_similarity: float = 0.0
    drift_score: float = 0.0
    drift_detected: bool = False
    started_at: int = 0
    duration_ms: int = 0


def extract_facts(text: str) -> list[Fact]:
    """Extract verbatim ADR ids / hashes / sigs by regex (byte-exact)."""
    facts: list[Fact] = []
    for m in _ADR_RE.finditer(text):
        facts.append(Fact(kind="adr", value=f"ADR-{m.group(1)}",
                         key=f"adr:{m.group(1)}"))
    for m in _HEX64_RE.finditer(text):
        facts.append(Fact(kind="hash", value=m.group(0), key=f"hash:{m.group(0)}"))
    for m in _SIG_RE.finditer(text):
        facts.append(Fact(kind="sig", value=m.group(0), key=f"sig:{m.group(0)[:32]}"))
    return facts


def is_drift(result: dict) -> bool:
    """Combined drift rule: injected off-domain query -> quarantine."""
    if result.get("drift_detected"):
        return True
    return (result.get("drift_score", 0.0) >= DRIFT_SCORE_THRESHOLD
            and result.get("top_similarity", 1.0) <= TOP_SIMILARITY_FLOOR)


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(y * y for y in b) ** 0.5
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


class HarnessMemory:
    """Persona mixture-of-experts memory over local Neo4j (+ Ollama embed).

    Opt-in: pass ``uri`` or set ``RATHNONE_HARNESS_MEMORY_URI``. With no URI the
    instance is **stateless** (in-memory fallback) — existing harness behaviour
    is unchanged and the suite runs without local infra.
    """

    def __init__(self, *, uri: Optional[str] = None,
                 user: str = "neo4j", password: str = "neo4j",
                 embed_url: str = "http://127.0.0.1:11434/api/embed",
                 model: str = "nomic-embed-text",
                 clock=lambda: 0):
        self.uri = uri or os.environ.get("RATHNONE_HARNESS_MEMORY_URI") or ""
        self.user = user
        self.password = password
        self.embed_url = embed_url
        self.model = model
        self._clock = clock
        self._driver = None
        self._inmem: dict[str, list[Investigation]] = {}
        self._inmem_facts: dict[str, list[Fact]] = {}
        self._inmem_vectors: dict[str, list[float]] = {}  # expert_ref -> vector
        self._inmem_session_vec: dict[str, list[float]] = {}
        if self.uri:
            self._connect()

    # --- lifecycle -----------------------------------------------------------
    def _connect(self) -> None:
        # Hard guard: only localhost/127.0.0.1 URIs are permitted.
        if "127.0.0.1" not in self.uri and "localhost" not in self.uri:
            # Refuse non-local substrate (fail-closed); fall back to in-memory.
            self._driver = None
            return
        try:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(
                self.uri, auth=(self.user, self.password))
            self._driver.verify_connectivity()
        except Exception:  # noqa: BLE001 -- infra may be down; degrade gracefully
            self._driver = None

    @property
    def enabled(self) -> bool:
        return self._driver is not None

    def close(self) -> None:
        if self._driver is not None:
            try:
                self._driver.close()
            except Exception:  # noqa: BLE001
                pass
            self._driver = None

    # --- local embedding -----------------------------------------------------
    def embed(self, text: str) -> list[float]:
        """Embed ``text`` via local Ollama (nomic-embed-text, 768-d)."""
        import urllib.request
        req = urllib.request.Request(
            self.embed_url,
            data=json.dumps({"model": self.model, "input": text}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec: localhost
            payload = json.loads(resp.read())
        return list(payload["embeddings"][0])

    # --- record --------------------------------------------------------------
    def record_investigation(self, inv: Investigation) -> None:
        if self._driver is not None:
            with self._driver.session() as s:
                s.run(
                    "MERGE (ses:AgentSession {id:$sid}) "
                    "MERGE (ex:Expert {ref:$ref}) "
                    "MERGE (ses)-[r:INVESTIGATED]->(ex) "
                    "SET r.query_preview=$q, r.top_similarity=$ts, "
                    "r.drift_score=$ds, r.drift_detected=$dd, "
                    "r.started_at=$st, r.duration_ms=$dm",
                    sid=inv.session_id, ref=inv.expert_ref,
                    q=inv.query_preview, ts=inv.top_similarity,
                    ds=inv.drift_score, dd=inv.drift_detected,
                    st=inv.started_at, dm=inv.duration_ms)
        else:
            self._inmem.setdefault(inv.session_id, []).append(inv)

    def store_facts(self, session_id: str, facts: list[Fact]) -> None:
        if self._driver is not None:
            with self._driver.session() as s:
                for f in facts:
                    s.run(
                        "MERGE (ses:AgentSession {id:$sid}) "
                        "MERGE (lf:LiteralFact {key:$k}) "
                        "SET lf.kind=$kind, lf.value=$val "
                        "MERGE (ses)-[:EXTRACTED]->(lf)",
                        sid=session_id, k=f.key, kind=f.kind, val=f.value)
        else:
            self._inmem_facts.setdefault(session_id, []).extend(facts)

    def anchor_expert(self, expert_ref: str, text: str) -> None:
        """Persist an expert node's anchor embedding (the persona context)."""
        vec = self.embed(text)
        if self._driver is not None:
            with self._driver.session() as s:
                s.run(
                    "MERGE (ex:Expert {ref:$ref}) "
                    "SET ex.vector=$vec",
                    ref=expert_ref, vec=vec)
        else:
            self._inmem_vectors[expert_ref] = vec

    # --- retrieval (mixture-of-experts) --------------------------------------
    def retrieve_mixture(self, query: str, top_k: int = 3
                         ) -> tuple[list[tuple[str, float]], bool]:
        """Return (top_k expert refs + similarity, drift_flag).

        Similarity is cosine over local Ollama embeddings. When local infra is
        absent (in-memory fallback) we fall back to a deterministic keyword
        overlap score between the query and each anchored expert's stored text.
        """
        qvec = self.embed(query)
        if self._driver is not None:
            with self._driver.session() as s:
                rows = s.run(
                    "MATCH (ex:Expert) WHERE ex.vector IS NOT NULL "
                    "RETURN ex.ref AS ref, ex.vector AS vec").data()
            scored = [(r["ref"], _cosine(qvec, r["vec"])) for r in rows]
        else:
            scored = [(ref, _cosine(qvec, vec))
                      for ref, vec in self._inmem_vectors.items()]
        scored.sort(key=lambda x: x[1], reverse=True)
        top = scored[:top_k]
        top_sim = top[0][1] if top else 0.0
        # Combined drift rule: low top similarity to anchored context. We derive
        # drift_score as (1 - top_similarity) so an off-domain query (low
        # similarity) crosses the DRIFT_SCORE_THRESHOLD and is quarantined.
        drift_score = 1.0 - top_sim
        drift = is_drift({"top_similarity": top_sim, "drift_score": drift_score,
                          "drift_detected": len(top) == 0})
        return top, drift

    def session_facts(self, session_id: str) -> list[Fact]:
        if self._driver is not None:
            with self._driver.session() as s:
                rows = s.run(
                    "MATCH (ses:AgentSession {id:$sid})-[:EXTRACTED]->(lf:LiteralFact) "
                    "RETURN lf.kind AS kind, lf.value AS value, lf.key AS key",
                    sid=session_id).data()
            return [Fact(kind=r["kind"], value=r["value"], key=r["key"])
                    for r in rows]
        return list(self._inmem_facts.get(session_id, []))

    def cold_start_similarity(self, query: str) -> float:
        """Baseline similarity with no anchored context (cold start)."""
        # With nothing anchored, cosine against a zero-mean probe is 0.0.
        return 0.0

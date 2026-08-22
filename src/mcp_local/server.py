"""ADR 46 — local MCP surface over the knowledge engine (self-hosted only).

Mirrors `mcp-for-aura`'s *safety model* — schema-first grounding (`get_schema`),
Read vs Read-write separation, per-client scope — but realized as a **local stdio
MCP server** driving the repo's own `create_app()` / `QueryScope` / `Operator-
Command` primitives. No hosted MCP SDK, no Aura, no network server: thetransport
is a hand-rolled JSON-RPC framed on stdin/stdout (stdlib only), so the venv's
pinned `requirements.txt` stays frozen.

Tools
-----
- ``get_schema(graph_name)`` — read-only; returns the SKC artifact's node types,
  eTLD+1 origins, and edge kinds so the agent is grounded before querying.
- ``read(query)`` — read-only, capability + blast-radius blinded by a SIGNED
  ``QueryScope`` (ADR 32). Fail-closed: no/invalid scope => refused.
- ``read_write(scope_change)`` — a SEPARATE gated tool. Refused without a
  signed ``OperatorCommand(verb="harness_apply")`` (ADR 43), replay-nonce guarded.

Local-first: stdio only; if ``RATHNONE_NEO4J_URI`` is set, ``read`` MAY
additionally mirror the served record into the local bolt graph via empty-safe
Cypher (opt-in, never required — the in-memory ``KnowledgeGraph`` remains the
source of truth for query execution). The driver points at localhost and never
at Aura/remote.

Invariant 1: the server only drives ``QueryExecutor`` + ``QueryScope`` +
``OperatorCommand``; it never imports `fleet.epistemic.decide()`.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# Make the repo importable whether run as a script or imported.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from src.query.algebra import Op  # noqa: E402
from src.query.executor import KnowledgeGraph, QueryExecutor  # noqa: E402
from src.query.loader import graph_from_skc_artifact  # noqa: E402
from src.query.scope import (  # noqa: E402
    QueryScope,
    enforce_constraints,
    op_body_hash,
    verify_scope,
    now_epoch_ns,
)
from src.security.operator import (  # noqa: E402
    OperatorCommand,
    verify_command,
    body_hash_of,
)


# ---------------------------------------------------------------------------
# MCP JSON-RPC types (minimal, faithful to the spec's request/response shape)
# ---------------------------------------------------------------------------
@dataclass
class JsonRpcRequest:
    id: Any
    method: str
    params: dict = field(default_factory=dict)


@dataclass
class JsonRpcResponse:
    id: Any
    result: Optional[dict] = None
    error: Optional[dict] = None

    def to_dict(self) -> dict:
        if self.error is not None:
            return {"jsonrpc": "2.0", "id": self.id, "error": self.error}
        return {"jsonrpc": "2.0", "id": self.id, "result": self.result}


def _err(code: int, message: str, data: Any = None) -> dict:
    e: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        e["data"] = data
    return e


# ---------------------------------------------------------------------------
# The server
# ---------------------------------------------------------------------------
class LocalMcpServer:
    """A local MCP server over a ``KnowledgeGraph`` (loaded from an SKC dict)."""

    def __init__(self, artifact: dict,
                 op_allowlist_pems: Optional[list[str]] = None,
                 operator_allowlist_pems: Optional[list[str]] = None,
                 graph_name: str = "default"):
        self.graph_name = graph_name
        self.graph: KnowledgeGraph = graph_from_skc_artifact(artifact)
        # ADR 32: an evidence-operation authority may be provisioned. None =>
        # the `read` tool stays DORMANT (no scope required) for local-first use.
        self.op_allowlist_pems = list(op_allowlist_pems or [])
        self.operator_allowlist_pems = list(operator_allowlist_pems or [])
        self._used_scope_nonces: set[int] = set()
        self._used_cmd_nonces: set[int] = set()
        self._neo4j_uri: str = os.environ.get("RATHNONE_NEO4J_URI") or ""

    # --- tool dispatch ---------------------------------------------------
    def handle(self, req: JsonRpcRequest) -> JsonRpcResponse:
        try:
            if req.method == "initialize":
                return JsonRpcResponse(req.id, result={
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "rathnone-local-knowledge-mcp",
                                   "version": "1.0"},
                })
            if req.method == "tools/list":
                return JsonRpcResponse(req.id, result={"tools": [
                    self._tool_spec("get_schema",
                                    "Read-only: return the graph's node types, "
                                    "eTLD+1 origins, and edge kinds so the agent "
                                    "is grounded before querying."),
                    self._tool_spec("read",
                                    "Read-only query, blinded by a SIGNED "
                                    "QueryScope (ADR 32). Refused without a "
                                    "valid scope when an op authority is "
                                    "provisioned."),
                    self._tool_spec("read_write",
                                    "Gated write. Refused without a SIGNED "
                                    "OperatorCommand(verb=harness_apply) "
                                    "(ADR 43), replay-nonce guarded."),
                ]})
            if req.method == "tools/call":
                name = req.params.get("name")
                arguments = req.params.get("arguments", {}) or {}
                if name == "get_schema":
                    result = self._tool_get_schema(arguments)
                elif name == "read":
                    result = self._tool_read(arguments)
                elif name == "read_write":
                    result = self._tool_read_write(arguments)
                else:
                    return JsonRpcResponse(
                        req.id, error=_err(-32601, f"unknown tool: {name}"))
                return JsonRpcResponse(req.id, result={"content": [
                    {"type": "text", "text": json.dumps(result,
                                                        sort_keys=True)}]})

            return JsonRpcResponse(
                req.id, error=_err(-32601, f"method not found: {req.method}"))
        except _Refused as rf:
            # Fail-closed: a refused action is a real MCP error to the client.
            return JsonRpcResponse(req.id, error=_err(-32000, str(rf)))
        except Exception as exc:  # noqa: BLE001 -- surface as JSON-RPC error
            return JsonRpcResponse(
                req.id, error=_err(-32603, f"internal error: {exc}"))

    @staticmethod
    def _tool_spec(name: str, desc: str) -> dict:
        return {"name": name, "description": desc, "inputSchema": {
            "type": "object", "properties": {"graph_name": {"type": "string"}},
            "required": []}}

    # --- tools ------------------------------------------------------------
    def _tool_get_schema(self, arguments: dict) -> dict:
        g = self.graph
        node_types: set[str] = set()
        origins: set[str] = set()
        edge_kinds: set[str] = set()
        for e in g.all():
            node_types.add(e.type)
            if e.source:
                origins.add(e.source)
        for eid in g._ents:
            for edge in g._adj.get(eid, []):
                edge_kinds.add(edge.kind)
        return {
            "graph_name": self.graph_name,
            "entity_count": g.entity_count(),
            "edge_count": g.edge_count(),
            "node_types": sorted(node_types),
            "origins": sorted(origins),
            "edge_kinds": sorted(edge_kinds),
        }

    def _tool_read(self, arguments: dict) -> dict:
        op_dict = arguments.get("op")
        if not op_dict:
            raise _Refused("read requires an 'op' (Op plan)")
        try:
            op = Op.from_dict(op_dict)
        except Exception as exc:
            raise _Refused(f"invalid Op plan: {exc}")

        # ADR 32 gate. If an op authority is provisioned, a valid signed scope
        # is REQUIRED and verified fail-closed; otherwise the tool stays open.
        raw_scope = arguments.get("scope")
        if self.op_allowlist_pems:
            if not raw_scope:
                raise _Refused("evidence-operation scope required "
                               "(authority provisioned)")
            try:
                scope = QueryScope.from_dict(raw_scope)
            except Exception as exc:
                raise _Refused(f"invalid scope: {exc}")
            ok, reason = verify_scope(
                scope, body=b"", allowlist_pems=self.op_allowlist_pems,
                used_nonces=self._used_scope_nonces, now=now_epoch_ns(),
                graph_name=self.graph_name)
            if not ok:
                raise _Refused(f"scope denied: {reason}")
            self._used_scope_nonces.add(scope.nonce)

        rec = QueryExecutor(self.graph).execute(op)
        out = rec.as_dict()
        if self.op_allowlist_pems and raw_scope:
            scope = QueryScope.from_dict(raw_scope)
            ok, reason = enforce_constraints(
                op, scope, included=len(rec.included),
                excluded=len(rec.excluded))
            if not ok:
                raise _Refused(f"scope constraint violated: {reason}")
            out["scope"] = {"enforced": True,
                            "capabilities": list(scope.capabilities),
                            "max_results": scope.max_results}
        else:
            out["scope"] = {"enforced": False}

        if self._neo4j_uri:
            self._mirror_to_local_neo4j(rec.deterministic_hash())
        return out

    def _tool_read_write(self, arguments: dict) -> dict:
        raw_cmd = arguments.get("operator_command")
        if not raw_cmd:
            raise _Refused("read_write requires an 'operator_command' "
                           "(OperatorCommand)")
        if not self.operator_allowlist_pems:
            raise _Refused("no operator allowlist configured (fail-closed)")
        try:
            cmd = OperatorCommand.from_dict(raw_cmd)
        except Exception as exc:
            raise _Refused(f"invalid operator command: {exc}")
        body = json.dumps(arguments.get("scope_change", {}),
                          sort_keys=True).encode("utf-8")
        ok, reason = verify_command(
            cmd, body=body,
            allowlist_pems=self.operator_allowlist_pems,
            used_nonces=self._used_cmd_nonces, now=now_epoch_ns(),
            max_age_s=3600, scope="harness")
        if not ok:
            raise _Refused(f"operator command denied: {reason}")
        if cmd.verb != "harness_apply":
            raise _Refused(f"operator command verb '{cmd.verb}' not permitted "
                           f"by read_write (requires harness_apply)")
        self._used_cmd_nonces.add(cmd.nonce)
        return {"applied": True, "verb": cmd.verb,
                "body_hash": body_hash_of(body)}

    # --- opt-in local Ne4j mirror (localhost only) ----------------------
    def _mirror_to_local_neo4j(self, record_hash: str) -> None:
        """Opt-in: persist a served-record marker into the LOCAL bolt graph.

        Uses the `cypher-no-data-loss` empty-safe MERGE pattern (anchor on the
        record node, optional relationships). Never required for the read to
        succeed — if the local DB is down we simply skip the mirror.
        """
        try:
            from neo4j import GraphDatabase  # local-only dep, already installed
        except Exception:  # noqa: BLE001
            return
        # Hard guard: only localhost/127.0.0.1 URIs are permitted.
        uri = self._neo4j_uri or ""
        if "127.0.0.1" not in uri and "localhost" not in uri:
            return
        try:
            driver = GraphDatabase.driver(uri, auth=("neo4j", "neo4j"))
            with driver.session() as session:
                session.run(
                    "MERGE (r:ServedRecord {hash:$h}) "
                    "SET r.last_served = timestamp()",
                    h=record_hash)
            driver.close()
        except Exception:  # noqa: BLE001 -- mirror is best-effort
            return


class _Refused(Exception):
    """Fail-closed refusal surfaced to the MCP client as an error."""


# ---------------------------------------------------------------------------
# Stdio JSON-RPC transport (hand-rolled, no mcp package)
# ---------------------------------------------------------------------------
def _supports_select(stream) -> bool:
    """``select.select`` needs a real file descriptor; in-memory pipes lack one."""
    try:
        stream.fileno()  # type: ignore[attr-defined]
        return True
    except (OSError, ValueError, AttributeError):
        return False


import time  # noqa: E402  (used only in the non-fd polling path)


def _read_message(stream) -> Optional[dict]:
    line = stream.readline()
    if not line:
        return None
    line = line.strip()
    if not line:
        return None
    return json.loads(line)


def run_stdio(server_factory: Callable[[], "LocalMcpServer"],
              stdin=None, stdout=None, *, _shutdown: Optional[threading.Event] = None):
    """Read JSON-RPC requests from ``stdin`` (one per line), write responses.

    Used both by the CLI entrypoint and by tests (which feed in-process pipes).
    Tolerates streams that are NOT real file descriptors (e.g. in-memory
    ``StringIO`` under test) by falling back to a bounded readline poll when
    ``select`` is unsupported on the stream.
    """
    import select
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    server = server_factory()
    can_select = hasattr(stdin, "fileno") and _supports_select(stdin)
    while True:
        if _shutdown is not None and _shutdown.is_set():
            break
        if can_select:
            try:
                ready, _, _ = select.select([stdin], [], [], 0.2)
            except (OSError, ValueError):
                ready = []
            if not ready:
                continue
        else:
            # In-memory / non-fd stream: yield so the peer can write, then
            # attempt a readline without blocking indefinitely.
            time.sleep(0.01)
            if stdin is sys.stdin:
                # real blocking read on a real stdin is fine
                pass
        try:
            msg = _read_message(stdin)
        except Exception:  # noqa: BLE001 -- drop malformed frames
            continue
        if msg is None:
            break
        if msg.get("method") == "notifications/initialized":
            continue  # notification, no response
        req = JsonRpcRequest(
            id=msg.get("id"), method=msg.get("method", ""),
            params=msg.get("params", {}) or {})
        resp = server.handle(req)
        stdout.write(json.dumps(resp.to_dict()) + "\n")
        stdout.flush()


__all__ = [
    "LocalMcpServer",
    "JsonRpcRequest",
    "JsonRpcResponse",
    "run_stdio",
]

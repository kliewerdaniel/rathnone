"""ADR 46 — local MCP surface tests (real stdio transport, not a mock).

Drives ``LocalMcpServer`` over an actual JSON-RPC stdio loop (in-process pipes)
exactly as an MCP client would:
  * ``initialize`` / ``tools/list`` negotiate the protocol;
  * ``get_schema`` grounds the agent (read-only, no scope);
  * ``read`` with a VALID signed ``QueryScope`` (ADR 32) is ALLOWED and is
    capability + max_results blinded;
  * ``read_write`` WITHOUT a signed ``OperatorCommand(harness_apply)`` is
    REFUSED (fail-closed).

Stdlib only for the transport; the signing uses the repo's own ``QueryScope`` /
``OperatorCommand`` primitives. No network, no Aura.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

from src.mcp_local.server import LocalMcpServer, run_stdio  # noqa: E402
from src.query.scope import EvidenceOpAuthority, QueryScope, op_body_hash  # noqa: E402
from src.query.algebra import Op  # noqa: E402
from src.security.operator import (  # noqa: E402
    OperatorAuthority,
    OperatorCommand,
    body_hash_of,
)

_ARTIFACT = {
    "graphs": {"concept_graph": {
        "nodes": [
            {"id": "n1", "label": "local-first", "type": "concept"},
            {"id": "n2", "label": "sovereignty", "type": "concept"},
        ],
        "edges": [{"id": "e1", "source": "n1", "target": "n2",
                   "type": "related"}],
    }},
    "documents_index": [
        {"doc_id": "d1", "title": "On Local-First", "domain": "arxiv",
         "authority": 0.9},
    ],
    "claims": [
        {"id": "c1", "doc_id": "d1", "text": "local-first is sovereign",
         "type": "claim", "confidence": 0.8},
    ],
}


def _write_msg(pipe, msg: dict) -> None:
    pipe.write(json.dumps(msg) + "\n")
    pipe.flush()


def _read_msg(pipe) -> dict:
    line = pipe.readline()
    assert line, "expected a response frame"
    return json.loads(line)


def _spawn_server(op_pem: str | None, operator_pem: str | None):
    """Boot the server in a thread over real OS pipe fds (selectable, safe)."""
    r_req, w_req = os.pipe()   # client -> server requests
    r_res, w_res = os.pipe()   # server -> client responses
    srv_in = os.fdopen(r_req, "r", buffering=1)
    srv_out = os.fdopen(w_res, "w", buffering=1)
    cli_in = os.fdopen(w_req, "w", buffering=1)
    cli_out = os.fdopen(r_res, "r", buffering=1)
    shutdown = threading.Event()

    def factory() -> LocalMcpServer:
        return LocalMcpServer(
            _ARTIFACT,
            op_allowlist_pems=[op_pem] if op_pem else None,
            operator_allowlist_pems=[operator_pem] if operator_pem else None,
            graph_name="skc",
        )

    t = threading.Thread(target=run_stdio, args=(factory, srv_in, srv_out),
                         kwargs={"_shutdown": shutdown}, daemon=True)
    t.start()
    return cli_in, cli_out, shutdown, t


def _cmd_dict(cmd: OperatorCommand) -> dict:
    return {
        "verb": cmd.verb, "tenant_id": cmd.tenant_id,
        "body_hash": cmd.body_hash, "nonce": cmd.nonce,
        "timestamp": cmd.timestamp, "operator_id": cmd.operator_id,
        "pubkey_pem": cmd.pubkey_pem, "sig": cmd.sig,
    }


def _rpc(inp, out, method, params=None, rid=1):
    _write_msg(inp, {"jsonrpc": "2.0", "id": rid,
                     "method": method, "params": params or {}})
    return _read_msg(out)


def test_initialize_and_tools_list():
    inp, out, shutdown, t = _spawn_server(None, None)
    try:
        r = _rpc(inp, out, "initialize", {})
        assert r["result"]["serverInfo"]["name"] == "rathnone-local-knowledge-mcp"
        tl = _rpc(inp, out, "tools/list")
        names = {t["name"] for t in tl["result"]["tools"]}
        assert names == {"get_schema", "read", "read_write"}
    finally:
        shutdown.set()


def test_get_schema_grounds_agent():
    inp, out, shutdown, t = _spawn_server(None, None)
    try:
        _rpc(inp, out, "initialize")
        r = _rpc(inp, out, "tools/call",
                 {"name": "get_schema", "arguments": {"graph_name": "skc"}})
        content = json.loads(r["result"]["content"][0]["text"])
        assert content["entity_count"] >= 3
        assert "concept" in content["node_types"]
        assert "related" in content["edge_kinds"]
    finally:
        shutdown.set()


def test_read_with_valid_scope_is_allowed_and_blinded():
    # Provision an evidence-operation authority, mint a scope for a MATCH op.
    op_key = Ed25519PrivateKey.generate()
    op_pem = op_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    auth = EvidenceOpAuthority("evidence-op-authority", op_key)
    op = Op.from_dict({"kind": "MATCH", "arg": "local-first"})
    scope = QueryScope(graph_name="skc", agent_id="agent-1",
                       capabilities=["MATCH"], max_results=10,
                       not_before=0, not_after=2**63, nonce=1,
                       pubkey_pem=op_pem,
                       body_hash=op_body_hash(op.to_dict()))
    auth.sign(scope)

    inp, out, shutdown, t = _spawn_server(op_pem, None)
    try:
        _rpc(inp, out, "initialize")
        r = _rpc(inp, out, "tools/call", {"name": "read", "arguments": {
            "op": op.to_dict(), "scope": scope.as_dict()}})
        assert "error" not in r, r.get("error")
        content = json.loads(r["result"]["content"][0]["text"])
        assert content["scope"]["enforced"] is True
        # MATCH on "local-first" should include the concept node n1.
        assert any(e.get("id") == "n1" for e in content["included"])
    finally:
        shutdown.set()


def test_read_write_without_signed_command_is_refused():
    # Provision an operator allowlist so read_write is gated.
    op_key = Ed25519PrivateKey.generate()
    op_pem = op_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    inp, out, shutdown, t = _spawn_server(None, op_pem)
    try:
        _rpc(inp, out, "initialize")
        # No operator_command at all -> refused.
        r = _rpc(inp, out, "tools/call", {"name": "read_write",
                 "arguments": {"scope_change": {"graph_name": "skc"}}})
        assert "error" in r, "read_write without a command must be refused"
        assert "operator_command" in r["error"]["message"].lower()
    finally:
        shutdown.set()


def test_read_write_with_signed_harness_apply_is_allowed():
    op_key = Ed25519PrivateKey.generate()
    op_pem = op_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    op_auth = OperatorAuthority(key=op_key, operator_id="harness-op")
    change = {"graph_name": "skc", "op": "annotate"}
    body = json.dumps(change, sort_keys=True).encode()
    cmd = OperatorCommand(verb="harness_apply", tenant_id="harness",
                          body_hash=body_hash_of(body), nonce=1,
                          timestamp=int(time.time() * 1e9), pubkey_pem=op_pem)
    cmd.sig = op_auth._key.sign(cmd.canonical_bytes()).hex()

    inp, out, shutdown, t = _spawn_server(None, op_pem)
    try:
        _rpc(inp, out, "initialize")
        r = _rpc(inp, out, "tools/call", {"name": "read_write",
                 "arguments": {"scope_change": change,
                               "operator_command": _cmd_dict(cmd)}})
        assert "error" not in r, r.get("error")
        content = json.loads(r["result"]["content"][0]["text"])
        assert content["applied"] is True
        assert content["verb"] == "harness_apply"
    finally:
        shutdown.set()

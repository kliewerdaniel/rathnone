"""ADR 35 — operator audit tool end-to-end (scripts/evidence_witness_verify.py).

Exercises the real CLI against a live app instance: a served attested query
populates the witness log, and the operator tool (a) verifies the chain +
signatures off-line against the pinned ADR 34 evidence key, (b) rejects a
substituted (wrong) key, and (c) archives the log. This is a black-box test of
the operator command, driven through ``main()`` with a TestClient standing in
for the live HTTP service.
"""

import importlib
import json
import os

import pytest

import scripts.evidence_witness_verify as audit

from src.query.attest import generate_keypair

_SKC_DEFAULT = (
    "/Users/danielkliewer/Projects/research-compiler-agent/"
    "build-research/research-knowledge-artifact.json"
)


def _make_app(monkeypatch):
    priv, pub = generate_keypair()
    monkeypatch.setenv("RATHNONE_EVIDENCE_KEY_PEM", priv.decode("utf-8"))
    monkeypatch.delenv("RATHNONE_EVIDENCE_OP_KEY_PEM", raising=False)
    monkeypatch.delenv("RATHNONE_QUERY_API_KEY", raising=False)
    mod = importlib.import_module("src.query.service")
    importlib.reload(mod)
    return mod.create_app(), priv, pub


def _serve_one(client):
    path = os.environ.get("RATHNONE_SKC_ARTIFACT", _SKC_DEFAULT)
    assert client.post("/graphs/load",
                       json={"artifact_path": path, "graph_name": "skc"}
                       ).status_code == 200
    r = client.post("/query/op/attested",
                    json={"graph_name": "skc",
                          "op": {"kind": "MATCH", "arg": "learning"}})
    assert r.status_code == 200, r.text


def _patch_client(monkeypatch, client):
    """Route the audit tool's HTTP at the live TestClient, not the network."""
    def fake_get(base_url, token):
        base = (base_url or "").rstrip("/")

        def get(url: str):
            return client.get(url if url.startswith("/") else base + url)

        return get

    monkeypatch.setattr(audit, "_client_get", fake_get)


def test_verify_with_pinned_key_passes_and_prints_table(monkeypatch, capsys, tmp_path):
    app, _priv, pub = _make_app(monkeypatch)
    from fastapi.testclient import TestClient
    client = TestClient(app)
    _serve_one(client)

    _patch_client(monkeypatch, client)
    key_file = tmp_path / "ev.pem"
    key_file.write_bytes(pub)

    rc = audit.main(["verify", "--base-url", "http://test",
                     "--evidence-key", str(key_file)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "VERIFIED" in out
    assert "<unscoped>" in out
    assert "<allow-all>" in out


def test_verify_with_wrong_key_fails(monkeypatch, capsys, tmp_path):
    app, _, _ = _make_app(monkeypatch)
    from fastapi.testclient import TestClient
    client = TestClient(app)
    _serve_one(client)

    _patch_client(monkeypatch, client)
    _, wrong_priv = generate_keypair()
    key_file = tmp_path / "wrong.pem"
    key_file.write_bytes(wrong_priv)

    rc = audit.main(["verify", "--base-url", "http://test",
                     "--evidence-key", str(key_file)])
    assert rc == 1
    assert "FAIL" in capsys.readouterr().out


def test_export_writes_log(monkeypatch, capsys, tmp_path):
    app, _, _ = _make_app(monkeypatch)
    from fastapi.testclient import TestClient
    client = TestClient(app)
    _serve_one(client)

    _patch_client(monkeypatch, client)
    out_file = tmp_path / "witness.json"
    rc = audit.main(["export", "--base-url", "http://test",
                     "--out", str(out_file)])
    assert rc == 0
    data = json.loads(out_file.read_text())
    assert len(data["entries"]) >= 1
    assert data["entries"][-1]["agent_id"] == "<unscoped>"

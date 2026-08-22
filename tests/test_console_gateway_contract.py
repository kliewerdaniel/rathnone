"""
Contract test: the operator console (console/lib/api.ts) depends on a fixed
gateway contract — specific endpoints + response shapes. Phase 5 claimed the
console "implemented" but it was never exercised against the live app, which is
how a malformed auth header (`Authorization: *** <key>` instead of `Bearer <key>`)
shipped unnoticed. This test drives the *real* FastAPI app via TestClient over
the exact routes the console calls and asserts the JSON shapes api.ts parses.

It does NOT render React (no headless browser here); it verifies the wire
contract the frontend assumes, which is the layer that was actually untested.
"""
import os

os.environ.setdefault("RATHNONE_API_KEY", "testkey")
os.environ.setdefault("RATHNONE_ENFORCE_AUTH", "0")
os.environ.setdefault("RATHNONE_KEY_OPS", "keyops")

from fastapi.testclient import TestClient  # noqa: E402

from src.service.app import app as _gateway_app  # noqa: E402

client = TestClient(_gateway_app)


def _mint():
    r = client.post("/tenants", json={"aum": 1_000_000, "live": False})
    assert r.status_code == 200, r.text
    return r.json()["tenant_id"]


def test_list_tenants_shape():
    # api.ts listTenants() reads r.tenant_ids
    r = client.get("/tenants")
    assert r.status_code == 200
    body = r.json()
    assert "tenant_ids" in body
    assert isinstance(body["tenant_ids"], list)


def test_create_tenant_shape():
    # api.ts createTenant() reads tenant_id, public_key_pem, settlement_address
    r = client.post("/tenants", json={"aum": 1_000_000, "live": False})
    assert r.status_code == 200
    body = r.json()
    for field in ("tenant_id", "public_key_pem", "settlement_address"):
        assert field in body, f"console expects '{field}' in /tenants response"
    # default (non-live) has no settlement address
    assert body["settlement_address"] is None


def test_tenant_info_shape():
    tid = _mint()
    # api.ts tenantInfo() reads aum, live, operator_gated
    r = client.get(f"/tenants/{tid}")
    assert r.status_code == 200
    body = r.json()
    for field in ("tenant_id", "aum", "live", "operator_gated"):
        assert field in body


def test_safety_endpoints_shape():
    # api.ts safety() reads breaker_open / live_signing_enabled
    r = client.get("/safety")
    assert r.status_code == 200
    body = r.json()
    assert "breaker_open" in body
    assert "live_signing_enabled" in body
    # halt + resume roundtrip (operator-only gates with RATHNONE_ENFORCE_AUTH=0)
    h = client.post("/safety/halt")
    assert h.status_code == 200 and h.json().get("breaker_open") is True
    rsum = client.post("/safety/resume")
    assert rsum.status_code == 200 and rsum.json().get("breaker_open") is False


def test_audit_meter_reconcile_shape():
    tid = _mint()
    for path, keys in (
        (f"/tenants/{tid}/audit", ("records",)),
        (f"/tenants/{tid}/meter", ("authorized_actions", "total_actions")),
        (f"/tenants/{tid}/reconciliation", ()),
    ):
        r = client.get(path)
        assert r.status_code == 200, f"{path}: {r.text}"
        body = r.json()
        for k in keys:
            assert k in body, f"console expects '{k}' in {path}"


def test_authorize_action_v2_shape():
    tid = _mint()
    action = {
        "action_id": "act-console-1",
        "tenant_id": tid,
        "capability": "rathnone.trade_execute",
        "instrument": "ETH",
        "side": "buy",
        "quantity": 1.0,
        "venue": "sim://exchange",
        "destination": "0xDEADBEEF",
        "actor": "console-contract-test",
    }
    r = client.post(
        f"/tenants/{tid}/authorize_action",
        json={"action": action, "require_human_approval": False, "denylist": ()},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    # console authorize/page.tsx reads r.verdict / r.blocked_reason (FLAT response)
    assert "verdict" in body, "console authorizeAction() reads r.verdict (flat)"


def test_auth_header_contract_when_enforced():
    """Regression for the `***` instead of `Bearer` bug.

    With enforcement ON, a request WITHOUT the Bearer header must be rejected,
    and WITH a correctly-formed Bearer header must be accepted. This pins the
    exact header shape the console must send.
    """
    saved = os.environ.get("RATHNONE_ENFORCE_AUTH")
    os.environ["RATHNONE_ENFORCE_AUTH"] = "1"
    try:
        # no auth -> 401/403
        bad = client.get("/tenants")
        assert bad.status_code in (401, 403), bad.text
        # correct Bearer -> 200
        good = client.get(
            "/tenants", headers={"Authorization": "Bearer testkey"}
        )
        assert good.status_code == 200, good.text
        # malformed (the old `***`) -> still rejected
        broken = client.get(
            "/tenants", headers={"Authorization": "*** testkey"}
        )
        assert broken.status_code in (401, 403), broken.text
    finally:
        if saved is None:
            os.environ.pop("RATHNONE_ENFORCE_AUTH", None)
        else:
            os.environ["RATHNONE_ENFORCE_AUTH"] = saved

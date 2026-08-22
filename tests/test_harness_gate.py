"""ADR 41/42/43 — harness authority gate tests.

Fail-closed by construction: any unverifiable state must refuse (DENY_OPEN /
BLOCKED), never run open. The registry case confirms the harness capability is
covered by the SAME parameterized generality suite as the finance trio.

ADR 43 (the fork this file closes): `execute` is hard-blocked until a SIGNED
operator command arrives — there is no local `pre_approved` acknowledgement
shortcut. A `execute` request with provisioned operators MUST carry a valid
OperatorCommand bound to the exact request body.
"""
import importlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import src.finance.registry as R
from src.finance.capabilities import CAP_FIN_AGENT_HARNESS_EXECUTE
from src.service import harness_auth as HA
from src.security.operator import OperatorCommand, body_hash_of
from src.service.harness_auth import sign_harness_command


def _op_key():
    return Ed25519PrivateKey.generate()


def _pem(key):
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _cmd(key, body, *, nonce=0, scope="harness"):
    return sign_harness_command(body, key, scope_id=scope, nonce=nonce)


# --- 1. registry auto-coverage (8th consumer) --------------------------------
def test_harness_capability_registered():
    labels = [lab for lab, _ in R.REGISTERED_CAPABILITIES]
    assert "rathnone/agent-harness-execute" in labels
    caps = [c for _, c in R.REGISTERED_CAPABILITIES]
    assert CAP_FIN_AGENT_HARNESS_EXECUTE in caps


@pytest.mark.parametrize("label,cap", R.REGISTERED_CAPABILITIES)
def test_decide_all_covers_harness(label, cap):
    """The harness capability rides the same parametrized decide() suite."""
    rows = R.decide_all(policy_allow=True, human=False)
    matched = [r for r in rows if r.capability == cap]
    assert matched, f"{cap} not covered by decide_all"
    assert matched[0].label == label


# --- 2. fail-closed core -----------------------------------------------------
def test_enforced_missing_key_denies_open():
    v = HA.evaluate_harness_action(enforce=True, api_key=False, breaker_open=False)
    assert v.decision == "DENY_OPEN"
    assert "API key missing" in v.reason


def test_explore_auto_allows_silently():
    # ADR 42: read-only research resolves to AUTO without prompting or signing.
    v = HA.evaluate_harness_action(enforce=True, kind="explore", breaker_open=False)
    assert v.decision == "ALLOW"


def test_apply_dormant_blocks_with_reason():
    # No operator allowlist configured => apply stays HUMAN -> BLOCKED, but with
    # an explicit "provision operators" reason (never silently allowed).
    v = HA.evaluate_harness_action(enforce=True, kind="apply", breaker_open=False)
    assert v.decision == "BLOCKED"
    assert "HUMAN" in v.reason


def test_apply_with_valid_signed_command_allows():
    # ADR 43: provision an operator; a correctly signed command converts apply to
    # ALLOW. The command is bound to the exact request body.
    key = _op_key()
    pem = _pem(key)
    body = {"kind": "apply", "policy_allow": True, "action": "git commit -m wip"}
    import json
    cmd = _cmd(key, body)
    v = HA.evaluate_harness_action(
        enforce=True, kind="apply", breaker_open=False,
        operator_command=cmd,
        operator_allowlist=[pem],
        used_nonces=set(),
        command_now=cmd.timestamp,
        command_scope="harness",
        request_body=json.dumps(body, sort_keys=True, separators=(",", ":")).encode(),
    )
    assert v.decision == "ALLOW"
    assert "operator=" in v.reason


def test_apply_missing_command_when_provisioned_denies():
    key = _op_key()
    pem = _pem(key)
    v = HA.evaluate_harness_action(
        enforce=True, kind="apply", breaker_open=False,
        operator_allowlist=[pem], used_nonces=set(), command_now=0,
        command_scope="harness", request_body=b"{}")
    assert v.decision == "DENY_OPEN"
    assert "operator-signed command required" in v.reason


def test_apply_invalid_signature_blocks():
    # A command signed by a DIFFERENT (non-allowlisted) key must be refused.
    good = _op_key()
    bad = _op_key()
    good_pem = good.public_key().public_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).Encoding.PEM,
        format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    import json
    body = {"kind": "apply", "policy_allow": True, "action": "rm -rf x"}
    cmd = _cmd(bad, body)  # signed by the wrong key
    v = HA.evaluate_harness_action(
        enforce=True, kind="apply", breaker_open=False,
        operator_command=cmd, operator_allowlist=[good_pem],
        used_nonces=set(), command_now=cmd.timestamp, command_scope="harness",
        request_body=json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
    assert v.decision == "DENY_OPEN"
    assert "command signature does not verify" in v.reason


def test_apply_replayed_nonce_blocks():
    key = _op_key()
    pem = _pem(key)
    import json
    body = {"kind": "apply", "policy_allow": True, "action": "git push"}
    cmd = _cmd(key, body, nonce=7)
    # First use succeeds...
    v1 = HA.evaluate_harness_action(
        enforce=True, kind="apply", breaker_open=False,
        operator_command=cmd, operator_allowlist=[pem],
        used_nonces=set(), command_now=cmd.timestamp, command_scope="harness",
        request_body=json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
    assert v1.decision == "ALLOW"
    # ...replaying the same nonce must be refused.
    v2 = HA.evaluate_harness_action(
        enforce=True, kind="apply", breaker_open=False,
        operator_command=cmd, operator_allowlist=[pem],
        used_nonces={7}, command_now=cmd.timestamp, command_scope="harness",
        request_body=json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
    assert v2.decision == "DENY_OPEN"
    assert "already used" in v2.reason


def test_apply_body_mismatch_blocks():
    # Command signed over one body cannot satisfy a different request body.
    key = _op_key()
    pem = _pem(key)
    import json
    signed_body = {"kind": "apply", "policy_allow": True, "action": "git commit -m good"}
    req_body = {"kind": "apply", "policy_allow": True, "action": "git commit -m evil"}
    cmd = _cmd(key, signed_body)
    v = HA.evaluate_harness_action(
        enforce=True, kind="apply", breaker_open=False,
        operator_command=cmd, operator_allowlist=[pem], used_nonces=set(),
        command_now=cmd.timestamp, command_scope="harness",
        request_body=json.dumps(req_body, sort_keys=True, separators=(",", ":")).encode())
    assert v.decision == "DENY_OPEN"
    assert "body_hash does not match" in v.reason


def test_invalid_kind_rejected():
    with pytest.raises(ValueError):
        HA.evaluate_harness_action(enforce=True, kind="delete_everything")


def test_policy_blocked_blocks():
    v = HA.evaluate_harness_action(
        enforce=True, breaker_open=False, policy_allow=False)
    assert v.decision == "BLOCKED"


def test_breaker_open_blocks_regardless_of_decide():
    # Operator halt is independent of decide() — even a signed apply must stop.
    key = _op_key()
    pem = _pem(key)
    import json
    body = {"kind": "apply", "policy_allow": True, "action": "git push"}
    cmd = _cmd(key, body)
    v = HA.evaluate_harness_action(
        enforce=True, breaker_open=True, kind="apply",
        operator_command=cmd, operator_allowlist=[pem], used_nonces=set(),
        command_now=cmd.timestamp, command_scope="harness",
        request_body=json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
    assert v.decision == "BLOCKED"
    assert v.breaker_open is True
    assert "circuit breaker" in v.reason


# --- 3. dev posture (ADR 17 unenforced) -------------------------------------
def test_dormant_allows_local_scratch():
    v = HA.evaluate_harness_action(enforce=False)
    assert v.decision == "ALLOW"
    assert v.dormant is True

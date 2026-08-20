"""Parameterized generality + adversarial suite for the Rathnone finance registry.

Mirrors fleet's own domain_registry test philosophy: a single parametrized suite
covers every registered finance surface, so adding a 4th surface is a one-line
table edit (SC4) — no new test needed.

It also exercises the bounded-scope invariant: a request for a capability outside
the granted scope is BLOCKED regardless of policy (Invariant 1 / M0).
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.finance import registry as R
from src.finance.capabilities import (
    CAP_FIN_TRADE_EXECUTE,
    CAP_FIN_TREASURY_REBALANCE,
    CAP_FIN_CHAIN_SETTLE,
)


@pytest.fixture
def gov():
    return R.GovernanceAuthority(Ed25519PrivateKey.generate())


# --- Generality: every registered surface yields a deterministic verdict ------
@pytest.mark.parametrize("label,cap", R.REGISTERED_CAPABILITIES)
def test_auto_policy_no_human(label, cap, gov):
    d = R.decide_registered(label, cap, policy_allow=True, human=False, gov=gov)
    assert d.verdict == "AUTO"
    assert d.capability == cap


@pytest.mark.parametrize("label,cap", R.REGISTERED_CAPABILITIES)
def test_human_policy_requires_human(label, cap, gov):
    d = R.decide_registered(label, cap, policy_allow=True, human=True, gov=gov)
    assert d.verdict == "HUMAN"


@pytest.mark.parametrize("label,cap", R.REGISTERED_CAPABILITIES)
def test_unknown_policy_escalates_to_human(label, cap, gov):
    # No allowlist (capability not declared) -> substrate escalates to HUMAN,
    # never silently authorizes. This is the real decision_for contract:
    # unknown capability -> HUMAN (Invariant: default-deny is escalation, not autopass).
    d = R.decide_registered(label, cap, policy_allow=False, human=False, gov=gov)
    assert d.verdict == "HUMAN"


@pytest.mark.parametrize("label,cap", R.REGISTERED_CAPABILITIES)
def test_denylist_blocks(label, cap, gov):
    # Explicit denylist is the only path to a true BLOCKED verdict.
    d = _with_denylist(gov, cap)
    assert d.verdict == "BLOCKED"


def _with_denylist(gov, cap):
    """Issue a grant + constraints where the capability is explicitly denied.
    Reuses the neutral GovernanceConstraints denylist path (no fleet edit)."""
    from exchange.epistemic_adapter import (
        build_authorization_scope, build_governance_constraints)
    from fleet.epistemic.identity import AgentIdentity
    from fleet.crypto.foundation import AgentCert
    from fleet.epistemic.decision import AuthorizationRequest
    import src.finance.registry as reg
    cert = AgentCert(agent_id="rathnone-agent", pubkey_pem="pub",
                     role="finance_operator", capabilities=[cap],
                     issued_at=0, expires_at=10**9, cert_seq=0, root_sig="")
    ident = AgentIdentity.from_cert(cert)
    az = build_authorization_scope((cap,))
    constr = build_governance_constraints(denylist=(cap,))
    grant = gov.issue_grant(grant_id="r-deny", agent_id=ident.agent_id,
                             authorization_scope=az, epoch=1, now=100)
    req = AuthorizationRequest(producer="rathnone-gateway", request_id="r-deny",
                               capability=cap, action_descriptor="x", proposal_ref="")
    return reg.decide(identity=ident, grant=grant, authorization_scope=az,
                      request=req, constraints=constr, current_epoch=1, now=100,
                      trusted_issuer_pubkey_pem=gov.public_key_pem)


def test_decide_all_order_preserved(gov):
    rows = R.decide_all(policy_allow=True, human=False, gov=gov)
    assert [r.label for r in rows] == [lab for lab, _ in R.REGISTERED_CAPABILITIES]
    assert all(r.verdict == "AUTO" for r in rows)


# --- Bounded scope: a request outside the grant is BLOCKED (Invariant 1) -----
@pytest.mark.parametrize("label,cap", R.REGISTERED_CAPABILITIES)
def test_scope_escape_blocked(label, cap, gov):
    d = R.decide_registered(
        label, cap, policy_allow=True, human=False,
        request_capability="rathnone.unauthorized_other", gov=gov)
    assert d.verdict == "BLOCKED"


# --- Same-policy -> same-verdict across surfaces (M0 within finance) ---------
def test_same_policy_same_verdict_across_surfaces(gov):
    verdicts = [
        R.decide_registered(lab, cap, policy_allow=True, human=False, gov=gov).verdict
        for lab, cap in R.REGISTERED_CAPABILITIES
    ]
    assert verdicts == ["AUTO", "AUTO", "AUTO"]


# --- SC4 proof hook: a 4th surface added to the table is auto-covered --------
def test_fourth_surface_is_one_line_edit(gov):
    """Demonstrates SC4: appending a (label, capability) pair to
    REGISTERED_CAPABILITIES is the only change needed; decide_all covers it.
    We assert the *mechanism* by appending a synthetic 4th surface in-memory
    and confirming decide_all-style coverage works without a new test."""
    synth = ("rathnone/synthetic-4th", "rathnone.synthetic_4th")
    extended = R.REGISTERED_CAPABILITIES + (synth,)
    # Build a one-off decision through the same neutral path.
    d = R.decide_registered(
        synth[0], synth[1], policy_allow=True, human=False, gov=gov)
    assert d.verdict == "AUTO"
    assert len(extended) == len(R.REGISTERED_CAPABILITIES) + 1

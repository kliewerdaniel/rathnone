"""Rathnone finance registry — the 7th consumer of fleet.epistemic.decide().

This mirrors fleet's own ``domain_registry`` pattern: it imports the *neutral*
builders from ``exchange.epistemic_adapter`` (build_authorization_scope,
build_governance_constraints, issue_grant, GovernanceAuthority) and calls the
SAME frozen ``fleet.epistemic.decide()`` that every fleet domain uses. It adds
zero substrate behavior.

The single source of truth is REGISTERED_CAPABILITIES — one (label, capability)
pair per finance surface. Adding a 4th surface is a one-line table edit plus a
constant; the parameterized generality suite (test_registry.py) auto-covers it.
This is the Rathnone-local proof of Meta-Invariant M0 (domain generality)
restricted to the finance slice (SC4).

Rathnone never imports the cognition layer. The import graph stays strictly
one-directional: this registry -> exchange.epistemic_adapter -> fleet.epistemic.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from exchange.epistemic_adapter import (
    build_authorization_scope,
    build_governance_constraints,
    issue_grant,
    GovernanceAuthority,
)
from fleet.epistemic.decision import AuthorizationRequest, decide
from fleet.epistemic.identity import AgentIdentity
from fleet.crypto.foundation import AgentCert

from .capabilities import (
    CAP_FIN_TRADE_EXECUTE,
    CAP_FIN_TREASURY_REBALANCE,
    CAP_FIN_CHAIN_SETTLE,
    CAP_FIN_AGENT_HARNESS_EXPLORE,
    CAP_FIN_AGENT_HARNESS_EXECUTE,
)

# The single source of truth: every registered finance surface, as a
# (human-readable label, literal capability string the substrate sees).
REGISTERED_CAPABILITIES: tuple[tuple[str, str], ...] = (
    ("rathnone/trade-execute", CAP_FIN_TRADE_EXECUTE),
    ("rathnone/treasury-rebalance", CAP_FIN_TREASURY_REBALANCE),
    ("rathnone/chain-settle", CAP_FIN_CHAIN_SETTLE),
    # ADR 41: the agent harness (Hermes + Codex sub-agents) joins as a consumer
    # of the SAME frozen decide() spine. No substrate behavior added.
    ("rathnone/agent-harness-execute", CAP_FIN_AGENT_HARNESS_EXECUTE),
    # ADR 42: harness split into two surfaces. EXPLORE (read-only research) is
    # AUTO; EXECUTE (consequential apply/commit/destructive) is HUMAN by default,
    # so the operator is prompted only for state-changing actions. Both ride the
    # same parametrized generality suite (test_registry.py auto-covers them).
    ("rathnone/agent-harness-explore", CAP_FIN_AGENT_HARNESS_EXPLORE),
)

# A default operator identity template; the grant's scope is always bound to the
# requested capability, exercising the bounded-scope invariant.
_DEFAULT_ROLE = "finance_operator"


@dataclass(frozen=True)
class FinanceDecision:
    """One substrate verdict produced through the Rathnone registry path."""
    label: str
    capability: str
    verdict: str
    reason: str


def decide_registered(
    label: str,
    capability: str,
    *,
    policy_allow: bool,
    human: bool,
    gov: GovernanceAuthority,
    request_capability: Optional[str] = None,
    now: int = 100,
    epoch: int = 1,
    agent_role: str = _DEFAULT_ROLE,
) -> FinanceDecision:
    """Run ONE generic decide() for a registered finance capability.

    The substrate never sees ``label`` — only the literal ``capability`` string
    plus the generic (grant, scope, policy) tuple. ``request_capability``
    (default = ``capability``) is what is actually requested; setting it to
    something else exercises the bounded-scope invariant (a request outside the
    granted scope is BLOCKED, regardless of policy).
    """
    request_capability = request_capability or capability
    cert = AgentCert(
        agent_id="rathnone-agent", pubkey_pem="pub", role=agent_role,
        capabilities=[capability], issued_at=0, expires_at=10**9,
        cert_seq=0, root_sig="",
    )
    ident = AgentIdentity.from_cert(cert)
    az = build_authorization_scope((capability,))
    constr = build_governance_constraints(
        allowlist=(capability,) if policy_allow else (),
        require_human_approval=human,
    )
    grant = gov.issue_grant(
        grant_id="r-reg", agent_id=ident.agent_id,
        authorization_scope=az, epoch=epoch, now=now)
    req = AuthorizationRequest(
        producer="rathnone-gateway", request_id="r-reg",
        capability=request_capability, action_descriptor="x", proposal_ref="")
    d = decide(
        identity=ident, grant=grant, authorization_scope=az, request=req,
        constraints=constr, current_epoch=epoch, now=now,
        trusted_issuer_pubkey_pem=gov.public_key_pem)
    return FinanceDecision(label, capability, d.verdict, d.reason)


def decide_all(
    *, policy_allow: bool, human: bool,
    gov: Optional[GovernanceAuthority] = None,
) -> list[FinanceDecision]:
    """Decide through the registry for EVERY registered finance surface under
    one policy. Order preserved from REGISTERED_CAPABILITIES."""
    gov = gov or GovernanceAuthority(Ed25519PrivateKey.generate())
    return [
        decide_registered(label, cap, policy_allow=policy_allow, human=human, gov=gov)
        for (label, cap) in REGISTERED_CAPABILITIES
    ]


__all__ = [
    "REGISTERED_CAPABILITIES",
    "FinanceDecision",
    "decide_registered",
    "decide_all",
]

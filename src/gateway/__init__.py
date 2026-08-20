"""Rathnone Gateway — the fresh product API surface (F4: Python service).

Thin wrapper over the frozen fleet.epistemic.decide(). It:
  1. accepts a RathnoneFinanceProposal (optionally carrying advisory evidence),
  2. builds the neutral AuthorizationRequest (dropping advisory evidence),
  3. calls the SAME frozen decide() every fleet domain uses,
  4. returns the AuthorizationDecision.

It never imports the cognition layer. The only authority inputs are the neutral
(identity, grant, scope, request, constraints, epoch, now, trusted_issuer)
tuple — Invariant 1 holds by construction.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from exchange.epistemic_adapter import (
    build_authorization_scope,
    build_governance_constraints,
    issue_grant,
    GovernanceAuthority,
)
from fleet.epistemic.decision import AuthorizationRequest, AuthorizationDecision, decide
from fleet.epistemic.identity import AgentIdentity
from fleet.crypto.foundation import AgentCert

from ..finance.proposal import RathnoneFinanceProposal


@dataclass
class GatewayContext:
    """The local-first authority runtime. Holds the trust anchor (governance
    authority) and the deterministic policy. The signing key NEVER leaves this
    context (hybrid model, F3)."""
    gov: GovernanceAuthority
    agent_role: str = "finance_operator"
    agent_id: str = "rathnone-agent"
    epoch: int = 1
    now: int = 100

    def _identity(self, capabilities):
        cert = AgentCert(
            agent_id=self.agent_id, pubkey_pem="pub", role=self.agent_role,
            capabilities=list(capabilities), issued_at=0, expires_at=10**9,
            cert_seq=0, root_sig="")
        return AgentIdentity.from_cert(cert)

    def authorize(
        self,
        proposal: RathnoneFinanceProposal,
        *,
        allowlist: tuple[str, ...],
        require_human_approval: bool = False,
        denylist: tuple[str, ...] = (),
    ) -> AuthorizationDecision:
        ident = self._identity((proposal.capability,))
        az = build_authorization_scope((proposal.capability,))
        constr = build_governance_constraints(
            allowlist=allowlist, denylist=denylist,
            require_human_approval=require_human_approval)
        grant = self.gov.issue_grant(
            grant_id="gw", agent_id=ident.agent_id,
            authorization_scope=az, epoch=self.epoch, now=self.now)
        req = proposal.to_authorization_request()
        return decide(
            identity=ident, grant=grant, authorization_scope=az, request=req,
            constraints=constr, current_epoch=self.epoch, now=self.now,
            trusted_issuer_pubkey_pem=self.gov.public_key_pem)

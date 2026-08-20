"""Rathnone finance proposal -> frozen AuthorizationRequest translator.

The gateway accepts a RathnoneFinanceProposal that may carry a quant/evidence
block (_advisory_evidence). That block is EXPLICITLY advisory: it is recorded for
human/audit context but is NEVER passed to fleet.epistemic.decide(). The only
fields that reach decide() are the neutral (identity, grant, scope, request,
constraints, epoch, now, trusted_issuer_pubkey_pem) tuple — none epistemic.

This is the single watchpoint for Invariant 1 (ModelOutput != Authorization):
if any code path ever forwards a probability/confidence/score into decide(), it
would have to alter fleet's signature — which is forbidden. The translator here
constructs AuthorizationRequest from declared fields only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from fleet.epistemic.authorization import AuthorizationRequest


@dataclass
class RathnoneFinanceProposal:
    """A finance action proposed by an (untrusted) agent or strategy.

    Fields:
      producer        — who proposed (opaque string, not authority)
      request_id      — idempotency / trace id
      capability      — one of the Rathnone finance capability strings
      action_descriptor — human-readable description of the action
      proposal_ref    — opaque ref to the proposal artifact
      advisory_evidence — OPTIONAL quant/evidence block. NEVER read by decide().
    """
    producer: str
    request_id: str
    capability: str
    action_descriptor: str
    proposal_ref: str = ""
    advisory_evidence: dict[str, Any] = field(default_factory=dict)

    def to_authorization_request(self) -> AuthorizationRequest:
        """Translate to the neutral substrate request. Deliberately drops
        advisory_evidence — it is not a field on AuthorizationRequest and must
        not influence the verdict."""
        return AuthorizationRequest(
            producer=self.producer,
            request_id=self.request_id,
            capability=self.capability,
            action_descriptor=self.action_descriptor,
            proposal_ref=self.proposal_ref,
        )

    def evidence_summary(self) -> str:
        """For audit/human display only. Not used in authorization."""
        if not self.advisory_evidence:
            return "(no advisory evidence)"
        return ", ".join(f"{k}={v}" for k, v in self.advisory_evidence.items())

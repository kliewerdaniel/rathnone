"""SettlementAuthRecord — binds an authorized action to an on-chain intent.

This is the new artifact Rathnone adds (docs/05-SCHEMA.md, B6). It extends the
substrate's AuthorizationDecision with a settlement-specific, fail-closed
binding. The verifier recomputes it from signed inputs alone (Invariant 3).

Fail-closed rules:
  - authorization_verdict != AUTO  -> no signature is committed; never signed.
  - intent_hash mismatch vs the executor's actual calldata -> verifier rejects.
  - ledger_next != H(ledger_prev || event) -> fail-closed verify.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from fleet.crypto.foundation import canonical_bytes, sha256


@dataclass(frozen=True)
class SettlementAuthRecord:
    kind: str = "settlement_authorization"
    decision_ref: str = ""            # hash of the governing AuthorizationDecision
    capability: str = ""
    chain: str = "evm_l2"             # chain-agnostic string field
    contract_address: str = ""
    intent_hash: str = ""             # H(to, value, calldata, nonce)
    epoch: int = 0
    authorization_verdict: str = ""    # AUTO | HUMAN | BLOCKED
    signer_commitment: str = ""       # Ed25519 sig over intent_hash (empty if not AUTO)
    ledger_prev: str = ""
    ledger_next: str = ""

    def state(self) -> dict:
        # NOTE: ledger_next is the chain link and is EXCLUDED from the canonical
        # body, otherwise the link would depend on itself. The verifier
        # recomputes ledger_next from (ledger_prev || canonical_body).
        return {
            "kind": self.kind,
            "decision_ref": self.decision_ref,
            "capability": self.capability,
            "chain": self.chain,
            "contract_address": self.contract_address,
            "intent_hash": self.intent_hash,
            "epoch": self.epoch,
            "authorization_verdict": self.authorization_verdict,
            "signer_commitment": self.signer_commitment,
            "ledger_prev": self.ledger_prev,
        }

    def compute_hash(self) -> str:
        return sha256(canonical_bytes(self.state()))

    @classmethod
    def build(
        cls,
        decision_ref: str,
        capability: str,
        intent_hash: str,
        verdict: str,
        *,
        chain: str = "evm_l2",
        contract_address: str = "",
        epoch: int = 0,
        ledger_prev: str = "",
        signer_commitment: str = "",
    ) -> "SettlementAuthRecord":
        rec = cls(
            decision_ref=decision_ref, capability=capability, chain=chain,
            contract_address=contract_address, intent_hash=intent_hash,
            epoch=epoch, authorization_verdict=verdict,
            signer_commitment=signer_commitment if verdict == "AUTO" else "",
            ledger_prev=ledger_prev)
        # Fail-closed ledger linkage: ledger_next = H(prev || event_body)
        event = canonical_bytes({"event": "settlement_auth", **rec.state()})
        ledger_next = sha256(ledger_prev.encode() + b"||" + event)
        return cls(**{**rec.state(), "ledger_next": ledger_next})

    def verify(self, expected_intent_hash: str, expected_ledger_prev: str) -> bool:
        """Independent verifier path (Invariant 3). Recomputes and checks."""
        if self.authorization_verdict != "AUTO" and self.signer_commitment:
            return False  # a non-AUTO record must carry no signature
        if self.intent_hash != expected_intent_hash:
            return False  # executor deception (A5)
        if self.ledger_prev != expected_ledger_prev:
            return False
        event = canonical_bytes({"event": "settlement_auth", **self.state()})
        expected_next = sha256(self.ledger_prev.encode() + b"||" + event)
        return self.ledger_next == expected_next

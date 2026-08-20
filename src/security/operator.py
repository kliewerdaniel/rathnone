"""v2 Operator Authority — makes HUMAN a first-class, cryptographically-bound
workflow (P0, Fork 3 = A).

Rationale (the gap this closes): in v1, HUMAN was a verdict plus an in-band
`human_approved` boolean flag. A privileged-but-compromised flow that flips that
flag to True could approve an action the operator never actually reviewed. Here,
approval is an *out-of-band, signed* statement:

    ApprovalRecord {
        action_hash,            # the EXACT action being approved
        operator_id,            # who
        decision,               # approve | reject | modify
        approved_action_hash,   # == action_hash for approve
        timestamp, nonce,
        sig                     # Ed25519 over canonical record, operator key
    }

The signer (live or simulated) REJECTS execution if
    approved_action_hash != action_hash
so "approve one thing, execute another" is structurally impossible. The approval
is bound to the exact economic transition, not to a request id or capability.

The operator key is an Ed25519 key. In v2 it is generated at boot if no key is
supplied; production should mount a real operator key via env/secret. This module
never feeds decide().
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from ..finance.action import FinancialAction


def _canonical(rec: dict) -> bytes:
    return json.dumps(
        {k: v for k, v in rec.items() if k != "sig"},
        sort_keys=True, separators=(",", ":"),
    ).encode()


@dataclass
class ApprovalRecord:
    action_hash: str
    operator_id: str
    decision: str            # "approve" | "reject" | "modify"
    approved_action_hash: str
    timestamp: int = 0
    nonce: int = 0
    sig: str = ""           # hex(Ed25519 sig) over canonical record

    def canonical_bytes(self) -> bytes:
        return _canonical({
            "action_hash": self.action_hash,
            "operator_id": self.operator_id,
            "decision": self.decision,
            "approved_action_hash": self.approved_action_hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
        })

    def verify(self, public_key) -> bool:
        if not self.sig:
            return False
        try:
            public_key.verify(bytes.fromhex(self.sig), self.canonical_bytes())
            return True
        except Exception:
            return False

    def binds_to(self, action_hash: str) -> bool:
        """True iff this approval covers the given action hash exactly."""
        return (self.decision == "approve"
                and self.approved_action_hash == action_hash == self.action_hash)


class OperatorAuthority:
    """Holds the operator's Ed25519 key and issues/verifies ApprovalRecords."""

    def __init__(self, key: Optional[Ed25519PrivateKey] = None,
                 operator_id: str = "rathnone-operator"):
        self._key = key or Ed25519PrivateKey.generate()
        self.operator_id = operator_id

    @property
    def public_key(self):
        return self._key.public_key()

    @property
    def public_key_pem(self) -> str:
        return self._key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def approve(self, action: FinancialAction, *, timestamp: int = 0,
                nonce: int = 0) -> ApprovalRecord:
        rec = ApprovalRecord(
            action_hash=action.action_hash,
            operator_id=self.operator_id,
            decision="approve",
            approved_action_hash=action.action_hash,
            timestamp=timestamp, nonce=nonce,
        )
        rec.sig = self._key.sign(rec.canonical_bytes()).hex()
        return rec

    def reject(self, action: FinancialAction, *, timestamp: int = 0,
               nonce: int = 0) -> ApprovalRecord:
        rec = ApprovalRecord(
            action_hash=action.action_hash,
            operator_id=self.operator_id,
            decision="reject",
            approved_action_hash=action.action_hash,
            timestamp=timestamp, nonce=nonce,
        )
        rec.sig = self._key.sign(rec.canonical_bytes()).hex()
        return rec


def load_operator_public_key(pem: str):
    return serialization.load_pem_public_key(pem.encode())


__all__ = ["OperatorAuthority", "ApprovalRecord", "load_operator_public_key"]

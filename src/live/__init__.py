"""Live (non-simulated) execution adapters for Rathnone.

This is the deferred "live track" (Phase 5B-follow-on). The default runtime
stays fully SIMULATED (no network, no credentials) via src/finance/adapters.py.
The adapters here are OPT-IN and produce REAL cryptographic artifacts:

  - SettlementAuthRecord.live_sign(): commits a genuine secp256k1 (Ethereum-
    compatible) signature over the authorized intent hash. The signature is
    independently verifiable by ANYONE using only the tenant's secp256k1
    public key / address — this is exactly what an on-chain settlement would
    require. (No live RPC is contacted; the signed intent is what a relayer
    or contract would consume. Wiring to a real L2 RPC is a deployment step,
    not a code-path change.)
  - OrderAuthRecord.live_sign(): commits a genuine Ed25519 signature over the
    authorized order, binding the operator's key to the decision.

Fail-closed, always:
  - if verdict != AUTO (or HUMAN without approval), live_sign refuses.
  - the signature is over the SAME intent_hash the verifier checks, so a
    tampered executor calldata fails verify().
  - this module imports ONLY signing primitives + the frozen decision types;
    it NEVER touches fleet.epistemic.decide() — signing happens strictly after
    the gateway has authorized.

Invariant 1 (ModelOutput != Authorization) is preserved: nothing here
influences a verdict; it only binds one that already exists.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .signing import (
    Secp256k1Signer,
    ed25519_sign,
    keccak256,
    canonical_json,
)


@dataclass
class SettlementAuthRecord:
    """Live settlement authorization: a REAL sig over an authorized intent.

    Mirrors src/finance/settlement.py's record but carries an actual secp256k1
    signature (Ethereum ecrecover-compatible), making it on-chain-verifiable.
    """

    decision_ref: str = ""
    capability: str = ""
    chain: str = "evm_l2"
    contract_address: str = ""
    intent_hash: str = ""          # hex(keccak256(canonical intent))
    verdict: str = ""
    signer_address: str = ""       # tenant settlement address (0x...)
    signature: str = ""            # hex(r||s||v), 65 bytes
    ledger_prev: str = ""
    ledger_next: str = ""

    @staticmethod
    def compute_intent_hash(intent: dict) -> str:
        """Deterministic intent hash = keccak256(canonical(intent))."""
        return keccak256(canonical_json(intent)).hex()

    @classmethod
    def build(
        cls,
        *,
        decision_ref: str,
        capability: str,
        intent: dict,
        verdict: str,
        signer: Secp256k1Signer,
        chain: str = "evm_l2",
        contract_address: str = "",
        ledger_prev: str = "",
    ) -> "SettlementAuthRecord":
        if verdict != "AUTO":
            raise ValueError("live settlement requires AUTO verdict")
        ih = cls.compute_intent_hash(intent)
        digest = bytes.fromhex(ih)
        sig = signer.sign_eth(digest)
        return cls(
            decision_ref=decision_ref,
            capability=capability,
            chain=chain,
            contract_address=contract_address,
            intent_hash=ih,
            verdict=verdict,
            signer_address=signer.address,
            signature=sig.hex(),
            ledger_prev=ledger_prev,
        )

    @classmethod
    def build_for_action(
        cls,
        *,
        action,
        decision_ref: str,
        capability: str,
        verdict: str,
        signer: Secp256k1Signer,
        chain: str = "evm_l2",
        contract_address: str = "",
        ledger_prev: str = "",
        approved: bool = False,
    ) -> "SettlementAuthRecord":
        """v2: sign over a FinancialAction's action_hash (not a raw intent dict).

        Preserves the same fail-closed rule as build(): requires AUTO, unless an
        explicit operator approval is supplied (HUMAN + approved). The signature
        binds the tenant's secp256k1 key to the exact economic action — tampering
        with the action changes the hash and breaks verify().
        """
        if verdict != "AUTO" and not approved:
            raise ValueError("live settlement requires AUTO verdict (or approval)")
        ih = action.action_hash
        digest = bytes.fromhex(ih)
        sig = signer.sign_eth(digest)
        return cls(
            decision_ref=decision_ref,
            capability=capability,
            chain=chain,
            contract_address=contract_address,
            intent_hash=ih,
            verdict=verdict,
            signer_address=signer.address,
            signature=sig.hex(),
            ledger_prev=ledger_prev,
        )

    def verify(self, expected_intent: dict) -> bool:
        """Independent verify: re-hash intent, recover signer, check address."""
        if self.verdict != "AUTO" or not self.signature:
            return False
        ih = self.compute_intent_hash(expected_intent)
        if ih != self.intent_hash:
            return False  # executor deception: intent != signed intent
        sig = bytes.fromhex(self.signature)
        recovered = recover_address(bytes.fromhex(self.intent_hash), sig)
        return recovered is not None and recovered.lower() == self.signer_address.lower()


@dataclass
class OrderAuthRecord:
    """Live order authorization: a REAL Ed25519 sig over an authorized order."""

    decision_ref: str = ""
    capability: str = ""
    venue: str = "sim://exchange"
    order_hash: str = ""           # hex(keccak256(canonical order))
    verdict: str = ""
    signer_pubkey: str = ""        # Ed25519 public key PEM
    signature: str = ""            # hex(Ed25519 sig)
    ledger_prev: str = ""
    ledger_next: str = ""

    @staticmethod
    def compute_order_hash(order: dict) -> str:
        return keccak256(canonical_json(order)).hex()

    @classmethod
    def build(
        cls,
        *,
        decision_ref: str,
        capability: str,
        order: dict,
        verdict: str,
        signing_key,  # Ed25519PrivateKey
        venue: str = "sim://exchange",
        ledger_prev: str = "",
    ) -> "OrderAuthRecord":
        if verdict != "AUTO":
            raise ValueError("live order requires AUTO verdict")
        oh = cls.compute_order_hash(order)
        sig = ed25519_sign(signing_key, bytes.fromhex(oh))
        return cls(
            decision_ref=decision_ref,
            capability=capability,
            venue=venue,
            order_hash=oh,
            verdict=verdict,
            signer_pubkey=_pem_of(signing_key),
            signature=sig.hex(),
            ledger_prev=ledger_prev,
        )

    @classmethod
    def build_for_action(
        cls,
        *,
        action,
        decision_ref: str,
        capability: str,
        verdict: str,
        signing_key,  # Ed25519PrivateKey
        venue: str = "sim://exchange",
        ledger_prev: str = "",
        approved: bool = False,
    ) -> "OrderAuthRecord":
        """v2: sign over a FinancialAction's action_hash (not a raw order dict)."""
        if verdict != "AUTO" and not approved:
            raise ValueError("live order requires AUTO verdict (or approval)")
        ah = action.action_hash
        sig = ed25519_sign(signing_key, bytes.fromhex(ah))
        return cls(
            decision_ref=decision_ref,
            capability=capability,
            venue=venue,
            order_hash=ah,
            verdict=verdict,
            signer_pubkey=_pem_of(signing_key),
            signature=sig.hex(),
            ledger_prev=ledger_prev,
        )

    def verify(self, expected_order: dict, public_key) -> bool:
        if self.verdict != "AUTO" or not self.signature:
            return False
        oh = self.compute_order_hash(expected_order)
        if oh != self.order_hash:
            return False
        try:
            public_key.verify(bytes.fromhex(self.signature), bytes.fromhex(self.order_hash))
            return True
        except Exception:
            return False


def _pem_of(ed25519_private_key) -> str:
    from cryptography.hazmat.primitives import serialization
    return ed25519_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def recover_address(digest: bytes, signature: bytes):
    from .signing import recover_address as _rec
    return _rec(digest, signature)


# Re-export signing primitives consumers may want.
__all__ = [
    "SettlementAuthRecord",
    "OrderAuthRecord",
    "Secp256k1Signer",
    "keccak256",
    "canonical_json",
]

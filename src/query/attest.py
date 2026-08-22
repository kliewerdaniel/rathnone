"""ADR 30 — evidence attestation (parallel evidence-domain authority).

The knowledge engine produces a deterministic ``EvidenceRecord``. This module
lets an authority *attest* that record so an agent can verify, off-line and
independently:

  - **authenticity** -- the evidence set was produced by the expected authority;
  - **integrity**    -- the included/excluded id set has not been tampered with;
  - **attribution**  -- which evidence-domain signer stands behind it.

Design constraints (consistent with Rathnone's frozen-spine posture):

  - The signing key is an **Ed25519 evidence-domain key that is SEPARATE from the
    frozen finance gateway's operator keyring** (ADR 17-23). We deliberately do
    NOT reuse ``src.security.keystore`` or ``src.security.operator`` here -- the
    evidence substrate is its own trust domain, a parallel authority, not a
    dependency on the money-path authz code.
  - The signature covers ONLY ``EvidenceRecord.deterministic_hash`` (the sha256
    over sorted included/excluded ids), never the reasons/plan text. That makes
    an attestation resilient to re-serialization of non-binding fields and keeps
    the verdict replayable from its hash -- Rathnone's key-free-verifiable
    discipline (Invariant 3).
  - Verification is **fail-closed**: any malformed input, wrong key, or tampered
    record yields ``False``, never an exception that a caller might swallow.

No network egress. ``cryptography`` is already a pinned repo dependency.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .executor import EvidenceRecord

ALGORITHM = "ed25519"


@dataclass
class Attestation:
    signer_id: str
    signed_hash: str
    signature: str                       # hex-encoded Ed25519 signature
    algorithm: str = ALGORITHM
    issued_at: int = field(default_factory=lambda: int(time.time()))

    def as_dict(self) -> dict:
        return {
            "signer_id": self.signer_id,
            "signed_hash": self.signed_hash,
            "signature": self.signature,
            "algorithm": self.algorithm,
            "issued_at": self.issued_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Attestation":
        return cls(
            signer_id=d["signer_id"],
            signed_hash=d["signed_hash"],
            signature=d["signature"],
            algorithm=d.get("algorithm", ALGORITHM),
            issued_at=int(d.get("issued_at", 0)),
        )


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (private_pem, public_pem), both PEM-encoded, for a fresh key."""
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    priv = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub


def load_private_key(pem: bytes) -> Ed25519PrivateKey:
    return cast(Ed25519PrivateKey, serialization.load_pem_private_key(pem, password=None))


def load_public_key(pem: bytes) -> Ed25519PublicKey:
    return cast(Ed25519PublicKey, serialization.load_pem_public_key(pem))


class EvidenceAuthority:
    """Holds an evidence-domain signing key and attests records."""

    def __init__(self, signer_id: str, private_key: Ed25519PrivateKey):
        self.signer_id = signer_id
        self._sk = private_key

    @classmethod
    def from_pem(cls, signer_id: str, pem: bytes) -> "EvidenceAuthority":
        return cls(signer_id, load_private_key(pem))

    def public_pem(self) -> bytes:
        return self._sk.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def signing_key(self) -> Ed25519PrivateKey:
        """The held private key (used to build the ADR 34 trust-log bootstrap
        entry; the substrate never exposes it over the wire)."""
        return self._sk

    def sign(self, record: EvidenceRecord) -> Attestation:
        h = record.deterministic_hash()
        sig = self._sk.sign(h.encode("utf-8"))
        return Attestation(
            signer_id=self.signer_id,
            signed_hash=h,
            signature=sig.hex(),
            issued_at=int(time.time()),
        )


def verify_attestation(record: EvidenceRecord,
                       att: Attestation,
                       public_pem: bytes) -> bool:
    """Fail-closed: return True only if ``att`` is a valid signature by the key
    in ``public_pem`` over the CURRENT hash of ``record``."""
    try:
        if att.algorithm != ALGORITHM:
            return False
        if att.signed_hash != record.deterministic_hash():
            # Tampered or drifted evidence set.
            return False
        pub = load_public_key(public_pem)
        pub.verify(bytes.fromhex(att.signature), att.signed_hash.encode("utf-8"))
        return True
    except Exception:  # noqa: BLE001 -- fail closed on any anomaly
        return False


__all__ = [
    "Attestation",
    "EvidenceAuthority",
    "generate_keypair",
    "load_private_key",
    "load_public_key",
    "verify_attestation",
    "ALGORITHM",
]

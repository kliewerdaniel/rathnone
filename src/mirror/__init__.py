"""Rathnone hybrid audit mirror client (F3: hybrid, key-free replica).

This is the CLIENT side of the optional cloud audit mirror. It holds:
  - the governance authority's PUBLIC key only (never the signing key),
  - a replica of the signed hash-chain ledger (the records pushed from the
    local-first gateway),

and performs INDEPENDENT verification (Invariant 3: Verification ⟂ Cognition):
reconstructs each entry's body and chain-link and confirms the signature +
chain integrity using only public material. It cannot authorize anything.

It reuses fleet's real ledger integrity contract (GENESIS head, canonical
signed body, sha256(prev || body) chain-link) so the mirror and the gateway
agree on the exact byte-level chain a verifier walks.
"""
from __future__ import annotations

import hashlib
import json
from typing import List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

GENESIS = b"\x00" * 32
_UNSIGNED = ("sig", "id", "seq")


def _entry_body(entry: dict) -> bytes:
    return json.dumps(
        {k: v for k, v in entry.items() if k not in _UNSIGNED},
        sort_keys=True, separators=(",", ":"),
    ).encode()


def load_public_key(pem: str) -> Ed25519PublicKey:
    """Load the governance public key from its PEM (the only key material the
    mirror is allowed to hold)."""
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_public_key(pem.encode() if isinstance(pem, str) else pem)


class AuditMirror:
    """Key-free forensic replica. Verifies a pushed ledger against the
    governance public key."""

    def __init__(self, governance_public_key: Ed25519PublicKey):
        self._pub = governance_public_key
        self._records: List[dict] = []
        self._prev = GENESIS

    def ingest(self, record: dict) -> None:
        """Receive one signed ledger record from the local gateway."""
        self._records.append(record)

    def verify_chain(self) -> tuple[bool, Optional[str]]:
        """Walk the replica and confirm:
          (1) every signature verifies against the governance public key,
          (2) every entry chains to the previous via sha256(prev || body),
          (3) the recorded prev matches the recomputed chain head.
        Returns (ok, error_reason). Fail-closed: any mismatch -> (False, reason).
        """
        prev = GENESIS
        for rec in self._records:
            body = _entry_body(rec)
            # (1) signature
            sig = bytes.fromhex(rec["sig"]) if isinstance(rec.get("sig"), str) else rec.get("sig")
            try:
                self._pub.verify(sig, body)
            except Exception:
                return False, f"signature invalid at seq {rec.get('seq')}"
            # (2)+(3) chain-link
            # The stored `prev` is the hex of the raw previous head (set by
            # make_ledger_entry as prev.hex()); the link advances by hashing
            # (prev || body). So we compare against prev.hex(), then advance.
            expected_prev = prev.hex()
            if rec.get("prev") != expected_prev:
                return False, f"chain break at seq {rec.get('seq')}"
            prev = hashlib.sha256(prev + body).digest()
        return True, None


def make_ledger_entry(seq: int, prev: bytes, body: dict,
                      signing_key) -> dict:
    """Helper used by the gateway side to produce a mirror-compatible record.
    Mirrors fleet's ledger envelope: signed body + seq + prev + id, signed with
    the (local, client-side) governance key. The mirror never sees that key.

    The signature is computed over _entry_body (the canonical signed body the
    verifier walks) — NOT over seq/id, which are envelope-only fields. This is
    what keeps AuditMirror.verify_chain()'s signature check consistent.
    """
    raw = {k: v for k, v in body.items() if k not in _UNSIGNED}
    raw["seq"] = seq
    raw["prev"] = prev.hex()
    raw["id"] = f"{seq:010d}"
    sig = signing_key.sign(_entry_body(raw))
    raw["sig"] = sig.hex()
    return raw

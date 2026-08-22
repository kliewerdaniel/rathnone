"""ADR 34 — evidence-authority trust log (parent key for the evidence domain).

ADR 30 gave the knowledge engine its own Ed25519 evidence key, SEPARATE from
the frozen finance gateway. But nothing anchored that key: an agent fetched
``/authority/public-key`` and trusted whatever it got (trust-on-first-fetch), and
there was no way to ROTATE or REVOKE the key without redeploying the service.

This module supplies the missing **trust anchor** as a small, self-certifying,
append-only hash-chain -- the evidence-domain analogue of a transparency log /
certificate authority. The chain is a sequence of ``AuthorityEntry`` records:

    * ``bootstrap`` -- the root (prev_hash = the anchor's own PEM hash). Signed by
      the anchor key. This is the trusted root the agent pins.
    * ``rotate``    -- introduces a NEW currently-trusted evidence key. Signed by
      the PREVIOUS trusted key (so only a key the chain already trusts can
      authorize its successor). prev_hash links to the prior entry.
    * ``revoke``    -- retires the CURRENT trusted key (same shape as rotate; the
      action tag marks the key DISTRUSTED from this entry forward). Signed by the
      key being revoked (it proves "I, the key in force, disavow myself").

The "current trusted key PEM" is the PEM carried by the LAST non-revoked entry.
An agent verifies the whole chain fail-closed against a **pinned anchor PEM**
(not the served one) -- so a compromised service cannot present a forged log;
rotation/revocation is observable and reversible-by-policy, and the gateway is
never touched.

Design constraints (consistent with the substrate):
    * Signatures cover a canonical, stable field set -- never the JSON text of
      the entry -- so re-serialization cannot break verification (Invariant 3
      discipline: verdict replayable from a hash).
    * The signature is over ``sha256(prev_hash || canonical_fields)``; prev_hash
      is the sha256 of the PREVIOUS entry's canonical bytes, so any tampering
      with a historical entry breaks every later signature (hash-chain).
    * Verification is fully OFF-LINE: needs only the log + the pinned anchor PEM.
    * ``cryptography`` is already a pinned dependency; no new deps.

State is per-``create_app()`` instance (built from ``RATHNONE_EVIDENCE_KEY_PEM``
when the operator has provisioned a log; otherwise a single bootstrap entry for
the live signing key so the endpoint always returns a valid log).
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .attest import ALGORITHM, load_private_key, load_public_key

ALGORITHM_LOG = ALGORITHM  # ed25519


def _b64ish(pem: bytes) -> str:
    """Stable text form of a PEM for hashing/binding (strip header/foot/runs)."""
    text = pem.decode("utf-8") if isinstance(pem, (bytes, bytearray)) else pem
    return "".join(text.split())


def _pem_fingerprint(pem: bytes) -> str:
    """sha256 of the canonical PEM bytes -- a stable anchor identifier."""
    return hashlib.sha256(_b64ish(pem).encode("utf-8")).hexdigest()


@dataclass
class AuthorityEntry:
    """One link in the evidence-authority trust log.

    ``prev_hash`` is ``""`` for the bootstrap root; otherwise the sha256 of the
    previous entry's canonical bytes. ``action`` is one of
    ``bootstrap`` / ``rotate`` / ``revoke``.
    """

    seq: int
    action: str                       # "bootstrap" | "rotate" | "revoke"
    signer_id: str
    pem: str                          # PEM text of the key this entry introduces/retires
    issued_at: int = 0
    prev_hash: str = ""
    sig: str = ""

    def canonical_bytes(self) -> bytes:
        """Stable, deterministic bytes a signature is computed over. Does NOT
        include ``sig`` (so a signature can be verified against these bytes)."""
        return json.dumps({
            "seq": self.seq,
            "action": self.action,
            "signer_id": self.signer_id,
            "pem": self.pem,
            "issued_at": self.issued_at,
            "prev_hash": self.prev_hash,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def signing_input(self) -> bytes:
        """What the signing key actually signs: the prev_hash chained in front
        of the canonical fields, so history cannot be rewritten."""
        return hashlib.sha256(
            self.prev_hash.encode("utf-8") + b"|" + self.canonical_bytes()
        ).digest()

    def as_dict(self) -> dict:
        return {
            "seq": self.seq,
            "action": self.action,
            "signer_id": self.signer_id,
            "pem": self.pem,
            "issued_at": self.issued_at,
            "prev_hash": self.prev_hash,
            "sig": self.sig,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AuthorityEntry":
        return cls(
            seq=int(d["seq"]),
            action=d["action"],
            signer_id=d["signer_id"],
            pem=d["pem"],
            issued_at=int(d.get("issued_at", 0)),
            prev_hash=d.get("prev_hash", ""),
            sig=d.get("sig", ""),
        )


@dataclass
class AuthorityLog:
    """An ordered, signed trust log. The 'current trusted key' is the PEM of the
    last entry whose action is not 'revoke'."""

    anchor_fingerprint: str
    entries: list[AuthorityEntry] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "anchor_fingerprint": self.anchor_fingerprint,
            "entries": [e.as_dict() for e in self.entries],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AuthorityLog":
        return cls(
            anchor_fingerprint=d.get("anchor_fingerprint", ""),
            entries=[AuthorityEntry.from_dict(e) for e in d.get("entries", [])],
        )

    def current_pem(self) -> Optional[str]:
        """PEM of the currently-trusted key, or None if the log ends in a
        revoke (the last entry's action is 'revoke' => the key in force was
        retired with no follow-on rotate). Only a 'bootstrap' or 'rotate' entry
        establishes a trusted key."""
        if not self.entries:
            return None
        last = self.entries[-1]
        if last.action in ("bootstrap", "rotate"):
            return last.pem
        return None


def _marshal_key(sk: Ed25519PrivateKey) -> str:
    return sk.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def sign_entry(entry: AuthorityEntry, sk: Ed25519PrivateKey) -> AuthorityEntry:
    """Set ``entry.sig`` over ``entry.signing_input()`` and return it. Caller has
    already filled seq/action/signer_id/pem/issued_at/prev_hash."""
    entry.sig = sk.sign(entry.signing_input()).hex()
    return entry


def build_bootstrap_log(sk: Ed25519PrivateKey,
                        signer_id: str = "evidence-authority") -> AuthorityLog:
    """Build the minimal valid log: a single bootstrap entry for ``sk``."""
    pem = _marshal_key(sk)
    entry = AuthorityEntry(
        seq=0, action="bootstrap", signer_id=signer_id, pem=pem,
        issued_at=int(time.time()), prev_hash="")
    sign_entry(entry, sk)
    return AuthorityLog(anchor_fingerprint=_pem_fingerprint(pem.encode("utf-8")),
                        entries=[entry])


def append_rotate(log: AuthorityLog, new_sk: Ed25519PrivateKey,
                  prev_sk: Ed25519PrivateKey,
                  signer_id: str = "evidence-authority") -> AuthorityLog:
    """Append a 'rotate' entry: ``new_sk`` becomes trusted, signed by ``prev_sk``
    (the key currently in force). Returns a NEW log (immutable)."""
    new_entries = list(log.entries)
    prev_hash = hashlib.sha256(log.entries[-1].canonical_bytes()).hexdigest() \
        if log.entries else ""
    entry = AuthorityEntry(
        seq=len(new_entries), action="rotate", signer_id=signer_id,
        pem=_marshal_key(new_sk), issued_at=int(time.time()), prev_hash=prev_hash)
    sign_entry(entry, prev_sk)
    new_entries.append(entry)
    return AuthorityLog(anchor_fingerprint=log.anchor_fingerprint,
                        entries=new_entries)


def append_revoke(log: AuthorityLog, prev_sk: Ed25519PrivateKey,
                  signer_id: str = "evidence-authority") -> AuthorityLog:
    """Append a 'revoke' entry: the current trusted key disavows itself, signed
    by ``prev_sk``. The 'current trusted key' becomes None until a later rotate."""
    new_entries = list(log.entries)
    prev_hash = hashlib.sha256(log.entries[-1].canonical_bytes()).hexdigest() \
        if log.entries else ""
    entry = AuthorityEntry(
        seq=len(new_entries), action="revoke", signer_id=signer_id,
        pem=_marshal_key(prev_sk), issued_at=int(time.time()), prev_hash=prev_hash)
    sign_entry(entry, prev_sk)
    new_entries.append(entry)
    return AuthorityLog(anchor_fingerprint=log.anchor_fingerprint,
                        entries=new_entries)


def verify_trust_log(log: AuthorityLog, anchor_pem: bytes) -> tuple[bool, Optional[str]]:
    """Fail-closed verification of a trust log against a PINNED anchor PEM.

    Returns ``(ok, reason)``. Rejects when:
      * the log is empty;
      * ``anchor_fingerprint`` does not match the pinned anchor PEM (the agent
        refuses to trust a log rooted at an unknown key -- no TOFU);
      * entries are out of order (seq), or the first entry is not ``bootstrap``;
      * any entry's signature fails against the key that entry claims to be
        authorized by (bootstrap: the anchor; rotate/revoke: the PREVIOUS
        trusted key);
      * the prev_hash chain is broken (tampering with history).

    ``anchor_pem`` is the operator-pinned root; it is NEVER taken from the served
    log. This is the whole point: the agent does not trust the service to name
    its own root.
    """
    if not log.entries:
        return False, "empty trust log"
    if log.anchor_fingerprint != _pem_fingerprint(anchor_pem):
        return False, "anchor fingerprint does not match pinned anchor"

    def _expected_signer_pem(entries_so_far: list[AuthorityEntry]) -> Optional[str]:
        # The key authorized to sign the next entry is the PEM of the last
        # non-revoked entry in the chain so far.
        for e in reversed(entries_so_far):
            if e.action != "revoke":
                return e.pem
        return None

    expected_prev = ""
    seen: list[AuthorityEntry] = []
    for i, e in enumerate(log.entries):
        if i == 0:
            if e.action != "bootstrap":
                return False, f"entry 0 must be bootstrap, got {e.action}"
            if e.prev_hash != "":
                return False, "bootstrap prev_hash must be empty"
        else:
            if e.action not in ("rotate", "revoke"):
                return False, f"entry {i} has invalid action {e.action}"
            if e.prev_hash != expected_prev:
                return False, f"entry {i} prev_hash chain broken"
        if e.seq != i:
            return False, f"entry {i} seq mismatch ({e.seq})"

        # The key authorized to sign entry i: the bootstrap entry signs with its
        # own PEM (= the anchor); every later entry signs with the PREVIOUS
        # trusted key (a non-revoked entry always exists by construction, so
        # signer_pem is never None here).
        if i == 0:
            signer_pem = log.entries[0].pem
        else:
            prior = _expected_signer_pem(seen)
            if prior is None:
                return False, f"entry {i} has no authorized prior signer"
            signer_pem = prior
        try:
            pk = load_public_key(signer_pem.encode("utf-8"))
        except Exception:  # noqa: BLE001
            return False, f"entry {i} signer PEM unloadable"
        try:
            pk.verify(bytes.fromhex(e.sig), e.signing_input())
        except Exception:  # noqa: BLE001 -- fail closed on any anomaly
            return False, f"entry {i} signature does not verify"

        # advance chain
        seen.append(e)
        expected_prev = hashlib.sha256(e.canonical_bytes()).hexdigest()
    return True, None


def trusted_key_for_seq(log: AuthorityLog, *, seq: int,
                        fingerprint: Optional[str] = None) -> Optional[str]:
    """Resolve the trusted evidence key introduced by trust-log entry ``seq``.

    Used by the ADR 36 rotation-aware witness verification: a served witness
    entry is bound to ``(key_seq, key_fingerprint)``; this returns the PEM the
    operator should use to verify that entry's signature. Returns ``None`` if:

      * ``seq`` is out of range (the entry claims a key the chain never
        introduced);
      * the entry at ``seq`` is a ``revoke`` (a revoked key is not a trusted
        signing key -- nothing should be signed under it after revocation);
      * a non-empty ``fingerprint`` is supplied and does not match the entry's
        PEM fingerprint (defends against a witness entry naming a ``seq`` whose
        key was rotated, then edited to point at a different fingerprint).

    The bootstrap entry (seq 0) carries the anchor key. A ``rotate`` entry
    carries the newly-trusted key. The result is the PEM string (public key),
    suitable for ``load_public_key(...)``.
    """
    if seq < 0 or seq >= len(log.entries):
        return None
    entry = log.entries[seq]
    if entry.action == "revoke":
        return None
    if fingerprint is not None and _pem_fingerprint(entry.pem.encode("utf-8")) != fingerprint:
        return None
    return entry.pem


__all__ = [
    "AuthorityEntry",
    "AuthorityLog",
    "build_bootstrap_log",
    "append_rotate",
    "append_revoke",
    "verify_trust_log",
    "trusted_key_for_seq",
    "sign_entry",
    "_pem_fingerprint",
    "ALGORITHM_LOG",
]

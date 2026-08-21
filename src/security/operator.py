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


# ---------------------------------------------------------------------------
# ADR 19 — signed operator commands (attributed, replay-guarded, command-bound)
#
# A *signed operator command* is the authorization primitive for safety-critical
# verbs (halt / resume / live authorize). It binds the operator's Ed25519 key to a
# SPECIFIC verb + tenant + request body hash + nonce + timestamp, so:
#   - attribution:  the operator pubkey/id are recorded (who issued the command),
#   - replay:       the nonce is checked against a used-nonce set,
#   - binding:      body_hash ties the command to the exact request (no "halt A,
#                   replay as halt B"),
#   - expiry:       timestamp must fall within an acceptance window.
# No new crypto: it reuses the exact Ed25519 verify path the downgrade record uses.
# ---------------------------------------------------------------------------

import hashlib


def body_hash_of(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@dataclass
class OperatorCommand:
    """A signed operator command (ADR 19).

    Signed over (verb, tenant_id, body_hash, nonce, timestamp, operator_id,
    pubkey_pem). ``body_hash`` is the sha256 of the canonical request body, so
    the command cannot be reused against a different request.
    """

    verb: str
    tenant_id: str
    body_hash: str
    nonce: int = 0
    timestamp: int = 0
    operator_id: str = "rathnone-operator"
    pubkey_pem: str = ""          # recorded for key-free ledger verification (Inv 3)
    sig: str = ""                 # hex(Ed25519) over canonical record

    def canonical_bytes(self) -> bytes:
        return _canonical({
            "verb": self.verb,
            "tenant_id": self.tenant_id,
            "body_hash": self.body_hash,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "operator_id": self.operator_id,
            "pubkey_pem": self.pubkey_pem,
        })

    def verify(self, public_key) -> bool:
        if not self.sig:
            return False
        try:
            public_key.verify(bytes.fromhex(self.sig), self.canonical_bytes())
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# ADR 21 — operator key lifecycle (provision / rotate / revoke / expire)
#
# ADR 19/20 treated the operator authority as a bare list[str] of PEMs. That
# leaves no room for: (a) immediate single-key revocation without a redeploy,
# (b) graceful key rotation (add new + retire old on a window), or (c) key
# expiry. The keyring keeps each authorized operator as a first-class,
# metadata-bearing entry and exposes the set of *active* (not revoked, not
# expired) public keys. The signed-command gate verifies against active keys
# only, so revoking a key takes effect on the very next request; expiry is a
# graceful rotation window (a key that lapses falls out of the active set and
# the tenant reverts to the ADR 17 shared-key path — consistent with the
# "dormant when no active allowlist" fail-closed default).
# ---------------------------------------------------------------------------

import time as _time


@dataclass
class OperatorKeyEntry:
    """One authorized operator key (ADR 21).

    ``key_id`` is a stable, collision-resistant handle (sha256 of the PEM),
    so a single key can be revoked by id without sending the full PEM.
    ``expires_at`` is a Unix epoch *second* (None = no expiry). ``revoked``
    is an immediate kill-switch independent of expiry.
    """

    public_key_pem: str
    operator_id: str = ""
    role: str = "operator"
    added_at: int = 0           # epoch seconds
    expires_at: Optional[int] = None   # epoch seconds, None = no expiry
    revoked: bool = False
    key_id: str = field(default="")

    def __post_init__(self):
        if not self.key_id:
            self.key_id = hashlib.sha256(
                self.public_key_pem.encode()).hexdigest()[:16]

    def is_expired(self, now_epoch_s: int) -> bool:
        return self.expires_at is not None and now_epoch_s >= self.expires_at

    def is_active(self, now_epoch_s: int) -> bool:
        return not self.revoked and not self.is_expired(now_epoch_s)

    @classmethod
    def from_pem(cls, pem: str, **kw) -> "OperatorKeyEntry":
        return cls(public_key_pem=pem, **kw)


class OperatorKeyRing:
    """ADR 21 — the set of authorized operator keys for one authority scope.

    Used for both tenant-scoped settlement authority (authorize verb) and the
    service-global safety scope (safety verbs). Provisioned out-of-band (deploy
    tooling), never via the console, which cannot hold signing keys.
    """

    def __init__(self, entries: Optional[list[OperatorKeyEntry]] = None):
        self._entries: list[OperatorKeyEntry] = list(entries or [])

    @classmethod
    def from_pems(cls, pems: list[str], **kw) -> "OperatorKeyRing":
        return cls([OperatorKeyEntry(public_key_pem=p, **kw) for p in pems])

    def add(self, public_key_pem: str, *, operator_id: str = "",
            role: str = "operator", expires_at: Optional[int] = None,
            now_epoch_s: Optional[int] = None) -> OperatorKeyEntry:
        now_epoch_s = now_epoch_s if now_epoch_s is not None else int(_time.time())
        e = OperatorKeyEntry(
            public_key_pem=public_key_pem, operator_id=operator_id,
            role=role, added_at=now_epoch_s, expires_at=expires_at)
        self._entries.append(e)
        return e

    def _find(self, pem: str) -> Optional[OperatorKeyEntry]:
        for e in self._entries:
            if e.public_key_pem == pem:
                return e
        return None

    def revoke(self, key_id_or_pem: str) -> bool:
        """Immediately revoke a key by id or full PEM. Returns True if found.

        Revocation is a kill-switch: the key leaves the active set instantly,
        so any subsequent command signed by it is refused. The entry is kept
        (not deleted) so the audit trail preserves the historical authority.
        """
        target = key_id_or_pem
        if not (target.startswith("-----") or "\n" in target):
            # treated as a key_id
            for e in self._entries:
                if e.key_id == target:
                    e.revoked = True
                    return True
            return False
        e = self._find(target)
        if e is None:
            return False
        e.revoked = True
        return True

    def rotate(self, new_public_key_pem: str, *, old_pem: Optional[str] = None,
               operator_id: str = "", expires_at: Optional[int] = None,
               expire_old_in_s: int = 0, now_epoch_s: Optional[int] = None
               ) -> "OperatorKeyRing":
        """Add a new key and gracefully retire the old one (ADR 21).

        If ``old_pem`` is given and ``expire_old_in_s`` > 0, the old key is
        given a short expiry window (so in-flight commands signed under it keep
        working during the cutover) rather than an immediate revoke. Otherwise
        the old key is revoked immediately.
        """
        now_epoch_s = now_epoch_s if now_epoch_s is not None else int(_time.time())
        self.add(new_public_key_pem, operator_id=operator_id, role="operator",
                 expires_at=expires_at, now_epoch_s=now_epoch_s)
        if old_pem is not None:
            old = self._find(old_pem)
            if old is not None:
                if expire_old_in_s > 0 and old.expires_at is None:
                    old.expires_at = now_epoch_s + expire_old_in_s
                else:
                    old.revoked = True
        return self

    def active_pems(self, now_epoch_s: Optional[int] = None) -> list[str]:
        """Public keys that are currently authorized (not revoked, not expired)."""
        now_epoch_s = now_epoch_s if now_epoch_s is not None else int(_time.time())
        return [e.public_key_pem for e in self._entries if e.is_active(now_epoch_s)]

    def lookup(self, pem: str) -> Optional[OperatorKeyEntry]:
        return self._find(pem)

    def is_authorized(self, pem: str, now_epoch_s: Optional[int] = None) -> bool:
        now_epoch_s = now_epoch_s if now_epoch_s is not None else int(_time.time())
        e = self._find(pem)
        return e.is_active(now_epoch_s) if e else False

    def __iter__(self):
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def as_pems(self) -> list[str]:
        return [e.public_key_pem for e in self._entries]


def verify_command(cmd: "OperatorCommand", *, body: bytes,
                   allowlist_pems: list[str], used_nonces: set[int],
                   now: int, max_age_s: int = 60) -> tuple[bool, Optional[str]]:
    """Fail-closed gate for a signed operator command (ADR 19).

    Returns (ok, reason). Refuses when:
      - the command does not bind to this exact request body (body_hash mismatch),
      - the signature fails against every key on the operator allowlist,
      - the nonce was already used (replay),
      - or the timestamp is outside the acceptance window.
    """
    if not allowlist_pems:
        return False, "no operator allowlist configured (fail-closed)"
    if cmd.body_hash != body_hash_of(body):
        return False, "command body_hash does not match the request body"
    if cmd.nonce in used_nonces:
        return False, f"command nonce {cmd.nonce} already used (replay)"
    # ``now`` and ``cmd.timestamp`` are both nanosecond-resolution (the app clock
    # is monotonic_ns in production, an injectable ns counter in tests), so the
    # acceptance window must be expressed in nanoseconds.
    max_age_ns = max_age_s * 1_000_000_000
    if cmd.timestamp < 0 or abs(now - cmd.timestamp) > max_age_ns:
        return False, f"command timestamp {cmd.timestamp} outside acceptance window"
    for pem in allowlist_pems:
        try:
            pk = load_operator_public_key(pem)
        except Exception:
            continue
        if cmd.verify(pk):
            return True, None
    return False, "command signature does not verify against any operator key"


__all__ = ["OperatorAuthority", "ApprovalRecord", "load_operator_public_key",
           "OperatorCommand", "verify_command", "body_hash_of"]

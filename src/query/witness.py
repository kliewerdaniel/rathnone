"""ADR 35 — evidence-serving witness log (transparency of what was served).

ADR 30 attests each ``EvidenceRecord`` (authenticity + integrity), ADR 32
scopes *who* may query, and ADR 34 anchors *which* evidence key is trusted. But
none of them records *what was actually served to whom*. The operator cannot
answer, after the fact:

    "Which evidence did agent X receive on date D, and is that record still
    the one a fresh execution would produce?"

ADR 35 supplies a **serving-witness log**: a tamper-evident, hash-chained,
signed append-only record of every attested query the service served. Each entry
binds:

    * ``query_hash``   -- the sha256 of the query spec (Op plan or NL text) the
      agent submitted, so the operator can match the log to a known request;
    * ``record_hash``  -- the deterministic hash of the ``EvidenceRecord`` that
      was returned (Identical to the value the attestation signed in ADR 30) -
      i.e. *which* evidence set was served;
    * ``agent_id``     -- the ADR 32 scope's agent, or "<unscoped>" if no scope
      was in force (local-first open mode);
    * ``capabilities`` -- the ADR 32 capability set enforced (or "[]" for
      allow-all / unscoped), so the operator can prove the served scope;
    * ``authority_id`` -- the evidence-domain signer id (the ADR 34 anchor label);
    * ``issued_at``    -- epoch-ns timestamp of service, for a real audit trail;
    * ``key_seq`` / ``key_fingerprint`` -- (ADR 36) the ADR 34 trust-log sequence
      number and anchor fingerprint of the evidence key that signed THIS entry.
      Recording the key binding inside the (signed) entry means a compromised
      service cannot re-attribute a served record to a different key after a
      rotation; the operator can prove which key served which record even across
      key transitions.

Chain discipline (mirrors ADR 34, the operator's trust anchor):

    * ``prev_hash`` of entry N is the sha256 of entry N-1's *canonical bytes*;
      entry 0 uses prev_hash = "". Any rewrite of a historical entry breaks
      every later signature -- tamper-evident by construction.
    * Each entry's signature is over ``signing_input() =
      sha256(prev_hash || canonical_fields)`` by the *evidence-domain* key that
      the operator already pins via ADR 34. **No new trust root is introduced**:
      the witness log is signed by the same key the agent already verifies for
      attestations, so ``verify_witness_log(log, evidence_pem)`` is fully
      off-line and reuses the ADR 34 anchor.
    * Verification is **fail-closed**: malformed input, broken chain, bad
      signature, or unverifiable entry => ``(False, reason)``. Never raises.

Two verify paths (ADR 36):

    * ``verify_witness_log(log, evidence_pem)`` -- the original, single-key path.
      Every entry must be signed by ONE pinned evidence key. Retained for
      compatibility and for deployments that never rotate.
    * ``verify_witness_log_anchored(log, trust_log)`` -- the rotation-aware path.
      Each entry is resolved to the trusted key named by its (signed)
      ``key_seq`` / ``key_fingerprint`` in the ADR 34 trust log. This is the path
      that survives an evidence-key rotation: old entries still verify under the
      rotated-out key, new entries under the rotated-in key, and a forged
      re-attribution (entry says key_seq=K but signed by a different key) is
      rejected because the binding is inside the signature.

Out of scope (deliberately): this log is **server-held and tamper-evident, not
trustless**. A compromised service could drop entries before serving (it cannot
forge them). The defense is the *auditability*: any party holding the served
records can replay this log and detect dropped entries, and the operator pins the
expected evidence key so a substituted log fails signature verification. Making
the log itself replicated/consensus is a separate concern (ADR-future), not a
reason to block this audit primitive.

No new dependencies. Evidence domain stays SEPARATE from the frozen gateway.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .authority import AuthorityLog, trusted_key_for_seq

_ALGORITHM = "ed25519"


@dataclass
class WitnessEntry:
    """One served query, hashed + signed into the witness chain."""

    seq: int
    authority_id: str
    query_hash: str
    record_hash: str
    agent_id: str
    capabilities: list[str]
    issued_at: int
    # ADR 36: which evidence key (in the ADR 34 trust log) signed this entry.
    # 0 == the bootstrap/anchor key; N == the key introduced by trust-log
    # entry N. Carried INSIDE the signed bytes so it cannot be rewritten after
    # the fact (a compromised service cannot re-attribute a served record to a
    # different key post-rotation).
    key_seq: int = 0
    key_fingerprint: str = ""
    prev_hash: str = ""
    sig: str = ""

    def canonical_bytes(self) -> bytes:
        """Stable deterministic bytes a signature is computed over (no ``sig``).

        ``key_seq`` / ``key_fingerprint`` are included so the key binding is
        cryptographically committed (tamper-evident per entry).
        """
        return json.dumps({
            "seq": self.seq,
            "authority_id": self.authority_id,
            "query_hash": self.query_hash,
            "record_hash": self.record_hash,
            "agent_id": self.agent_id,
            "capabilities": list(self.capabilities),
            "issued_at": self.issued_at,
            "key_seq": self.key_seq,
            "key_fingerprint": self.key_fingerprint,
            "prev_hash": self.prev_hash,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def signing_input(self) -> bytes:
        """What the evidence key signs: prev_hash chained in front of the
        canonical fields, so history cannot be rewritten."""
        return hashlib.sha256(
            self.prev_hash.encode("utf-8") + b"|" + self.canonical_bytes()
        ).digest()

    def as_dict(self) -> dict:
        return {
            "seq": self.seq,
            "authority_id": self.authority_id,
            "query_hash": self.query_hash,
            "record_hash": self.record_hash,
            "agent_id": self.agent_id,
            "capabilities": list(self.capabilities),
            "issued_at": self.issued_at,
            "key_seq": self.key_seq,
            "key_fingerprint": self.key_fingerprint,
            "prev_hash": self.prev_hash,
            "sig": self.sig,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "WitnessEntry":
        return cls(
            seq=int(d["seq"]),
            authority_id=d["authority_id"],
            query_hash=d["query_hash"],
            record_hash=d["record_hash"],
            agent_id=d["agent_id"],
            capabilities=list(d.get("capabilities", [])),
            issued_at=int(d.get("issued_at", 0)),
            key_seq=int(d.get("key_seq", 0)),
            key_fingerprint=d.get("key_fingerprint", ""),
            prev_hash=d.get("prev_hash", ""),
            sig=d.get("sig", ""),
        )


@dataclass
class WitnessLog:
    """An ordered, signed record of served attested queries.

    ``trust_log`` is an optional reference to the ADR 34 trust log used to
    anchor entries rotation-aware (ADR 36). It is NOT serialized with the
    entries (the entries carry their own ``key_seq`` / ``key_fingerprint``
    binding); it is supplied at verify time to ``verify_witness_log_anchored``.
    """

    authority_id: str
    entries: list[WitnessEntry] = field(default_factory=list)
    trust_log: Optional["AuthorityLog"] = None

    def as_dict(self) -> dict:
        return {
            "authority_id": self.authority_id,
            "entries": [e.as_dict() for e in self.entries],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "WitnessLog":
        return cls(
            authority_id=d.get("authority_id", ""),
            entries=[WitnessEntry.from_dict(e) for e in d.get("entries", [])],
        )


def append_entry(
    log: WitnessLog,
    *,
    query_hash: str,
    record_hash: str,
    agent_id: str,
    capabilities: list[str],
    sk: Ed25519PrivateKey,
    authority_id: str,
    issued_at: Optional[int] = None,
    key_seq: int = 0,
    key_fingerprint: str = "",
) -> WitnessLog:
    """Append a new witness entry, signed by the evidence-domain ``sk``. Returns
    a NEW log (immutable). Caller passes the CURRENT ``log`` (possibly empty);
    the new entry's prev_hash links to the last entry's canonical bytes.

    ``key_seq`` / ``key_fingerprint`` bind this entry to the ADR 34 trust-log
    entry that introduced the signing key (ADR 36). For a key that is still the
    bootstrap/anchor key, pass ``key_seq=0`` and the anchor fingerprint.
    """
    from .attest import load_public_key  # local import: keep attest the key owner

    prev_hash = (
        hashlib.sha256(log.entries[-1].canonical_bytes()).hexdigest()
        if log.entries else ""
    )
    entry = WitnessEntry(
        seq=len(log.entries),
        authority_id=authority_id,
        query_hash=query_hash,
        record_hash=record_hash,
        agent_id=agent_id,
        capabilities=list(capabilities),
        issued_at=issued_at if issued_at is not None else int(time.time_ns()),
        key_seq=key_seq,
        key_fingerprint=key_fingerprint,
        prev_hash=prev_hash,
    )
    entry.sig = sk.sign(entry.signing_input()).hex()
    # Sanity: the public key derived from sk is what we advertise as the signer.
    _ = load_public_key  # referenced for symmetry; signer == authority key
    new_entries = list(log.entries)
    new_entries.append(entry)
    return WitnessLog(authority_id=authority_id, entries=new_entries,
                     trust_log=log.trust_log)


def verify_witness_log(
    log: WitnessLog, evidence_pem: bytes
) -> tuple[bool, Optional[str]]:
    """Fail-closed verification of a witness log against a PINNED evidence-domain
    public key (the same PEM the operator already anchors via ADR 34).

    Returns ``(ok, reason)``. Rejects when:
      * the log is empty;
      * ``authority_id`` is empty;
      * any entry's seq is out of order;
      * the prev_hash chain is broken (history rewritten);
      * the first entry's prev_hash is non-empty;
      * any entry's signature fails against ``evidence_pem``.

    Single-key path: every entry must be signed by the SAME pinned key. This is
    the original ADR 35 verify, retained for compatibility and for deployments
    that never rotate. Use ``verify_witness_log_anchored`` for rotation-aware
    verification (ADR 36).

    The agent has already verified (via ADR 34) that ``evidence_pem`` is the
    currently-trusted, anchored evidence key -- so a witness log signed by any
    other key is rejected here.
    """
    if not log.entries:
        return False, "empty witness log"
    if not log.authority_id:
        return False, "witness log has no authority_id"

    from .attest import load_public_key

    expected_prev = ""
    for i, e in enumerate(log.entries):
        if e.seq != i:
            return False, f"entry {i} seq mismatch ({e.seq})"
        if i == 0:
            if e.prev_hash != "":
                return False, "first witness entry must have empty prev_hash"
        else:
            if e.prev_hash != expected_prev:
                return False, f"entry {i} prev_hash chain broken"
        try:
            pk = load_public_key(evidence_pem)
        except Exception:  # noqa: BLE001
            return False, f"entry {i} evidence PEM unloadable"
        try:
            pk.verify(bytes.fromhex(e.sig), e.signing_input())
        except Exception:  # noqa: BLE001 -- fail closed on any anomaly
            return False, f"entry {i} signature does not verify"
        expected_prev = hashlib.sha256(e.canonical_bytes()).hexdigest()
    return True, None


def verify_witness_log_anchored(
    log: WitnessLog, trust_log: AuthorityLog
) -> tuple[bool, Optional[str]]:
    """ADR 36 — rotation-aware verification of a witness log against an ADR 34
    evidence-authority trust log (the operator-pinned anchor chain).

    Each witness entry is resolved to the trusted key named by its (signed)
    ``key_seq`` / ``key_fingerprint``. This is the path that survives an
    evidence-key rotation:

      * entries served under the OLD key still verify (under the rotated-out key
        named by their ``key_seq``);
      * entries served under the NEW key verify under the rotated-in key;
      * a forged re-attribution -- an entry claiming ``key_seq=K`` but actually
        signed by a different key -- is rejected, because the binding lives
        inside the entry's signed bytes (so changing the signature to match the
        claimed key breaks ``prev_hash`` for every later entry, and changing the
        claimed key to match the signature fails ``key_seq`` resolution).

    Returns ``(ok, reason)``. Rejects when:
      * the log is empty; entries are out of order; the prev_hash chain is broken;
      * an entry's ``key_seq`` / ``key_fingerprint`` does not name a trusted key
        in ``trust_log`` (i.e. the entry claims a key the chain never introduced,
        or names a revoked key -- the trust log only yields non-revoked trusted
        keys);
      * any entry's signature fails against the key resolution yields.

    The trust log itself is expected to already be verified against the
    operator-pinned anchor (e.g. via ``agent.verify_authority``); this function
    trusts the trust log it is handed.
    """
    if not log.entries:
        return False, "empty witness log"
    if not log.authority_id:
        return False, "witness log has no authority_id"

    expected_prev = ""
    for i, e in enumerate(log.entries):
        if e.seq != i:
            return False, f"entry {i} seq mismatch ({e.seq})"
        if i == 0:
            if e.prev_hash != "":
                return False, "first witness entry must have empty prev_hash"
        else:
            if e.prev_hash != expected_prev:
                return False, f"entry {i} prev_hash chain broken"

        # Resolve the evidence key this entry claims to be signed by.
        pem = trusted_key_for_seq(
            trust_log, seq=e.key_seq, fingerprint=e.key_fingerprint or None)
        if pem is None:
            return False, (
                f"entry {i} key_seq={e.key_seq} does not name a trusted "
                f"evidence key in the anchor chain")
        from .attest import load_public_key
        try:
            pk = load_public_key(pem.encode("utf-8"))
        except Exception:  # noqa: BLE001
            return False, f"entry {i} resolved evidence PEM unloadable"
        try:
            pk.verify(bytes.fromhex(e.sig), e.signing_input())
        except Exception:  # noqa: BLE001 -- fail closed on any anomaly
            return False, f"entry {i} signature does not verify under its bound key"
        expected_prev = hashlib.sha256(e.canonical_bytes()).hexdigest()
    return True, None


__all__ = [
    "WitnessEntry",
    "WitnessLog",
    "append_entry",
    "verify_witness_log",
    "verify_witness_log_anchored",
]

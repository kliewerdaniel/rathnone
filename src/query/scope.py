"""ADR 32 — evidence-domain operation scope.

A signed, body-bound, replay-guarded, time-windowed query permission envelope for
the knowledge engine — the evidence-domain analogue of the gateway's
``OperatorCommand`` (ADR 19/20) and the live settlement cap (ADR 26).

A ``QueryScope`` is minted out-of-band by an operator
(``scripts/evidence_scope_sign.py``) and presented by an agent on every query
(``X-Evidence-Scope`` header). When the evidence-operation authority is
**provisioned** (``RATHNONE_EVIDENCE_OP_KEY_PEM`` set), the service requires a
valid scope and enforces its constraints fail-closed:

  * ``capabilities`` -> allowed ``OpKind`` names (``[]`` = all); enforced on the
    compiled ``Op`` (so an agent scoped to ``MATCH`` cannot smuggle
    ``CONNECTED_TO`` via phrasing),
  * ``max_results`` -> cap on ``included + excluded`` entities (blast-radius
    limiter),
  * ``graph_name``   -> the scope (F2 analogue: a scope for one graph cannot
    satisfy another),
  * ``body_hash``    -> the scope binds to the exact query body (raw NL text for
    ``/query/nl*``, the canonical ``Op`` dict for ``/query/op*``),
  * ``nonce``        -> replay guard,
  * ``not_before`` / ``not_after`` -> TTL window (epoch-nanosecond, like the
    gateway).

Unprovisioned => scope enforcement is **OFF** (local-first, frictionless). The
key is SEPARATE from the ADR 30 attestation key and from the gateway keyring
(F1).

No new dependencies (``cryptography`` is already pinned).
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ALGORITHM = "ed25519"


def body_hash_of(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def op_body_hash(op_dict: dict) -> str:
    """Canonical hash of an Op plan -- bind a scope to the exact query plan."""
    return body_hash_of(op_binding_bytes(op_dict))


def op_binding_bytes(op_dict: dict) -> bytes:
    """Deterministic bytes a scope binds to for an Op query: the canonical JSON
    of the Op plan. The signing tool and the service both derive this from the
    parsed plan, never the raw wire bytes (avoids JSON-encode drift)."""
    return json.dumps(
        op_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")


def nl_binding_bytes(text: str) -> bytes:
    """Deterministic bytes a scope binds to for an NL query: the raw query text.
    (F3: scope binds to the raw NL text, parallel to the gateway's raw-body
    binding; the capability allowlist is still enforced on the compiled Op.)"""
    return text.encode("utf-8")


def now_epoch_ns() -> int:
    """Epoch-nanosecond timestamp, matching the gateway's command clock (F5)."""
    return int(time.time() * 1_000_000_000)


@dataclass
class QueryScope:
    """A signed evidence-operation scope (ADR 32).

    Signed over canonical ``(graph_name, agent_id, capabilities, max_results,
    not_before, not_after, nonce, operator_id, pubkey_pem, body_hash)`` -- the
    same canonicalization discipline as the gateway's ``OperatorCommand``.
    """

    graph_name: str
    agent_id: str
    capabilities: list[str] = field(default_factory=list)
    max_results: Optional[int] = None
    not_before: int = 0
    not_after: int = 0
    nonce: int = 0
    operator_id: str = "evidence-operator"
    pubkey_pem: str = ""
    body_hash: str = ""
    sig: str = ""

    def canonical_bytes(self) -> bytes:
        return json.dumps({
            "graph_name": self.graph_name,
            "agent_id": self.agent_id,
            "capabilities": self.capabilities,
            "max_results": self.max_results,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "nonce": self.nonce,
            "operator_id": self.operator_id,
            "pubkey_pem": self.pubkey_pem,
            "body_hash": self.body_hash,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def verify(self, public_key) -> bool:
        if not self.sig:
            return False
        try:
            public_key.verify(bytes.fromhex(self.sig), self.canonical_bytes())
            return True
        except Exception:  # noqa: BLE001 -- fail closed
            return False

    def as_dict(self) -> dict:
        return {
            "graph_name": self.graph_name,
            "agent_id": self.agent_id,
            "capabilities": list(self.capabilities),
            "max_results": self.max_results,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "nonce": self.nonce,
            "operator_id": self.operator_id,
            "pubkey_pem": self.pubkey_pem,
            "body_hash": self.body_hash,
            "sig": self.sig,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "QueryScope":
        return cls(
            graph_name=d["graph_name"],
            agent_id=d["agent_id"],
            capabilities=list(d.get("capabilities", [])),
            max_results=d.get("max_results"),
            not_before=int(d.get("not_before", 0)),
            not_after=int(d.get("not_after", 0)),
            nonce=int(d.get("nonce", 0)),
            operator_id=d.get("operator_id", "evidence-operator"),
            pubkey_pem=d.get("pubkey_pem", ""),
            body_hash=d.get("body_hash", ""),
            sig=d.get("sig", ""),
        )


class EvidenceOpAuthority:
    """Holds the evidence-operation signing key (SEPARATE evidence-domain key)."""

    def __init__(self, signer_id: str, private_key: Ed25519PrivateKey):
        self.signer_id = signer_id
        self._sk = private_key

    @classmethod
    def from_pem(cls, signer_id: str, pem: bytes) -> "EvidenceOpAuthority":
        from .attest import load_private_key
        if isinstance(pem, str):
            pem = pem.encode("utf-8")
        return cls(signer_id, load_private_key(pem))

    def public_pem(self) -> str:
        return self._sk.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def active_pems(self) -> list[str]:
        """The set of authorized operation public keys (single key today; a
        ring would return multiple)."""
        return [self.public_pem()]

    def sign(self, scope: QueryScope) -> QueryScope:
        scope.pubkey_pem = self.public_pem()
        scope.sig = self._sk.sign(scope.canonical_bytes()).hex()
        return scope


def _disallowed_kinds(op, allowed: set[str]) -> set[str]:
    found: set[str] = set()
    stack = [op]
    while stack:
        node = stack.pop()
        kind = getattr(node, "kind", None)
        if kind is not None:
            name = getattr(kind, "value", None) or str(kind)
            if name not in allowed:
                found.add(name)
        for child in getattr(node, "children", []) or []:
            stack.append(child)
    return found


def enforce_constraints(op, scope: QueryScope, *, included: int = 0,
                        excluded: int = 0) -> tuple[bool, Optional[str]]:
    """Fail-closed enforcement of a scope's capability + size constraints.

    ``op`` is an ``Op`` (or any node with ``.kind`` + ``.children``). Returns
    ``(ok, reason)``.
    """
    if scope.capabilities:
        allowed = set(scope.capabilities)
        bad = _disallowed_kinds(op, allowed)
        if bad:
            return False, (
                f"query uses capabilities outside scope "
                f"{sorted(allowed)}: {sorted(bad)}")
    if scope.max_results is not None:
        total = included + excluded
        if total > scope.max_results:
            return False, (
                f"query result size {total} exceeds scope max_results "
                f"{scope.max_results}")
    return True, None


def verify_scope(scope: QueryScope, *, body: bytes, allowlist_pems: list[str],
                 used_nonces: set[int], now: int,
                 graph_name: str) -> tuple[bool, Optional[str]]:
    """Fail-closed gate for an evidence-operation scope (parallel to
    ``verify_command``). Refuses when:

      * no op authority is provisioned (allowlist empty) -- fail-closed,
      * ``scope.graph_name != graph_name`` (F2 analogue),
      * ``nonce`` already used (replay),
      * ``now`` outside ``[not_before, not_after]`` (TTL),
      * the signature fails against the allowlist.

    NOTE: the **body binding** (``scope.body_hash`` vs the query's canonical
    binding) is checked separately, inside the service handler, because it binds
    to the *parsed* query spec (Op plan or raw NL text) — not the raw wire
    bytes. Keeping it out of this gate avoids JSON-encode drift between client
    and server. This function answers only "is this a validly-signed, fresh,
    in-scope credential for ``graph_name``?"
    """
    if not allowlist_pems:
        return False, "no evidence-operation authority configured (fail-closed)"
    if scope.graph_name != graph_name:
        return False, (f"scope graph_name '{scope.graph_name}' does not match "
                       f"query graph_name '{graph_name}'")
    if scope.nonce in used_nonces:
        return False, f"scope nonce {scope.nonce} already used (replay)"
    if not (scope.not_before <= now <= scope.not_after):
        return False, (f"scope outside TTL window "
                       f"[{scope.not_before}, {scope.not_after}] at {now}")
    for pem in allowlist_pems:
        try:
            pk = serialization.load_pem_public_key(pem.encode("utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if scope.verify(pk):
            return True, None
    return False, "scope signature does not verify against any op key"


__all__ = [
    "QueryScope",
    "EvidenceOpAuthority",
    "enforce_constraints",
    "verify_scope",
    "body_hash_of",
    "op_body_hash",
    "now_epoch_ns",
    "ALGORITHM",
]

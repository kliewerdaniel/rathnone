"""ADR 37 — cross-surface root-of-trust (operator-attested surface ancestry).

ADR 17–24 govern the frozen Sovereign Finance Gateway; ADR 27–36 govern the
separate, evidence-domain knowledge-query engine. The two surfaces deliberately
share NO trust path at the code level: the engine never imports
``fleet.epistemic.decide()`` or any gateway keyring, and the gateway never
imports the engine. That isolation is the point (a compromise of one cannot
authorize the other). But an operator still wants ONE question answered
off-line:

    "Are the keys these two independent surfaces are signing with RIGHT NOW
    both vouched for by the single operator identity I actually trust?"

ADR 37 supplies a **surface-attestation manifest**: a small, signed statement in
which the operator's root Ed25519 key vouches for the *current* public key of
each surface. The operator signs, out-of-band, a manifest that maps:

    surface        ->  current public key PEM (the key the surface signs with)
    (gateway)          (frozen spine operator key / tenant gov key, read-only)
    (knowledge)        (ADR 34 evidence anchor, read-only)

Each surface's key is bound by ``(surface_id, key_kind, pubkey_pem,
issued_at)`` and signed by the operator root. A verifier (holding the operator
root pubkey out-of-band) checks the manifest signature and then checks that a
given surface's *currently served* public key equals the one the manifest
vouches for. The result is a single, auditably-attested ancestry:

    operator root  --signed-->  surface A current key
                       \\--signed-->  surface B current key

without either surface ever learning about the other, and without the engine
importing any gateway code.

Design constraints (consistent with the substrate):
  * **Read-only over surfaces.** This module imports NOTHING from
    ``src.service`` / ``src.security`` / ``fleet.epistemic``. The surface keys
    are fed in as raw public-key PEMs (read from a gateway health endpoint or an
    ADR 34 trust-log anchor — by the CALLER, outside this module). So this is a
    pure verification artifact; it can never mutate gateway authz or the frozen
    spine. The isolation invariant is preserved structurally.
  * **No new trust root in the engine.** The operator root is a THIRD key,
    separate from both the gateway's operator keyring and the evidence anchor.
    It is the operator's "meta" key used only to attest surface ancestry.
  * **Fail-closed.** Malformed manifest, broken chain, bad signature, or a
    served key that doesn't match the vouched key => ``(False, reason)``. Never
    raises.
  * Signatures cover a canonical, stable field set (never the JSON text), so
    re-serialization cannot break verification (Invariant 3 discipline).
  * ``cryptography`` is already pinned; no new deps.

Use:
  * Operator, out-of-band: ``scripts/surface_attest.py sign --root ...
    --surface gateway --kind operator --pubkey-pem <gateway op pub> ...``
    produces a manifest JSON to pin in deployment config.
  * Verifier (audit / CI): load the manifest, verify its signature against the
    pinned operator root, then ``check_surface(manifest, 'gateway', served_pem)``
    and ``check_surface(manifest, 'knowledge', evidence_anchor_pem)``.
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

from .query.attest import ALGORITHM, generate_keypair, load_public_key

_ALGORITHM = ALGORITHM  # ed25519


def _canonical(rec: dict) -> bytes:
    return json.dumps(
        {k: v for k, v in rec.items() if k != "sig"},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def _pem_fingerprint(pem: bytes) -> str:
    text = pem.decode("utf-8") if isinstance(pem, (bytes, bytearray)) else pem
    return hashlib.sha256("".join(text.split()).encode("utf-8")).hexdigest()


@dataclass
class SurfaceKeyBinding:
    """One operator-vouched surface key.

    ``surface_id`` names the surface (e.g. ``gateway`` / ``knowledge``);
    ``key_kind`` names the role of the vouched key within that surface (e.g.
    ``operator`` / ``evidence-anchor``); ``pubkey_pem`` is the CURRENT public
    key the surface is signing with; ``issued_at`` is when the operator vouched.
    """

    surface_id: str
    key_kind: str
    pubkey_pem: str
    issued_at: int = 0

    def canonical_bytes(self) -> bytes:
        return json.dumps({
            "surface_id": self.surface_id,
            "key_kind": self.key_kind,
            "pubkey_pem": self.pubkey_pem,
            "issued_at": self.issued_at,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_dict(cls, d: dict) -> "SurfaceKeyBinding":
        return cls(surface_id=d["surface_id"], key_kind=d["key_kind"],
                   pubkey_pem=d["pubkey_pem"], issued_at=int(d.get("issued_at", 0)))


@dataclass
class SurfaceAttestationManifest:
    """Operator-signed attestation that the named surface keys are authoritative.

    ``bindings`` is the operator-vouched current key for each surface. The whole
    manifest is signed by the operator root over
    ``signing_input() = sha256(canonical(bindings))``.
    """

    operator_id: str
    bindings: list[SurfaceKeyBinding] = field(default_factory=list)
    issued_at: int = 0
    algorithm: str = _ALGORITHM
    sig: str = ""

    def canonical_bytes(self) -> bytes:
        return json.dumps({
            "operator_id": self.operator_id,
            "bindings": [b.canonical_bytes().decode("utf-8") for b in self.bindings],
            "issued_at": self.issued_at,
            "algorithm": self.algorithm,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def signing_input(self) -> bytes:
        return hashlib.sha256(self.canonical_bytes()).digest()

    def as_dict(self) -> dict:
        return {
            "operator_id": self.operator_id,
            "bindings": [b.__dict__ for b in self.bindings],
            "issued_at": self.issued_at,
            "algorithm": self.algorithm,
            "sig": self.sig,
            "manifest_fingerprint": _pem_fingerprint(self.canonical_bytes()),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SurfaceAttestationManifest":
        return cls(
            operator_id=d["operator_id"],
            bindings=[SurfaceKeyBinding.from_dict(b) for b in d.get("bindings", [])],
            issued_at=int(d.get("issued_at", 0)),
            algorithm=d.get("algorithm", _ALGORITHM),
            sig=d.get("sig", ""),
        )

    def binding_for(self, surface_id: str) -> Optional[SurfaceKeyBinding]:
        for b in self.bindings:
            if b.surface_id == surface_id:
                return b
        return None


# --- operator root key (the meta key that attests surface ancestry) --------

def generate_root_keypair() -> tuple[bytes, bytes]:
    """Return (private_pem, public_pem) for a fresh operator root key."""
    return generate_keypair()


def build_manifest(operator_id: str, root_sk: Ed25519PrivateKey,
                   bindings: list[SurfaceKeyBinding],
                   issued_at: Optional[int] = None) -> SurfaceAttestationManifest:
    """Build + sign a surface-attestation manifest with the operator root."""
    m = SurfaceAttestationManifest(
        operator_id=operator_id,
        bindings=list(bindings),
        issued_at=issued_at if issued_at is not None else int(time.time()),
        algorithm=_ALGORITHM,
    )
    m.sig = root_sk.sign(m.signing_input()).hex()
    return m


def verify_manifest(manifest: SurfaceAttestationManifest,
                    root_pub_pem: bytes) -> tuple[bool, Optional[str]]:
    """Fail-closed: is ``manifest`` a valid signature by the operator root
    ``root_pub_pem``? Returns ``(ok, reason)``."""
    if manifest.algorithm != _ALGORITHM:
        return False, "unsupported algorithm"
    if not manifest.sig:
        return False, "manifest has no signature"
    try:
        pk: Ed25519PublicKey = load_public_key(root_pub_pem)
    except Exception:  # noqa: BLE001
        return False, "operator root PEM unloadable"
    try:
        pk.verify(bytes.fromhex(manifest.sig), manifest.signing_input())
    except Exception:  # noqa: BLE001 -- fail closed on any anomaly
        return False, "manifest signature does not verify under operator root"
    return True, None


def check_surface(manifest: SurfaceAttestationManifest, surface_id: str,
                  served_pubkey_pem: bytes) -> tuple[bool, Optional[str]]:
    """Does the served key for ``surface_id`` match the one the operator root
    vouched for in ``manifest``? Returns ``(ok, reason)``.

    The manifest signature is NOT re-checked here; callers verify the manifest
    once via ``verify_manifest`` and then compare any number of surfaces. This
    is the "is this surface's current key the one my operator trusts?" check.
    """
    binding = manifest.binding_for(surface_id)
    if binding is None:
        return False, f"manifest does not vouch for surface '{surface_id}'"
    served_text = served_pubkey_pem.decode("utf-8") if isinstance(
        served_pubkey_pem, (bytes, bytearray)) else served_pubkey_pem
    served_fp = _pem_fingerprint(served_text.encode("utf-8"))
    vouched_fp = _pem_fingerprint(binding.pubkey_pem.encode("utf-8"))
    if served_fp != vouched_fp:
        return False, (
            f"surface '{surface_id}' served key does not match the operator-"
            f"vouched key (fingerprint mismatch)")
    return True, None


__all__ = [
    "SurfaceKeyBinding",
    "SurfaceAttestationManifest",
    "generate_root_keypair",
    "build_manifest",
    "verify_manifest",
    "check_surface",
    "_pem_fingerprint",
]

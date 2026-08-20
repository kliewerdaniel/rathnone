"""Real cryptographic primitives for the live (non-simulated) track.

Implements, with NO heavy external deps:
  - keccak256 (the Ethereum variant) in pure Python
  - secp256k1 ECDSA sign + public-key recovery (the exact scheme Ethereum
    wallets use) so a SettlementAuthRecord's commitment is a REAL on-chain-
    verifiable signature, not a placeholder
  - Ed25519 order-signing helpers (the signing itself uses `cryptography`)

These primitives NEVER decide anything. They only sign what an already-AUTO
(or HUMAN+approved) decision has authorized. Invariant 1 (ModelOutput !=
Authorization) is untouched — signing happens strictly after decide().
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from Crypto.Hash import keccak as _pycryptodome_keccak  # verified Keccak_256

_MASK = (1 << 64) - 1


def _rol(x: int, n: int) -> int:
    n &= 63
    return ((x << n) | (x >> (64 - n))) & _MASK


def keccak256(data: bytes) -> bytes:
    """Ethereum-style keccak256 (256-bit). Uses the verified pycryptodome
    Keccak_256 (matches the Ethereum test vectors exactly)."""
    h = _pycryptodome_keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# ---------------------------------------------------------------------------
# secp256k1 (manual, dependency-free)
# ---------------------------------------------------------------------------

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)
_Inf = None  # point at infinity


def _inv(a: int, m: int) -> int:
    return pow(a, m - 2, m)


def _ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if x1 == x2:
        lam = (3 * x1 * x1) * _inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _inv((x2 - x1) % P, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def _ec_mul(k: int, pt):
    result = None
    addend = pt
    while k:
        if k & 1:
            result = _ec_add(result, addend)
        addend = _ec_add(addend, addend)
        k >>= 1
    return result


def _rfc6979_nonce(x: int, z_bytes: bytes) -> int:
    """Deterministic ECDSA nonce (RFC6979, HMAC-SHA256) — matches real wallets."""
    olen = 32
    x_bytes = x.to_bytes(olen, "big")
    V = b"\x01" * olen
    K = b"\x00" * olen

    def hm(data: bytes) -> bytes:
        return hmac.new(K, data, hashlib.sha256).digest()

    K = hm(V + b"\x00" + x_bytes + z_bytes)
    V = hm(V)
    K = hm(V + b"\x01" + x_bytes + z_bytes)
    V = hm(V)
    while True:
        T = b""
        while len(T) < olen:
            V = hm(V)
            T += V
        k = int.from_bytes(T[:olen], "big")
        if 1 <= k < N:
            return k
        K = hm(V + b"\x00")
        V = hm(V)


def _pubkey_bytes(point) -> bytes:
    x, y = point
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def _address_from_point(point) -> str:
    digest = keccak256(_pubkey_bytes(point)[1:])  # drop 0x04 prefix
    return "0x" + digest[-20:].hex()


class Secp256k1Signer:
    """A real secp256k1 key pair (the tenant's settlement "wallet")."""

    def __init__(self, priv_int: Optional[int] = None):
        if priv_int is None:
            while True:
                cand = secrets.randbelow(N)
                if 1 <= cand < N:
                    priv_int = cand
                    break
        if not (1 <= priv_int < N):
            raise ValueError("invalid secp256k1 private key")
        self.priv_int = priv_int
        self.pub = _ec_mul(priv_int, G)

    @property
    def private_bytes(self) -> bytes:
        return self.priv_int.to_bytes(32, "big")

    @property
    def address(self) -> str:
        return _address_from_point(self.pub)

    def public_key_hex(self) -> str:
        return _pubkey_bytes(self.pub).hex()

    def sign(self, digest: bytes) -> Tuple[int, int, int]:
        """Sign a 32-byte digest. Returns (r, s, rec_id). Low-s normalized
        (EIP-2); rec_id parity tracks the normalization."""
        z = int.from_bytes(digest, "big")
        while True:
            k = _rfc6979_nonce(self.priv_int, digest)
            R = _ec_mul(k, G)
            r = R[0] % N
            if r == 0:
                continue
            s = (pow(k, -1, N) * (z + r * self.priv_int)) % N
            if s == 0:
                continue
            rec_id = R[1] & 1
            if s > N // 2:
                s = N - s
                rec_id ^= 1
            return r, s, rec_id

    def sign_eth(self, digest: bytes) -> bytes:
        """65-byte Ethereum-style signature: r(32) || s(32) || v(27+rec_id)."""
        r, s, rec_id = self.sign(digest)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + rec_id])


def secp256k1_recover(digest: bytes, r: int, s: int, rec_id: int):
    """Recover the public point from a signature (Ethereum ecrecover semantics)."""
    z = int.from_bytes(digest, "big")
    x = r
    if x >= P:
        return None
    beta = (x * x * x + 7) % P
    y = pow(beta, (P + 1) // 4, P)
    if (y & 1) != (rec_id & 1):
        y = (P - y) % P
    R = (x, y)
    rinv = pow(r, -1, N)
    Q = _ec_mul(rinv, _ec_add(_ec_mul(s, R), _ec_mul((-z) % N, G)))
    return Q


def recover_address(digest: bytes, signature: bytes) -> Optional[str]:
    """Recover the signer address from a 65-byte Ethereum-style signature."""
    if len(signature) != 65:
        return None
    r = int.from_bytes(signature[0:32], "big")
    s = int.from_bytes(signature[32:64], "big")
    v = signature[64]
    rec_id = v - 27
    point = secp256k1_recover(digest, r, s, rec_id)
    if point is None:
        return None
    return _address_from_point(point)


# ---------------------------------------------------------------------------
# Ed25519 (via cryptography) — order signing
# ---------------------------------------------------------------------------

def ed25519_sign(private_key, digest: bytes) -> bytes:
    return private_key.sign(digest)


__all__ = [
    "keccak256", "canonical_json",
    "P", "N", "G", "Secp256k1Signer",
    "secp256k1_recover", "recover_address",
    "ed25519_sign",
]

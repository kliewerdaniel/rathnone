"""Real EVM-L2 venue adapter (v2 P2 — drop-in for SimulatedVenue).

This is the long-deferred deployment step: a ``VenueAdapter`` that actually
broadcasts authorized actions to a real Ethereum-compatible L2 over JSON-RPC,
instead of the deterministic ``SimulatedVenue``.

Design constraints (same as the rest of Rathnone):
  - It is a DROP-IN. Same ``VenueAdapter.submit(action)`` / ``query(action_id)``
    surface, so the pipeline code-path is unchanged.
  - It is FAIL-CLOSED. With no ``RATHNONE_L2_RPC_URL`` set, ``get_venue()`` returns
    ``SimulatedVenue`` (identical to today). If the RPC url is set but the venue
    cannot construct (bad chain id, missing settlement key), it RAISES rather than
    silently falling back to a simulator — a simulated MATCH for an action that was
    never broadcast would be the worst possible failure.
  - It NEVER decides. It only broadcasts what the pipeline already authorized and
    signs the raw transaction with the tenant's OWN settlement key (the same key the
    pipeline's SettlementAuthRecord used). The signature it puts on-chain is a real,
    recoverable EIP-155 transaction.
  - No credentials are invented by this code. The RPC url and chain id come from
    environment; the signer is handed in by the caller (the live tenant's
    settlement_key). If you have no RPC endpoint, you do not run this adapter.

RLP + EIP-155 signing are hand-rolled (no eth_account dependency) and reuse the
already-audited ``Secp256k1Signer`` from ``src.live.signing``.
"""

from __future__ import annotations

import httpx

from ..live.signing import Secp256k1Signer, keccak256, recover_address
from .adapter import VenueAdapter, VenueState, VenueReport


# ---------------------------------------------------------------------------
# Minimal RLP (Ethereum's recursive-length-prefix). Mechanical, not crypto.
# ---------------------------------------------------------------------------

def _to_bytes(x) -> bytes:
    if isinstance(x, bytes):
        return x
    if isinstance(x, int):
        if x == 0:
            return b""
        return x.to_bytes((x.bit_length() + 7) // 8, "big")
    raise TypeError(f"RLP: cannot encode {type(x)}")


def _rlp_encode(item):
    if isinstance(item, (list, tuple)):
        out = b"".join(_rlp_encode(i) for i in item)
        return _encode_length(len(out), 0xC0) + out
    b = _to_bytes(item)
    if len(b) == 1 and b[0] < 0x80:
        return b
    return _encode_length(len(b), 0x80) + b


def _encode_length(length: int, offset: int) -> bytes:
    if length < 56:
        return bytes([offset + length])
    bl = _to_bytes(length)
    return bytes([offset + 55 + len(bl)]) + bl


def _rlp_decode(data: bytes, pos: int = 0):
    """(item, new_pos) — item is bytes (scalar) or list of items."""
    if pos >= len(data):
        raise ValueError("RLP: truncated input")
    b0 = data[pos]
    if b0 < 0x80:
        return data[pos:pos + 1], pos + 1
    if b0 < 0xB8:
        length = b0 - 0x80
        return data[pos + 1:pos + 1 + length], pos + 1 + length
    if b0 < 0xC0:
        llen = b0 - 0xB7
        length = int.from_bytes(data[pos + 1:pos + 1 + llen], "big")
        start = pos + 1 + llen
        return data[start:start + length], start + length
    if b0 < 0xF8:
        length = b0 - 0xC0
        return _decode_list(data[pos + 1:pos + 1 + length]), pos + 1 + length
    llen = b0 - 0xF7
    length = int.from_bytes(data[pos + 1:pos + 1 + llen], "big")
    start = pos + 1 + llen
    return _decode_list(data[start:start + length]), start + length


def _decode_list(data: bytes):
    out = []
    pos = 0
    while pos < len(data):
        item, pos = _rlp_decode(data, pos)
        out.append(item)
    return out


def _addr_to_bytes(addr: str) -> bytes:
    a = addr[2:] if addr.lower().startswith("0x") else addr
    return bytes.fromhex(a)


class RealL2Venue(VenueAdapter):
    """Broadcasts authorized actions to a real EVM-L2 via JSON-RPC.

    Args:
        rpc_url:  JSON-RPC endpoint (must be non-empty; fail-closed otherwise).
        signer:   the tenant's ``Secp256k1Signer`` (settlement key). The on-chain
                  tx is signed with this exact key, so it matches the ledger's
                  ``live_sign`` settlement record.
        chain_id: EVM chain id (must be > 0; EIP-155 replay protection).
        gas_price/gas_limit: tx economics; defaults to a standard transfer.
        client:   injectable JSON-RPC transport (for tests / mocks).
    """

    def __init__(self, rpc_url: str, signer: Secp256k1Signer, chain_id: int,
                 *, gas_price: int = 1_000_000_000, gas_limit: int = 21_000,
                 client=None):
        if not rpc_url or not str(rpc_url).strip():
            raise ValueError("RealL2Venue requires a non-empty rpc_url (fail-closed)")
        if not (1 <= int(chain_id) <= 2 ** 32):
            raise ValueError(f"RealL2Venue requires a valid chain_id>0, got {chain_id!r}")
        if not isinstance(signer, Secp256k1Signer):
            raise ValueError("RealL2Venue requires a Secp256k1Signer settlement key")
        self._rpc_url = str(rpc_url).strip()
        self._signer = signer
        self._chain_id = int(chain_id)
        self._gas_price = int(gas_price)
        self._gas_limit = int(gas_limit)
        self._client = client or httpx.Client(base_url=self._rpc_url, timeout=10.0)
        self._tx_by_action: dict[str, str] = {}

    # -- JSON-RPC ---------------------------------------------------------
    def _rpc(self, method: str, params: list):
        resp = self._client.post("/", json={
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("error"):
            raise RuntimeError(f"L2 RPC {method} error: {payload['error']}")
        return payload.get("result")

    # -- tx assembly ------------------------------------------------------
    def _build_raw_tx(self, to_b: bytes, value: int, nonce: int, data: bytes) -> bytes:
        head = [
            _to_bytes(nonce),
            _to_bytes(self._gas_price),
            _to_bytes(self._gas_limit),
            to_b,
            _to_bytes(value),
            data,
            _to_bytes(self._chain_id),
            b"",
            b"",
        ]
        digest = keccak256(_rlp_encode(head))
        r, s, rec_id = self._signer.sign(digest)
        v = rec_id + 35 + self._chain_id * 2
        return _rlp_encode([
            _to_bytes(nonce),
            _to_bytes(self._gas_price),
            _to_bytes(self._gas_limit),
            to_b,
            _to_bytes(value),
            data,
            _to_bytes(v),
            r.to_bytes(32, "big"),
            s.to_bytes(32, "big"),
        ])

    # -- VenueAdapter interface ------------------------------------------
    def submit(self, action) -> VenueReport:
        dest = action.destination
        if not dest:
            # Fail-closed: a real broadcast with no destination is meaningless.
            raise ValueError("RealL2Venue.submit requires action.destination")
        to_b = _addr_to_bytes(dest)
        # chain_settle moves value; trade_execute / treasury are contract calls
        # (value 0, calldata would be ABI-encoded — left as a follow-up hook).
        value = int(action.notional_value) if action.capability == "rathnone.chain_settle" else 0
        nonce = int(action.nonce)
        raw = self._build_raw_tx(to_b, value, nonce, data=b"")
        tx_hash = self._rpc("eth_sendRawTransaction", ["0x" + raw.hex()])
        self._tx_by_action[action.action_id] = tx_hash
        return VenueReport(
            action.action_id, VenueState.SUBMITTED,
            destination=dest, amount=float(value), nonce=nonce,
            tx_hash=tx_hash, note="broadcast to L2")

    def query(self, action_id: str) -> VenueReport:
        tx_hash = self._tx_by_action.get(action_id)
        if not tx_hash:
            return VenueReport(action_id, VenueState.NONE, note="unknown to venue")
        receipt = self._rpc("eth_getTransactionReceipt", [tx_hash])
        if receipt is None:
            # Broadcast but not yet mined.
            return VenueReport(action_id, VenueState.SUBMITTED,
                               tx_hash=tx_hash, note="pending inclusion")
        status = int(receipt.get("status", "0x0"), 16)
        to = receipt.get("to", "")
        value = int(receipt.get("value", "0x0"), 16)
        nonce = int(receipt.get("nonce", "0x0"), 16)
        if status == 1:
            state = VenueState.SETTLED
            note = "on-chain settlement confirmed"
        else:
            state = VenueState.REJECTED
            note = receipt.get("revertReason") or "on-chain revert"
        return VenueReport(action_id, state, destination=to, amount=float(value),
                           nonce=nonce, tx_hash=tx_hash, note=note)


__all__ = ["RealL2Venue", "_rlp_encode", "_rlp_decode", "_to_bytes", "_addr_to_bytes"]

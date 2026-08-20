#!/usr/bin/env python3
"""Local live-broadcast proof against an anvil node (same RealL2Venue path).

This is the LOCAL-CHAIN twin of live_broadcast_probe.py. It points RealL2Venue
at a local `anvil` node (Foundry), which mints test ETH for free, so we can
prove the EXACT production broadcast code path end-to-end without external
funding:

    RealL2Venue.submit() -> eth_sendRawTransaction -> anvil -> receipt
    -> independent EIP-155 signer recovery from the on-chain tx

The on-chain crypto (RLP encode, EIP-155 sign, send, receipt, recover) is
identical to what a public Base Sepolia RPC would see. Difference: the chain
is local, so it proves the CODE PATH, not a public-net broadcast.

Run anvil first:  anvil --chain-id 84532
Then:             .venv/bin/python scripts/live_broadcast_probe_local.py
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx

from src.live.signing import Secp256k1Signer, keccak256, recover_address
from src.venue.l2 import RealL2Venue, _rlp_encode, _to_bytes
from src.finance.action import FinancialAction

RPC_URL = os.environ.get("RATHNONE_L2_LOCAL_RPC", "http://127.0.0.1:8545")
CHAIN_ID = int(os.environ.get("RATHNONE_L2_CHAIN_ID", "84532"))
_KEY_FILE = os.environ.get("RATHNONE_L2_KEY_FILE", ".live_probe_key")


def _rpc(method: str, params: list):
    r = httpx.post(RPC_URL, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=15.0)
    r.raise_for_status()
    payload = r.json()
    if payload.get("error"):
        raise RuntimeError(f"RPC {method} error: {payload['error']}")
    return payload.get("result")


def _load_or_mint_key() -> Secp256k1Signer:
    if os.path.exists(_KEY_FILE):
        with open(_KEY_FILE, "r") as fh:
            priv_hex = fh.read().strip()
        if priv_hex:
            return Secp256k1Signer(int(priv_hex, 16))
    signer = Secp256k1Signer()
    with open(_KEY_FILE, "w") as fh:
        fh.write(signer.private_bytes.hex())
    os.chmod(_KEY_FILE, 0o600)
    return signer


def main() -> None:
    print(f"[env] local rpc={RPC_URL}  chain_id={CHAIN_ID}")
    signer = _load_or_mint_key()
    address = signer.address
    print(f"[key] persisted in {_KEY_FILE} -> {address}")

    # read-only sanity
    net_version = _rpc("net_version", [])
    net_chain = int(net_version, 16) if isinstance(net_version, str) and net_version.startswith("0x") else int(net_version)
    print(f"[read] net_version={net_version} (chain_id={net_chain})")
    assert net_chain == CHAIN_ID, f"chain mismatch: anvil={net_chain} expected={CHAIN_ID}"

    # anvil pre-funds its own genesis accounts; our minted key is NOT one of
    # them, so fund it from the first anvil default account (free, local).
    funder = _rpc("eth_accounts", [])[0]
    fund_tx = _rpc("eth_sendTransaction", [{
        "from": funder, "to": address, "value": hex(10 ** 17),  # 0.1 ETH
    }])
    print(f"[fund] anvil funded {address} (tx {fund_tx})")
    balance = int(_rpc("eth_getBalance", [address, "latest"]), 16)
    print(f"[read] balance={balance} wei ({balance / 1e18:.6f} ETH)")
    assert balance > 0, "funding failed"

    # on-chain nonce + gas price for the real broadcast
    onchain_nonce = int(_rpc("eth_getTransactionCount", [address, "latest"]), 16)
    gp = int(_rpc("eth_gasPrice", []), 16)
    gas_price = max(gp * 2, 1_000_000_000)
    print(f"[live] onchain_nonce={onchain_nonce}  gas_price={gas_price} wei")

    venue = RealL2Venue(rpc_url=RPC_URL, signer=signer, chain_id=CHAIN_ID, gas_price=gas_price)
    action = FinancialAction(
        action_id="live-probe-local", tenant_id="probe", actor="probe",
        capability="rathnone.chain_settle", instrument="ETH", side="settle",
        quantity=1.0, price_limit=1.0, currency="wei", settlement_asset="wei",
        destination=address, nonce=onchain_nonce, timestamp=int(time.time()),
    )
    rep = venue.submit(action)
    print(f"[live] venue_state={rep.state.value}  tx_hash={rep.tx_hash}")
    assert rep.tx_hash, "no tx_hash returned"

    # independent confirmation: receipt + recover signer from on-chain tx
    receipt = _rpc("eth_getTransactionReceipt", [rep.tx_hash])
    assert receipt is not None, "tx not mined"
    status = int(receipt.get("status", "0x0"), 16)
    print(f"[live] receipt status={status} (1=success)")
    tx = _rpc("eth_getTransactionByHash", [rep.tx_hash])
    raw_v = int(tx["v"], 16)
    raw_r = int(tx["r"], 16)
    raw_s = int(tx["s"], 16)
    to_b = bytes.fromhex(tx["to"][2:]) if tx.get("to") else b""
    value = int(tx.get("value", "0x0"), 16)
    nonce = int(tx.get("nonce", "0x0"), 16)
    gprice = int(tx.get("gasPrice", "0x0"), 16)
    glimit = int(tx.get("gas", "0x0"), 16)
    data = bytes.fromhex(tx.get("input", "0x")[2:])
    head = [_to_bytes(nonce), _to_bytes(gprice), _to_bytes(glimit),
            to_b, _to_bytes(value), data, _to_bytes(CHAIN_ID), b"", b""]
    digest = keccak256(_rlp_encode(head))
    rec_id = (raw_v - 35 - CHAIN_ID * 2) % 2
    recovered = recover_address(
        digest, raw_r.to_bytes(32, "big") + raw_s.to_bytes(32, "big") + bytes([27 + rec_id]))
    print(f"[live] recovered signer={recovered}")
    print(f"[live] matches minted key={recovered.lower() == address.lower()}")
    assert recovered.lower() == address.lower(), "signature binding mismatch"

    # also confirm the venue's own query() reconciles SETTLED from the receipt
    q = venue.query(action.action_id)
    print(f"[live] venue.query() -> state={q.state.value}  tx_hash={q.tx_hash}")
    assert q.state.value == "SETTLED"

    print("[local] LIVE BROADCAST PROOF COMPLETE (local anvil chain).")


if __name__ == "__main__":
    main()

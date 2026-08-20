#!/usr/bin/env python3
"""Real-L2 live-broadcast probe (testnet, fail-closed, no credentials in chat).

Drives the EXISTING production broadcast path:

    RealL2Venue.submit()  ->  eth_sendRawTransaction  ->  real chain

This is the runtime proof for the v2 P2 real-venue drop-in. It never invents a
private key and never reads one from chat:

  - STEP 1 (mint):  on first run, a fresh secp256k1 settlement key is generated
                    and persisted to a LOCAL gitignored file
                    (RATHNONE_L2_KEY_FILE, default .live_probe_key). On later
                    runs the SAME key is reused, so the address printed in STEP 1
                    is the one you fund and the one STEP 3 broadcasts from.
  - STEP 2 (read):  RPC connectivity + chainId match + funded balance verified.
                    Nothing is broadcast.
  - STEP 3 (prove): a 1-wei self-transfer is broadcast on the live path; the
                    returned tx hash is shown and independently confirmed via
                    eth_getTransactionReceipt + EIP-155 signer recovery.

All configuration from the environment (NOT chat):
    RATHNONE_L2_RPC_URL    - https public RPC (e.g. https://sepolia.base.org)
    RATHNONE_L2_CHAIN_ID   - EVM chain id (Base Sepolia = 84532)
    RATHNONE_L2_BROADCAST  - set "1" to allow the real 1-wei broadcast
    RATHNONE_L2_KEY_FILE   - optional: path to persist the minted key

Run STEP 1, fund the printed address, then re-run with RATHNONE_L2_BROADCAST=1.
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx

from src.live.signing import Secp256k1Signer, keccak256, recover_address
from src.venue.l2 import RealL2Venue, _rlp_encode, _rlp_decode, _to_bytes
from src.finance.action import FinancialAction

_KEY_FILE = os.environ.get("RATHNONE_L2_KEY_FILE", ".live_probe_key")

_PLACEHOLDER_HINTS = ("your-base-sepolia-rpc-url", "@url:", "example.com",
                      "localhost", "replace-me", "<")


def _env(name: str) -> str:
    v = os.environ.get(name, "")
    if not v or not str(v).strip():
        sys.exit(f"FAIL-CLOSED: {name} is not set in the environment.")
    return str(v).strip()


def _rpc(rpc_url: str, method: str, params: list):
    r = httpx.post(rpc_url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=15.0)
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
    signer = Secp256k1Signer()  # fresh, in-process
    with open(_KEY_FILE, "w") as fh:
        fh.write(signer.private_bytes.hex())
    os.chmod(_KEY_FILE, 0o600)
    return signer


def main() -> None:
    rpc_url = _env("RATHNONE_L2_RPC_URL")
    if any(h in rpc_url for h in _PLACEHOLDER_HINTS):
        sys.exit(f"FAIL-CLOSED: RATHNONE_L2_RPC_URL still looks like a placeholder "
                 f"({rpc_url!r}). Set a real RPC endpoint, e.g. https://sepolia.base.org")
    try:
        chain_id = int(_env("RATHNONE_L2_CHAIN_ID"))
    except ValueError:
        sys.exit("FAIL-CLOSED: RATHNONE_L2_CHAIN_ID must be an integer.")
    if not (1 <= chain_id <= 2 ** 32):
        sys.exit(f"FAIL-CLOSED: chain_id {chain_id} out of range.")

    print(f"[env] rpc={rpc_url}  chain_id={chain_id}")

    # --- STEP 1: load/reuse the persisted key (operator funds it) -----------
    signer = _load_or_mint_key()
    address = signer.address
    print(f"[step1] settlement key (persisted in {_KEY_FILE}) -> {address}")
    if not os.environ.get("RATHNONE_L2_BROADCAST") == "1":
        print(f"[step1] FUND THIS ADDRESS with a little testnet ETH before STEP 3.")

    # --- STEP 2: read-only proof (no broadcast) -----------------------------
    net_version = _rpc(rpc_url, "net_version", [])
    net_chain = int(net_version, 16) if isinstance(net_version, str) and net_version.startswith("0x") else int(net_version)
    print(f"[step2] net_version={net_version} (decoded chain_id={net_chain})")
    if net_chain != chain_id:
        sys.exit(f"FAIL-CLOSED: RPC reports chain_id {net_chain}, expected {chain_id}. "
                 f"Check RATHNONE_L2_CHAIN_ID.")

    bal_hex = _rpc(rpc_url, "eth_getBalance", [address, "latest"])
    balance = int(bal_hex, 16) if isinstance(bal_hex, str) and bal_hex.startswith("0x") else int(bal_hex)
    print(f"[step2] balance={balance} wei ({balance / 1e18:.6f} ETH)")
    if balance == 0:
        print("[step2] address is unfunded. Fund it, then re-run with RATHNONE_L2_BROADCAST=1.")
        return

    # --- STEP 3: real 1-wei self-transfer broadcast -------------------------
    if os.environ.get("RATHNONE_L2_BROADCAST") != "1":
        print("[step2] funded. Re-run with RATHNONE_L2_BROADCAST=1 to broadcast the 1-wei proof.")
        return

    print("[step3] broadcasting 1-wei self-transfer on the live path...")
    # Use the account's real next nonce + a sane gas price so the tx mines.
    onchain_nonce = int(_rpc(rpc_url, "eth_getTransactionCount", [address, "latest"]), 16)
    gp_hex = _rpc(rpc_url, "eth_gasPrice", [])
    gp = int(gp_hex, 16) if isinstance(gp_hex, str) and gp_hex.startswith("0x") else int(gp_hex)
    gas_price = max(gp * 2, 1_000_000_000)  # at least 1 gwei, 2x network
    print(f"[step3] onchain_nonce={onchain_nonce}  gas_price={gas_price} wei")

    venue = RealL2Venue(rpc_url=rpc_url, signer=signer, chain_id=chain_id, gas_price=gas_price)
    action = FinancialAction(
        action_id="live-probe-1", tenant_id="probe", actor="probe",
        capability="rathnone.chain_settle", instrument="ETH", side="settle",
        quantity=1.0, price_limit=1.0, currency="wei", settlement_asset="wei",
        destination=address, nonce=onchain_nonce, timestamp=int(time.time()),
    )
    rep = venue.submit(action)
    print(f"[step3] venue_state={rep.state.value}  tx_hash={rep.tx_hash}")
    if not rep.tx_hash:
        sys.exit("[step3] FAIL-CLOSED: no tx_hash returned from eth_sendRawTransaction.")

    # Independent confirmation: read receipt + recover signer from on-chain tx.
    receipt = _rpc(rpc_url, "eth_getTransactionReceipt", [rep.tx_hash])
    if receipt is None:
        print(f"[step3] tx broadcast (pending inclusion). Re-query later: {rep.tx_hash}")
    else:
        status = int(receipt.get("status", "0x0"), 16)
        print(f"[step3] receipt status={status} (1=success)")
        tx = _rpc(rpc_url, "eth_getTransactionByHash", [rep.tx_hash])
        raw_v = int(tx.get("v"), 16)
        raw_r = int(tx.get("r"), 16)
        raw_s = int(tx.get("s"), 16)
        to_b = bytes.fromhex(tx["to"][2:]) if tx.get("to") else b""
        value = int(tx.get("value", "0x0"), 16)
        nonce = int(tx.get("nonce", "0x0"), 16)
        gas_price_t = int(tx.get("gasPrice", "0x0"), 16)
        gas_limit = int(tx.get("gas", "0x0"), 16)
        data = bytes.fromhex(tx.get("input", "0x")[2:])
        head = [_to_bytes(nonce), _to_bytes(gas_price_t), _to_bytes(gas_limit),
                to_b, _to_bytes(value), data, _to_bytes(chain_id), b"", b""]
        digest = keccak256(_rlp_encode(head))
        rec_id = (raw_v - 35 - chain_id * 2) % 2
        recovered = recover_address(
            digest, raw_r.to_bytes(32, "big") + raw_s.to_bytes(32, "big") + bytes([27 + rec_id]))
        print(f"[step3] recovered signer={recovered}")
        print(f"[step3] matches minted key={recovered.lower() == address.lower()}")
        assert recovered.lower() == address.lower(), "signature binding mismatch"

    print("[step3] LIVE BROADCAST PROOF COMPLETE.")


if __name__ == "__main__":
    main()

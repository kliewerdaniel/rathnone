"""Rathnone finance capability constants.

These are the literal capability strings the *substrate* sees. They mirror the
shape of fleet's own constants (CAP_TRADE_EXECUTE, CAP_INCIDENT_REMEDIATE, ...):
a domain-specific module defines the constant; the registry pairs it with a
human-readable label. The substrate never sees the label — only the string.

Rathnone's flagship surface is the finance trio under one governance authority:
  1. trade execution        (venue order routing / fills)
  2. treasury rebalance     (cross-account / cross-asset rebalances)
  3. on-chain settlement     (fail-closed smart-contract / tx-intent signing)
"""
from __future__ import annotations

CAP_FIN_TRADE_EXECUTE = "rathnone.trade_execute"
CAP_FIN_TREASURY_REBALANCE = "rathnone.treasury_rebalance"
CAP_FIN_CHAIN_SETTLE = "rathnone.chain_settle"

# ADR 40: the local agent harness (Hermes + Codex sub-agents) registers as an
# 8th consumer of the SAME frozen decide() spine, so consequential harness
# actions (apply patch / commit / destructive command) are gated fail-closed.
CAP_FIN_AGENT_HARNESS_EXECUTE = "rathnone.agent_harness_execute"

# Reserved for the chain-agnostic settlement binding (B6). Not yet in the
# registry table; listed here so the contract surface is explicit.
CAP_FIN_CHAIN_SETTLE_EVM_L2 = "rathnone.chain_settle.evm_l2"

__all__ = [
    "CAP_FIN_TRADE_EXECUTE",
    "CAP_FIN_TREASURY_REBALANCE",
    "CAP_FIN_CHAIN_SETTLE",
    "CAP_FIN_AGENT_HARNESS_EXECUTE",
    "CAP_FIN_CHAIN_SETTLE_EVM_L2",
]

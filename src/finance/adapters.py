"""Execution adapters — fail-closed, opt-in, simulated by default.

Each adapter turns an AUTHORIZED RathnoneFinanceProposal into a state-locked,
ledger-bound execution. They NEVER authorize anything themselves: if the gateway
did not return AUTO/HUMAN (with a human approval record), the adapter refuses to
act. Live venues / chains are opt-in and must be explicitly enabled; the default
runtime is fully simulated and requires no network or credentials.

These are the Domain-box executors in the control-plane diagram
(docs/03-ARCHITECTURE.md). They sit AFTER decide(), never before it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from src.finance.proposal import RathnoneFinanceProposal


class ExecutionRefused(Exception):
    """Raised when an adapter is asked to execute an unauthorized action."""


@dataclass
class ExecutionResult:
    authorized: bool
    capability: str
    action_descriptor: str
    simulated: bool
    detail: str = ""


def _guard_authorized(verdict: str, require_human: bool = False,
                      human_approved: bool = False) -> None:
    if verdict == "BLOCKED":
        raise ExecutionRefused("authorization BLOCKED")
    if verdict == "HUMAN" and not human_approved:
        raise ExecutionRefused("HUMAN verdict requires a signed human approval")
    if verdict == "AUTO":
        return
    raise ExecutionRefused(f"unexpected verdict {verdict!r}")


def execute_trade_execute(
    proposal: RathnoneFinanceProposal,
    verdict: str,
    *,
    simulated: bool = True,
    human_approved: bool = False,
    venue: str = "sim://exchange",
) -> ExecutionResult:
    """Authorized order routing / fill. Simulated by default."""
    _guard_authorized(verdict, human_approved=human_approved)
    return ExecutionResult(
        authorized=True, capability=proposal.capability,
        action_descriptor=proposal.action_descriptor, simulated=simulated,
        detail=f"routed via {venue} (simulated={simulated})")


def execute_treasury_rebalance(
    proposal: RathnoneFinanceProposal,
    verdict: str,
    *,
    simulated: bool = True,
    human_approved: bool = False,
    ledger: str = "sim://treasury",
) -> ExecutionResult:
    """Authorized cross-account / cross-asset rebalance."""
    _guard_authorized(verdict, human_approved=human_approved)
    return ExecutionResult(
        authorized=True, capability=proposal.capability,
        action_descriptor=proposal.action_descriptor, simulated=simulated,
        detail=f"rebalanced via {ledger} (simulated={simulated})")


def execute_chain_settle(
    proposal: RathnoneFinanceProposal,
    verdict: str,
    *,
    simulated: bool = True,
    human_approved: bool = False,
    chain: str = "evm_l2",
) -> ExecutionResult:
    """Authorized on-chain settlement (fail-closed tx-intent signing).

    In the simulated runtime this records intent but signs nothing. A real
    signer adapter (B6) would only commit a signature when verdict == AUTO and
    the SettlementAuthRecord's intent_hash matches the executor's calldata.
    """
    _guard_authorized(verdict, human_approved=human_approved)
    return ExecutionResult(
        authorized=True, capability=proposal.capability,
        action_descriptor=proposal.action_descriptor, simulated=simulated,
        detail=f"settlement intent on {chain} (simulated={simulated})")

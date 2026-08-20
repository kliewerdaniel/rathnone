"""Tenant isolation (B8) for the Rathnone product service.

Each tenant owns a DISTINCT Ed25519 governance key. Authorization, the signed
ledger, and the key-free verify are all scoped per tenant. Isolation is enforced
by the SIGNATURE, not a guard flag: a record produced under tenant A's key can
never verify under tenant B's public key. This reuses the exact ledger integrity
contract from ``src/mirror`` (GENESIS head, canonical body, sha256(prev||body)
chain-link) so the console/cloud mirror agrees byte-for-byte with the gateway.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from exchange.epistemic_adapter import GovernanceAuthority

from ..live.signing import Secp256k1Signer
from ..mirror import GENESIS, _entry_body, make_ledger_entry
from ..mirror import load_public_key as _load_public_key
from ..finance.capabilities import (
    CAP_FIN_TRADE_EXECUTE,
    CAP_FIN_TREASURY_REBALANCE,
    CAP_FIN_CHAIN_SETTLE,
)
from ..gateway import GatewayContext  # real decide() wrapper


_TENANT_CAPS = (
    CAP_FIN_TRADE_EXECUTE,
    CAP_FIN_TREASURY_REBALANCE,
    CAP_FIN_CHAIN_SETTLE,
)


@dataclass
class Tenant:
    """One commercial customer. Owns its signing key, ledger, scope, and AUM.

    In the LIVE track a tenant additionally owns:
      - a secp256k1 settlement key (Ethereum address) for on-chain settlement
        intents (gated behind live=True, fail-closed),
      - its Ed25519 governance key (already present) reused for order signing.
    """

    tenant_id: str
    gov: GovernanceAuthority
    agent_role: str = "finance_operator"
    agent_id: str = "rathnone-agent"
    epoch: int = 1
    now: int = 100
    aum: float = 0.0
    settlement_key: Optional[Secp256k1Signer] = None
    settlement_allowlist: set[str] = field(default_factory=set)  # v3 F6: trusted destinations
    operator_allowlist: list[str] = field(default_factory=list)  # ADR 18: operator Ed25519 pubkey PEMs
    _used_downgrade_nonces: set[int] = field(default_factory=set, repr=False)
    _records: list[dict] = field(default_factory=list, repr=False)
    _head: bytes = field(default=GENESIS, repr=False)

    @property
    def public_key_pem(self) -> str:
        return self.gov.public_key_pem

    def context(self) -> GatewayContext:
        """Build a fresh GatewayContext bound to this tenant's authority."""
        return GatewayContext(
            gov=self.gov, agent_role=self.agent_role,
            agent_id=self.agent_id, epoch=self.epoch, now=self.now,
        )

    def authorize(self, proposal, *, require_human_approval=False,
                  denylist=()):
        """Run the frozen decide() for this tenant; AUTO/HUMAN/BLOCKED."""
        return self.context().authorize(
            proposal, allowlist=_TENANT_CAPS,
            require_human_approval=require_human_approval, denylist=denylist,
        )

    @property
    def settlement_address(self) -> Optional[str]:
        """The tenant's on-chain settlement address (Ethereum 0x…), if the
        live track has been enabled for this tenant."""
        return self.settlement_key.address if self.settlement_key else None

    def enable_live(self) -> str:
        """Opt a tenant into the live (real-signing) track. Mints a secp256k1
        settlement key and returns its address. Fail-closed: live signing is
        only possible after this is called AND an action is AUTO-authorized."""
        if self.settlement_key is None:
            self.settlement_key = Secp256k1Signer()
        return self.settlement_key.address

    def live_settle(self, intent: dict, decision_ref: str, verdict: str,
                    *, chain: str = "evm_l2", contract_address: str = "") -> dict:
        """Produce a REAL secp256k1-signed settlement authorization (live track).

        Fail-closed: requires verdict == AUTO and the live track enabled. The
        returned record carries a genuine Ethereum-style signature over the
        intent hash; anyone can verify it with the tenant's address.
        """
        if self.settlement_key is None:
            raise RuntimeError("live track not enabled for tenant")
        from ..live import SettlementAuthRecord
        rec = SettlementAuthRecord.build(
            decision_ref=decision_ref, capability=CAP_FIN_CHAIN_SETTLE,
            intent=intent, verdict=verdict, signer=self.settlement_key,
            chain=chain, contract_address=contract_address)
        return rec.__dict__

    def live_order(self, order: dict, decision_ref: str, verdict: str,
                   *, venue: str = "sim://exchange") -> dict:
        """Produce a REAL Ed25519-signed order authorization (live track).

        Fail-closed: requires verdict == AUTO. The signature binds the tenant's
        governance key to the authorized order.
        """
        from ..live import OrderAuthRecord
        rec = OrderAuthRecord.build(
            decision_ref=decision_ref, capability=CAP_FIN_TRADE_EXECUTE,
            order=order, verdict=verdict, signing_key=self.gov.private_key,
            venue=venue)
        return rec.__dict__

    def append_ledger(self, body: dict) -> dict:
        """Sign + append one ledger entry under this tenant's key.

        Returns the entry (with seq/prev/id/sig) and advances the local head.
        """
        seq = len(self._records) + 1
        rec = make_ledger_entry(seq, self._head, body, self.gov.private_key)
        self._records.append(rec)
        self._head = hashlib.sha256(self._head + _entry_body(rec)).digest()
        return rec

    def audit(self) -> list[dict]:
        return list(self._records)

    def verify_locally(self) -> tuple[bool, Optional[str]]:
        """Independent key-free verify using only this tenant's PUBLIC key.

        Mirrors what the cloud/judge console does — proves the per-AUM audit
        trail is self-consistent without ever holding the signing key.
        """
        pub = _load_public_key(self.public_key_pem)
        prev = GENESIS
        for rec in self._records:
            body = _entry_body(rec)
            try:
                sig = bytes.fromhex(rec["sig"])
                pub.verify(sig, body)
            except Exception:
                return False, f"signature invalid at seq {rec.get('seq')}"
            if rec.get("prev") != prev.hex():
                return False, f"chain break at seq {rec.get('seq')}"
            prev = hashlib.sha256(prev + body).digest()
        return True, None


class TenantRegistry:
    """In-memory registry of tenants keyed by tenant_id.

    (In a real deployment this is backed by a tenant provisioning store; the
    contract — per-tenant key + ledger — is identical. Kept in-memory for the
    testable v1 service.)
    """

    def __init__(self):
        self._tenants: dict[str, Tenant] = {}

    def create(self, *, aum: float = 0.0) -> Tenant:
        tid = uuid.uuid4().hex[:16]
        gov = GovernanceAuthority(Ed25519PrivateKey.generate())
        t = Tenant(tenant_id=tid, gov=gov, aum=aum)
        self._tenants[tid] = t
        return t

    def get(self, tenant_id: str) -> Optional[Tenant]:
        return self._tenants.get(tenant_id)

    def ids(self) -> list[str]:
        return list(self._tenants.keys())


__all__ = ["Tenant", "TenantRegistry", "_TENANT_CAPS"]

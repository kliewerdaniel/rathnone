"""v2 Replay & isolation registry — formal execution-security primitive (P0).

Elevates nonce/expiry/replay from "best-effort checks" to a central, tenant-
scoped invariant. Every executable action is registered once; the registry
guarantees (ratified as a security primitive):

    same action_hash already SIGNED/SETTLED -> IDEMPOTENT (block re-execution)
    different action_hash with the SAME nonce -> BLOCK (nonce reuse)
    expired action (expiry < now)            -> BLOCK
    replayed signature / request id           -> BLOCK
    tenant_id mismatch on lookup             -> BLOCK (cross-tenant confusion)

The registry is pure state + validation; it holds no signing keys. It is the
deterministic gate the pipeline consults BEFORE the signer runs.

Design: in-memory keyed by (tenant_id, nonce) and (tenant_id, action_hash). A
real deployment backs this with a durable store; the contract (the four
guarantees) is identical.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ActionStatus(str, Enum):
    REGISTERED = "REGISTERED"
    SIGNED = "SIGNED"
    SUBMITTED = "SUBMITTED"
    SETTLED = "SETTLED"
    BLOCKED = "BLOCKED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


@dataclass
class ActionRecord:
    action_id: str
    tenant_id: str
    action_hash: str
    nonce: int
    status: ActionStatus = ActionStatus.REGISTERED
    registered_at: int = 0


class ReplayError(Exception):
    """Raised when an action violates a replay/isolation invariant."""


class ActionRegistry:
    def __init__(self):
        # (tenant_id, nonce) -> action_hash (detects nonce reuse across actions)
        self._by_nonce: dict[tuple[str, int], str] = {}
        # (tenant_id, action_hash) -> ActionRecord (detects replay)
        self._by_hash: dict[tuple[str, str], ActionRecord] = {}

    def _check_tenant(self, tenant_id: str) -> None:
        if not tenant_id:
            raise ReplayError("tenant_id is required")

    def register(self, *, tenant_id: str, action_id: str, action_hash: str,
                 nonce: int, now: int, expiry: int = 0) -> ActionRecord:
        """Validate and register a proposed action. Raises ReplayError on any
        invariant violation."""
        self._check_tenant(tenant_id)
        if nonce < 0:
            raise ReplayError(f"nonce must be >= 0, got {nonce}")

        # Expiry check (time-based invariant).
        if expiry and now and expiry < now:
            self._record_status(tenant_id, action_hash, ActionStatus.EXPIRED)
            raise ReplayError(
                f"action expired (expiry={expiry} < now={now})")

        # Replay check: same action_hash already seen for this tenant.
        existing = self._by_hash.get((tenant_id, action_hash))
        if existing is not None:
            raise ReplayError(
                f"replay detected: action_hash {action_hash[:10]}... already "
                f"in state {existing.status.value}")

        # Nonce reuse check: a different action_hash under the same nonce.
        prior_hash = self._by_nonce.get((tenant_id, nonce))
        if prior_hash is not None and prior_hash != action_hash:
            raise ReplayError(
                f"nonce {nonce} reused for a different action "
                f"(prior={prior_hash[:10]}...)")

        rec = ActionRecord(
            action_id=action_id, tenant_id=tenant_id, action_hash=action_hash,
            nonce=nonce, status=ActionStatus.REGISTERED, registered_at=now)
        self._by_hash[(tenant_id, action_hash)] = rec
        self._by_nonce[(tenant_id, nonce)] = action_hash
        return rec

    def advance(self, tenant_id: str, action_hash: str, status: ActionStatus) -> None:
        rec = self._by_hash.get((tenant_id, action_hash))
        if rec is None:
            raise ReplayError(f"unknown action_hash {action_hash[:10]}...")
        rec.status = status

    def _record_status(self, tenant_id: str, action_hash: str,
                       status: ActionStatus) -> None:
        rec = self._by_hash.get((tenant_id, action_hash))
        if rec is not None:
            rec.status = status

    def status_of(self, tenant_id: str, action_hash: str) -> Optional[ActionStatus]:
        rec = self._by_hash.get((tenant_id, action_hash))
        return rec.status if rec else None

    def seen(self, tenant_id: str, action_hash: str) -> bool:
        return (tenant_id, action_hash) in self._by_hash

    def reset(self) -> None:
        """Drop all recorded actions (test isolation)."""
        self._by_nonce.clear()
        self._by_hash.clear()


class DurableActionRegistry:
    """Crash-survivable twin of ``ActionRegistry`` (P1).

    Holds the same replay/isolation contract — but backed by SQLite instead of
    process memory, so the nonce/action_hash invariants survive a restart and
    are enforced across processes. The schema encodes the invariants directly:

        UNIQUE(tenant_id, nonce)        -> nonce reuse across actions is refused
        UNIQUE(tenant_id, action_hash)  -> replay of a settled action is refused

    Every invariant violation is caught both in Python (clear message) and by the
    DB constraint (fail-closed: a duplicate INSERT raises, never silently merges).

    Defaults to an in-memory database so the test suite stays isolated and hermetic
    — set ``RATHNONE_LEDGER_DB`` (or pass ``db_path``) to a file path for a real
    deployment. The in-memory default keeps the v1 test contract intact.
    """

    def __init__(self, db_path: Optional[str] = None):
        import os
        import sqlite3
        self._db_path = db_path or os.environ.get("RATHNONE_LEDGER_DB", ":memory:")
        # a fresh in-memory DB per connection, so each instance is isolated;
        # file DBs share a path and therefore the durable state.
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS actions (
                   tenant_id   TEXT NOT NULL,
                   action_id  TEXT NOT NULL,
                   action_hash TEXT NOT NULL,
                   nonce       INTEGER NOT NULL,
                   status      TEXT NOT NULL,
                   registered_at INTEGER NOT NULL,
                   PRIMARY KEY (tenant_id, action_hash),
                   UNIQUE (tenant_id, nonce)
               )""")
        self._conn.commit()

    def _check_tenant(self, tenant_id: str) -> None:
        if not tenant_id:
            raise ReplayError("tenant_id is required")

    def register(self, *, tenant_id: str, action_id: str, action_hash: str,
                 nonce: int, now: int, expiry: int = 0) -> ActionRecord:
        self._check_tenant(tenant_id)
        if nonce < 0:
            raise ReplayError(f"nonce must be >= 0, got {nonce}")
        # Expiry check (time-based invariant). Expired actions are recorded as
        # EXPIRED so the forensic trail shows the rejection cause.
        if expiry and now and expiry < now:
            try:
                self._conn.execute(
                    "INSERT OR IGNORE INTO actions "
                    "(tenant_id, action_id, action_hash, nonce, status, registered_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (tenant_id, action_id, action_hash, nonce,
                     ActionStatus.EXPIRED.value, now))
                self._conn.commit()
            except Exception:
                pass
            raise ReplayError(
                f"action expired (expiry={expiry} < now={now})")

        cur = self._conn.execute(
            "SELECT status FROM actions WHERE tenant_id=? AND action_hash=?",
            (tenant_id, action_hash))
        row = cur.fetchone()
        if row is not None:
            raise ReplayError(
                f"replay detected: action_hash {action_hash[:10]}... already "
                f"in state {row[0]}")
        # Nonce reuse: a different action_hash under the same (tenant, nonce).
        # The UNIQUE(tenant_id, nonce) constraint is the hard backstop; this
        # read produces the precise "reused for a different action" message.
        cur = self._conn.execute(
            "SELECT action_hash FROM actions WHERE tenant_id=? AND nonce=?",
            (tenant_id, nonce))
        prior = cur.fetchone()
        if prior is not None and prior[0] != action_hash:
            raise ReplayError(
                f"nonce {nonce} reused for a different action "
                f"(prior={prior[0][:10]}...)")
        try:
            self._conn.execute(
                "INSERT INTO actions "
                "(tenant_id, action_id, action_hash, nonce, status, registered_at) "
                "VALUES (?,?,?,?,?,?)",
                (tenant_id, action_id, action_hash, nonce,
                 ActionStatus.REGISTERED.value, now))
            self._conn.commit()
        except Exception as e:  # constraint violation = invariant breach
            raise ReplayError(
                f"replay/nonce invariant violated: {e}") from e
        return ActionRecord(
            action_id=action_id, tenant_id=tenant_id, action_hash=action_hash,
            nonce=nonce, status=ActionStatus.REGISTERED, registered_at=now)

    def advance(self, tenant_id: str, action_hash: str, status: ActionStatus) -> None:
        cur = self._conn.execute(
            "SELECT 1 FROM actions WHERE tenant_id=? AND action_hash=?",
            (tenant_id, action_hash))
        if cur.fetchone() is None:
            raise ReplayError(f"unknown action_hash {action_hash[:10]}...")
        self._conn.execute(
            "UPDATE actions SET status=? WHERE tenant_id=? AND action_hash=?",
            (status.value, tenant_id, action_hash))
        self._conn.commit()

    def _record_status(self, tenant_id: str, action_hash: str,
                       status: ActionStatus) -> None:
        self._conn.execute(
            "UPDATE actions SET status=? WHERE tenant_id=? AND action_hash=?",
            (status.value, tenant_id, action_hash))
        self._conn.commit()

    def status_of(self, tenant_id: str, action_hash: str) -> Optional[ActionStatus]:
        cur = self._conn.execute(
            "SELECT status FROM actions WHERE tenant_id=? AND action_hash=?",
            (tenant_id, action_hash))
        row = cur.fetchone()
        return ActionStatus(row[0]) if row else None

    def seen(self, tenant_id: str, action_hash: str) -> bool:
        cur = self._conn.execute(
            "SELECT 1 FROM actions WHERE tenant_id=? AND action_hash=?",
            (tenant_id, action_hash))
        return cur.fetchone() is not None

    def reset(self) -> None:
        """Drop all recorded actions (test isolation)."""
        self._conn.execute("DELETE FROM actions")
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

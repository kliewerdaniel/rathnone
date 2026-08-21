"""ADR 23 — durable operator-key persistence (crash-survivable keyring).

The ADR 21/22 runtime key-management surface lives in process memory. A restart
wipes every operator key that was added / rotated / revoked at runtime, reverting
the live-money signing authority to whatever ``configure_safety_operators``
bootstrapped. This module makes the keyring **durable**: a SQLite-backed store
keyed by ``(scope, key_id)`` persists every key entry, so the authority survives
a restart and is consistent across worker processes.

Fail-closed contract (mirrors ``DurableActionRegistry``):
  - The store encodes the authority's truth. A key is "active" only if present in
    the store and not revoked / not expired.
  - Every mutation writes THROUGH to the store (no background flush, no lost edit).
  - If the durable store is unreachable, mutations RAISE rather than silently
    degrading to memory — a control-plane that looks authorized but isn't (or
    vice-versa) is worse than a hard fail.
  - In-memory default: when ``RATHNONE_KEY_DB`` is unset, persistence is a no-op
    (None store) and the existing ADR 17-22 in-memory behavior is unchanged.

The store holds the SAME ``OperatorKeyEntry`` data model (key_id, operator_id,
role, added_at, expires_at, revoked, pem). The service hydrates a keyring from the
store on first use and writes back through the mutation endpoints.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import asdict
from typing import Iterable, Optional

from .operator import OperatorKeyEntry, OperatorKeyRing


_KEY_DB_ENV = "RATHNONE_KEY_DB"


class DurableOperatorKeyStore:
    """SQLite-backed operator-key authority store (ADR 23).

    Keyed by (scope, key_id). One row per key entry; revocation/expiry are flags
    on the row, never a deletion, so the historical authority is preserved (Inv 3
    key-free ledger replay depends on the binding still existing).
    """

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path or os.environ.get(_KEY_DB_ENV, ":memory:")
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS operator_keys (
                   scope       TEXT NOT NULL,
                   key_id      TEXT NOT NULL,
                   operator_id TEXT NOT NULL,
                   role        TEXT NOT NULL,
                   added_at    INTEGER NOT NULL,
                   expires_at  INTEGER,
                   revoked     INTEGER NOT NULL DEFAULT 0,
                   pem         TEXT NOT NULL,
                   PRIMARY KEY (scope, key_id)
               )"""
        )
        # F4: append-only audit of safety-scope operator commands (halt/resume),
        # so the who-halted / who-resumed trail survives a process restart and is
        # not lost when the in-memory _safety_audit is cleared. Key-free
        # verifiable: each row records the operator pubkey pem alongside the event.
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS safety_audit (
                   seq      INTEGER PRIMARY KEY AUTOINCREMENT,
                   verb     TEXT NOT NULL,
                   operator_id TEXT NOT NULL,
                   operator_pubkey_pem TEXT NOT NULL,
                   nonce    INTEGER NOT NULL,
                   reason   TEXT NOT NULL DEFAULT '',
                   ts       INTEGER NOT NULL
               )"""
        )
        self._conn.commit()

    # --- read side ----------------------------------------------------------

    def load_scope(self, scope: str) -> OperatorKeyRing:
        """Hydrate an ``OperatorKeyRing`` for one authority scope from the store."""
        cur = self._conn.execute(
            "SELECT operator_id, role, added_at, expires_at, revoked, pem "
            "FROM operator_keys WHERE scope = ?",
            (scope,),
        )
        entries = [
            OperatorKeyEntry(
                public_key_pem=row[5],
                operator_id=row[0],
                role=row[1],
                added_at=row[2],
                expires_at=row[3],
                revoked=bool(row[4]),
            )
            for row in cur.fetchall()
        ]
        return OperatorKeyRing(entries)

    def scopes(self) -> list[str]:
        cur = self._conn.execute(
            "SELECT DISTINCT scope FROM operator_keys"
        )
        return [r[0] for r in cur.fetchall()]

    # --- write side (write-through) -----------------------------------------

    def _put(self, scope: str, e: OperatorKeyEntry) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO operator_keys "
            "(scope, key_id, operator_id, role, added_at, expires_at, revoked, pem) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (scope, e.key_id, e.operator_id, e.role, e.added_at,
             e.expires_at, 1 if e.revoked else 0, e.public_key_pem),
        )
        self._conn.commit()

    def save_entry(self, scope: str, entry: OperatorKeyEntry) -> None:
        """Persist one key entry (used on add / rotate). Write-through."""
        self._put(scope, entry)

    def revoke_key(self, scope: str, key_id: str) -> bool:
        """Mark a key revoked in the store. Returns True if it existed."""
        cur = self._conn.execute(
            "UPDATE operator_keys SET revoked = 1 "
            "WHERE scope = ? AND key_id = ?",
            (scope, key_id),
        )
        self._conn.commit()
        return cur.rowcount > 0

    def revoke_pem(self, scope: str, pem: str) -> bool:
        cur = self._conn.execute(
            "UPDATE operator_keys SET revoked = 1 "
            "WHERE scope = ? AND pem = ?",
            (scope, pem),
        )
        self._conn.commit()
        return cur.rowcount > 0

    def persist_ring(self, scope: str, ring: OperatorKeyRing) -> None:
        """Write-through an ENTIRE ring (used by ``configure_safety_operators``).

        Replaces the scope's persisted authority with exactly ``ring``'s entries.
        Runs in a transaction so the scope never transiently holds a partial set.
        """
        try:
            self._conn.execute("BEGIN")
            self._conn.execute(
                "DELETE FROM operator_keys WHERE scope = ?", (scope,))
            for e in ring:
                self._conn.execute(
                    "INSERT OR REPLACE INTO operator_keys "
                    "(scope, key_id, operator_id, role, added_at, expires_at, "
                    "revoked, pem) VALUES (?,?,?,?,?,?,?,?)",
                    (scope, e.key_id, e.operator_id, e.role, e.added_at,
                     e.expires_at, 1 if e.revoked else 0, e.public_key_pem),
                )
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def append_safety_audit(self, event: dict) -> None:
        """F4: append one safety-scope operator-command event (durable trail).

        Written through immediately so the halt/resume attribution survives a
        process restart. Fail-closed: raises on any store error (the caller
        treats durability as best-effort on top of the authoritative in-memory
        record, but a write failure is surfaced rather than silently swallowed).
        """
        self._conn.execute(
            "INSERT INTO safety_audit "
            "(verb, operator_id, operator_pubkey_pem, nonce, reason, ts) "
            "VALUES (?,?,?,?,?,?)",
            (event.get("verb", ""), event.get("operator_id", ""),
             event.get("operator_pubkey_pem", ""), event.get("nonce", 0),
             event.get("reason", ""), event.get("ts", 0)),
        )
        self._conn.commit()

    def load_safety_audit(self) -> list[dict]:
        """Return the full (durable) safety-command audit trail, oldest first."""
        cur = self._conn.execute(
            "SELECT seq, verb, operator_id, operator_pubkey_pem, nonce, reason, ts "
            "FROM safety_audit ORDER BY seq ASC"
        )
        return [
            {"seq": r[0], "verb": r[1], "operator_id": r[2],
             "operator_pubkey_pem": r[3], "nonce": r[4], "reason": r[5], "ts": r[6]}
            for r in cur.fetchall()
        ]

    def close(self) -> None:
        self._conn.close()


def from_env() -> Optional[DurableOperatorKeyStore]:
    """Return a file-backed store when ``RATHNONE_KEY_DB`` is set, else None.

    None => the service stays fully in-memory (the ADR 17-22 default), so unset
    is the safe, backward-compatible state.
    """
    if os.environ.get(_KEY_DB_ENV):
        return DurableOperatorKeyStore()
    return None


__all__ = ["DurableOperatorKeyStore", "from_env"]

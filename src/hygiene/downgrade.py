"""ADR 18 — signed operator downgrade of a hygiene-BLOCKED action.

This is the safETY VALVE for v3's always-BLOCKED severity (fork F9). A hygiene
BLOCKED means "the claim could not be independently corroborated" — a *knowledge
gap*, not a spine rejection. An operator who actually reviewed the action can
release it via a SIGNED downgrade, reusing the existing v2 Ed25519 operator
machinery (no new crypto, no new keys).

Hard constraints (ADR 18, ratified "proceed with all"):
  - Invariant 1 preserved: corroboration NEVER reaches decide(); the downgrade is
    a pipeline-only human override, post-spine.
  - Narrowing preserved: ONLY a hygiene-BLOCKED (AUTO/HUMAN -> BLOCKED) may be
    downgraded. A spine-BLOCKED can NEVER be downgraded (that would contradict
    decide()). The only widener is an external signed human — already part of the
    protocol via the HUMAN authority.
  - Invariant 3 preserved: the DowngradeRecord is replayable key-free from the
    ledger (operator pubkey pems are recorded; verify uses only public material).
  - Fail-closed: unconfigured key / bad sig / replayed nonce / wrong violation set
    => refuse.
  - 2-of-2 for DESTINATION_OWNERSHIP: that override (F6, the strongest anti-theft
    check) requires a SECOND operator signature, because releasing a fund movement
    to an off-allowlist address is the highest-consequence override.

The record signs over the exact action_hash + the violation ids it releases, so
"downgrade a benign claim, execute a poisoned one" is structurally impossible.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..finance.action import FinancialAction
from ..security.operator import load_operator_public_key


# Violation codes whose override requires a SECOND operator (2-of-2).
_SECOND_OP_CODES = {"destination_off_allowlist", "destination_untrusted"}


def _canonical(rec: dict) -> bytes:
    return json.dumps(
        {k: v for k, v in rec.items() if k != "sig"},
        sort_keys=True, separators=(",", ":"),
    ).encode()


@dataclass
class DowngradeRecord:
    """A signed operator release of a hygiene-BLOCKED action.

    Signed over (action_hash, violation_ids, reason, timestamp, nonce). A SECOND
    operator signature (``second_sig``) is required iff any released violation is
    in ``_SECOND_OP_CODES`` (DESTINATION_OWNERSHIP family).
    """

    action_hash: str
    violation_ids: list[str]
    operator_id: str
    reason: str
    timestamp: int = 0
    nonce: int = 0
    sig: str = ""              # hex(Ed25519) over canonical record, primary operator
    second_operator_id: str = ""
    second_sig: str = ""       # hex(Ed25519), required for 2-of-2 codes
    pubkey_pem: str = ""       # recorded for key-free ledger verification (Inv 3)
    second_pubkey_pem: str = ""

    def canonical_bytes(self) -> bytes:
        return _canonical({
            "released_hash": self.action_hash,
            "violation_ids": self.violation_ids,
            "operator_id": self.operator_id,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "second_operator_id": self.second_operator_id,
        })

    @property
    def requires_second(self) -> bool:
        return any(c in _SECOND_OP_CODES for c in self.violation_ids)

    def verify(self, *, primary_pem: Optional[str] = None,
               second_pem: Optional[str] = None) -> bool:
        """Verify signatures against the supplied/recorded operator pubkeys.

        When only ``primary_pem`` is given (or falls back to the recorded
        ``pubkey_pem``) only the PRIMARY signature is checked. A 2-of-2 record
        is therefore verifiable at the primary step even though ``second_sig`` is
        still empty; the second signature is only checked when a ``second_pem`` is
        explicitly supplied (so the precise refusal reason — bad primary vs.
        missing 2nd operator — can be surfaced by the caller).

        Fail-closed: a missing signature or mismatched key => False.
        """
        if not self.sig:
            return False
        pk_pem = primary_pem or self.pubkey_pem
        if not pk_pem:
            return False
        try:
            pk = load_operator_public_key(pk_pem)
            assert isinstance(pk, Ed25519PublicKey)
            pk.verify(bytes.fromhex(self.sig), self.canonical_bytes())
        except Exception:
            return False
        # Only validate the second signature when a second key is actually
        # supplied; otherwise leave the 2-of-2 decision to the caller.
        if second_pem is not None:
            if not self.second_sig:
                return False
            try:
                spk = load_operator_public_key(second_pem)
                assert isinstance(spk, Ed25519PublicKey)
                spk.verify(bytes.fromhex(self.second_sig), self.canonical_bytes())
            except Exception:
                return False
        return True


def validate_downgrade(downgrade, *, action: FinancialAction,
                        hygiene_violations: list[dict],
                        operator_allowlist: list[str],
                        used_nonces: set[int]) -> tuple[bool, Optional[str]]:
    """Fail-closed gate for a proposed downgrade (used by the pipeline).

    Returns (ok, reason). Refuses when:
      - the downgrade does not bind to this action's exact hash,
      - it tries to release a violation the action was NOT blocked on,
      - the signature(s) fail against the tenant operator-allowlist,
      - the nonce was already used (replay),
      - or a 2-of-2 violation lacks a valid second operator.
    """
    if downgrade.action_hash != action.action_hash:
        return False, "downgrade does not bind to this action's hash"
    # Every released violation id must be among the actual hygiene violations.
    actual = {v.get("code") for v in hygiene_violations}
    released = set(downgrade.violation_ids)
    if not released.issubset(actual):
        return False, "downgrade releases violations the action was not blocked on"
    # The action must actually have been hygiene-BLOCKED on these codes.
    if not actual:
        return False, "action was not hygiene-blocked; nothing to downgrade"
    # Replay guard (pipeline tracks used nonces; see pipeline.py).
    if downgrade.nonce in used_nonces:
        return False, f"downgrade nonce {downgrade.nonce} already used (replay)"
    # Signature verification against the tenant operator-allowlist. The allowlist
    # holds PEM public keys; we try each (fail-closed: none match => refuse).
    #
    # For a 2-of-2 (DESTINATION_OWNERSHIP) override we check the PRIMARY and
    # SECOND signatures against two *distinct* allowlist keys separately, so the
    # precise refusal reason is surfaced (bad primary vs. missing 2nd operator).
    if not operator_allowlist:
        return False, "tenant has no operator allowlist (fail-closed)"
    for pem in operator_allowlist:
        if not downgrade.verify(primary_pem=pem):
            continue  # try the next allowlist key for the primary signature
        # Primary signature verified against `pem`.
        if downgrade.requires_second:
            # The second operator must be a *different* allowlisted key.
            for spem in operator_allowlist:
                if spem == pem:
                    continue
                if downgrade.verify(primary_pem=pem, second_pem=spem):
                    return True, None
            return False, "2-of-2 override lacks a valid second operator"
        return True, None
    return False, "downgrade signature does not verify against any operator key"


__all__ = ["DowngradeRecord", "validate_downgrade", "_SECOND_OP_CODES"]

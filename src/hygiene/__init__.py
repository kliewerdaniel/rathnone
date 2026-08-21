"""v3 Epistemic Hygiene layer (knowledge-poisoning defense).

This is the "is the action's *knowledge* true?" counterpart to v2's
"is this action within our authority?". It treats selected economic fields of a
FinancialAction (instrument, price_limit, destination, quantity, evidence) as
UNTRUSTED CLAIMS about the world that must be independently corroborated before
the system will consider them.

HARD CONSTRAINTS (see docs/16-V3-EPISTEMIC-HYGIENE.md):
  - Invariant 1 preserved: corroboration results NEVER reach fleet.epistemic.decide().
    This layer runs strictly AFTER the spine, narrowing-only, exactly like RiskEngine.
  - Narrowing-only: AUTO -> BLOCKED allowed; BLOCKED -> AUTO / HUMAN -> AUTO forbidden.
  - Fail-closed: an uncorroborated claim is BLOCKED, never assumed-true by default.
  - Invariant 3 preserved: verdict is replayable key-free from the EvidenceGraph +
    signed ledger (provenance events emitted by the pipeline).
  - Opt-in: disabled by default (mirrors the live track). Disabled == pure pass-through,
    so the v1/v2 suites are unaffected.

The layer is stateless w.r.t. corroboration SOURCES at construction; the pipeline
injects the tenant's settlement allowlist + the configured instrument master / feeds at
evaluate() time. This keeps it deterministic and trivially testable without network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..finance.action import FinancialAction
from .downgrade import DowngradeRecord, validate_downgrade

@dataclass
class HygieneViolation:
    code: str
    message: str
    detail: Optional[dict] = None


@dataclass
class HygieneVerdict:
    """Narrowing-only verdict. ok=False => AUTO -> BLOCKED (poisoned claim)."""
    ok: bool
    verdict: str
    input_verdict: str
    violations: list[HygieneViolation] = field(default_factory=list)
    checks_run: int = 0
    provenance: list[dict] = field(default_factory=list)

    @property
    def reasons(self) -> list[str]:
        return [f"{v.code}: {v.message}" for v in self.violations]


class CorroborationLayer:
    """Deterministic, narrowing-only, fail-closed knowledge-poisoning gate.

    Disabled by default. When enabled it demands independent corroboration for the
    action's economic claims; any unverifiable claim => BLOCKED.

    ADR 24: price corroboration is supplied as a set of NAMED, independently-originated
    sources (``price_sources: dict[source_id, float]``) rather than an anonymous list of
    quotes. Quorum is satisfied only by *distinct sources* — two quotes from the same
    feed (or two entries that share a source id) count ONCE. This closes fork F7's
    weakest point: previously a single feed reporting twice satisfied quorum=2. Sources
    are still locally-configured values (no network egress by default), so the
    "no egress by default" principle holds; ADR 24 only makes the *independence* of the
    quoted evidence real rather than assumed.
    """

    def __init__(self, *,
                 enabled: bool = False,
                 instrument_master: Optional[set[str]] = None,
                 feeds: Optional[dict[str, list[float]]] = None,
                 price_sources: Optional[dict[str, dict[str, float]]] = None,
                 price_band_bps: int = 50,
                 quorum: int = 2):
        self.enabled = enabled
        self.instrument_master = instrument_master or set()
        self._feeds = feeds or {}
        # ADR 24: price_sources[source_id][instrument] = quote (named, distinct origins)
        self._price_sources = price_sources or {}
        self.price_band_bps = price_band_bps
        self.quorum = quorum

    # --- ADR 18: signed operator downgrade of a hygiene-BLOCKED action -------
    def sign_downgrade(self, action: FinancialAction, *, operator_key: Ed25519PrivateKey,
                       violation_ids: list[str], reason: str,
                       second_key: Optional[Ed25519PrivateKey] = None, nonce: int = 0,
                       timestamp: int = 0, operator_id: str = "rathnone-operator",
                       second_operator_id: str = "") -> DowngradeRecord:
        """Produce a SIGNED DowngradeRecord (the ADR 18 safety valve).

        ``operator_key`` is the primary operator's Ed25519 private key; for a
        2-of-2 violation (DESTINATION_OWNERSHIP family) ``second_key`` must also
        be supplied. Fail-closed: missing/mismatched key => ValueError.
        """
        rec = DowngradeRecord(
            action_hash=action.action_hash, violation_ids=list(violation_ids),
            operator_id=operator_id, reason=reason, timestamp=timestamp,
            nonce=nonce, pubkey_pem=operator_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode(),
        )
        if rec.requires_second:
            if second_key is None:
                raise ValueError(
                    f"violations {rec.violation_ids} require a 2nd operator signature")
            # Set the 2nd-operator identity BEFORE signing, so the canonical
            # bytes the primary signature covers match what verify() replays.
            rec.second_operator_id = second_operator_id or "rathnone-operator-2"
            rec.second_pubkey_pem = second_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
        rec.sig = operator_key.sign(rec.canonical_bytes()).hex()
        if rec.requires_second:
            rec.second_sig = second_key.sign(rec.canonical_bytes()).hex()
        return rec

    def _median(self, xs: list[float]) -> float:
        s = sorted(xs)
        n = len(s)
        if n == 0:
            return 0.0
        mid = n // 2
        return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2.0

    def evaluate(self, action: FinancialAction, *,
                 allowlist: Optional[set[str]] = None,
                 input_verdict: str = "AUTO") -> HygieneVerdict:
        allowlist = allowlist or set()
        violations: list[HygieneViolation] = []
        provenance: list[dict] = []
        checks = 0

        # Disabled => pure pass-through (narrowing holds trivially). The v1/v2
        # suites never enable this layer, so they are completely unaffected.
        if not self.enabled:
            return HygieneVerdict(ok=True, verdict=input_verdict,
                                  input_verdict=input_verdict, checks_run=0)

        # Narrowing-only: a frozen BLOCKED stays BLOCKED (never widened).
        if input_verdict == "BLOCKED":
            return HygieneVerdict(ok=False, verdict="BLOCKED",
                                  input_verdict="BLOCKED", violations=violations,
                                  checks_run=checks, provenance=provenance)

        # --- 1. INSTRUMENT_EXISTS ----------------------------------------------
        checks += 1
        if self.instrument_master and action.instrument not in self.instrument_master:
            violations.append(HygieneViolation(
                "instrument_unknown",
                f"instrument '{action.instrument}' not in reference master",
                {"instrument": action.instrument}))

        # --- 2. PRICE_QUOTE (>= quorum DISTINCT sources, within band) --------
        checks += 1
        # ADR 24: gather quotes keyed by their ORIGIN. A source is identified by
        # its source id; two quotes that share an id (or a legacy anonymous feed's
        # repeated values) count as ONE. Quorum is over distinct origins only.
        # Back-compat: a legacy ``feeds`` entry provides a single anonymous source
        # ("feed") for the instrument — it can satisfy quorum only if quorum==1.
        quotes_by_source: dict[str, float] = {}
        if action.instrument in self._feeds:
            quotes = self._feeds[action.instrument]
            # An anonymous feed list is treated as one source carrying the median
            # of its entries (it cannot supply more than one distinct origin).
            if quotes:
                quotes_by_source["feed"] = self._median(quotes)
        for src_id, per_src in self._price_sources.items():
            if action.instrument in per_src:
                quotes_by_source[src_id] = per_src[action.instrument]
        n_distinct = len(quotes_by_source)
        if quotes_by_source:
            if n_distinct < self.quorum:
                violations.append(HygieneViolation(
                    "price_unverifiable",
                    f"only {n_distinct} distinct price source(s); require quorum "
                    f"{self.quorum}",
                    {"instrument": action.instrument,
                     "n_sources": n_distinct,
                     "sources": sorted(quotes_by_source.keys())}))
            else:
                mid = self._median(list(quotes_by_source.values()))
                band = mid * self.price_band_bps / 10_000.0
                lo, hi = mid - band, mid + band
                provenance.append({"claim": "PRICE_QUOTE",
                                   "instrument": action.instrument,
                                   "asserted": action.price_limit,
                                   "corroborated_mid": mid, "band": band,
                                   "n_sources": n_distinct,
                                   "sources": sorted(quotes_by_source.keys())})
                if not (lo <= float(action.price_limit) <= hi):
                    violations.append(HygieneViolation(
                        "price_out_of_band",
                        f"price_limit {action.price_limit} outside corroborated "
                        f"[{lo}, {hi}] (mid {mid}, band {self.price_band_bps}bps)",
                        {"asserted": action.price_limit, "lo": lo, "hi": hi}))
        else:
            # No source configured for this instrument => fail-closed.
            violations.append(HygieneViolation(
                "price_unverifiable",
                f"no independent price source for instrument '{action.instrument}'",
                {"instrument": action.instrument}))

        # --- 3. DESTINATION_OWNERSHIP (pre-registered allowlist) --------------
        checks += 1
        if action.destination:
            if not allowlist:
                # Fail-closed: hygiene enabled but tenant has no allowlist => trust
                # NOT assumed. Block anything that names a destination.
                violations.append(HygieneViolation(
                    "destination_untrusted",
                    "hygiene enabled but tenant settlement allowlist is empty",
                    {"destination": action.destination}))
            elif action.destination not in allowlist:
                violations.append(HygieneViolation(
                    "destination_off_allowlist",
                    f"destination {action.destination} not on tenant allowlist",
                    {"destination": action.destination}))

        # --- 4. QUANTITY_INTENT_MATCH -----------------------------------------
        checks += 1
        intended = (action.evidence or {}).get("intended_quantity")
        if intended is not None and abs(float(action.quantity) - float(intended)) > 1e-9:
            violations.append(HygieneViolation(
                "quantity_intent_mismatch",
                f"quantity {action.quantity} != intended_quantity {intended}",
                {"quantity": action.quantity, "intended": intended}))

        # --- 5. EVIDENCE_GROUNDED ---------------------------------------------
        checks += 1
        if action.risk_class == "high" and not action.evidence:
            violations.append(HygieneViolation(
                "evidence_ungrounded",
                "high-risk action carries no grounding evidence",
                {"risk_class": action.risk_class}))

        if violations:
            return HygieneVerdict(ok=False, verdict="BLOCKED",
                                  input_verdict=input_verdict, violations=violations,
                                  checks_run=checks, provenance=provenance)
        return HygieneVerdict(ok=True, verdict=input_verdict,
                              input_verdict=input_verdict, violations=violations,
                              checks_run=checks, provenance=provenance)


__all__ = ["CorroborationLayer", "HygieneVerdict", "HygieneViolation",
           "DowngradeRecord", "validate_downgrade"]

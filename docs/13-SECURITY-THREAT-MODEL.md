# 13 — Security Threat Model & Defenses (red-team inversions, defended)

**Status:** Implemented + verified. This document records the four harmful
trajectories the system could be twisted into, and the concrete defense that
makes each one structurally impossible. It is a defensive record — none of the
escalation directions are implemented, and the design explicitly refuses them.

## Posture
Rathnone's core strengths — autonomy, immutability, deterministic authority —
are *trustworthy only when bounded*. Each strength has a failure mode where the
same property becomes a weapon. The guards below invert the inversion.

## The four inversions and their antidotes

### V1 — Predatory extraction (strength: autonomous speed → HFT predation)
- **Threat:** Wire a predictive/exploitation model into `decide()` so the loop
  optimizes for value extraction (front-running, liquidity drains).
- **Defense (implemented):**
  1. `decide()` is **frozen and unchanged** in `sovereign-agent-fleet`; advisory
     evidence never reaches it (`src/finance/proposal.py` drops it; the new
     `sanitize_advisory_evidence` strips neutral decision fields in case a future
     edit accidentally forwards them).
  2. `VelocityGuard` caps live-signing throughput (`src/security/guards.py`),
     so the live track cannot become a high-frequency signing engine. Configurable,
     fail-closed (exceeding the limit → 429).
  3. `validate_order` enforces buy/sell/positive-qty structure.

### V2 — Financial panopticon (strength: immutable ledger → total surveillance)
- **Threat:** Bind the ledger to real-world identity (biometric / social credit)
  and use the immutable record as a tool to exclude participants.
- **Defense (implemented):** `assert_no_pii` rejects any ledger body carrying
  identity-binding keys (`biometric`, `ssn`, `email`, `kyc`, `social_credit`,
  `real_world_id`, …). The ledger is structurally pseudonymous — the panopticon
  escalation cannot be added without defeating this guard. Service layer enforces
  it on `execute_live` payloads (403).

### V3 — Algorithmic oligarchy (strength: sovereign autonomy → capital gatekeeping)
- **Threat:** Gate the gateway by AUM or identity so only an elite qualifies.
- **Defense (verified):** `fleet.epistemic.decide()` takes **no AUM/identity
  parameter** (signature: `identity, grant, authorization_scope, request,
  constraints, current_epoch, now, trusted_issuer_pubkey_pem`). A regression test
  (`test_verdict_independent_of_aum`) proves a $0 and a $9T tenant get identical
  verdicts for identical proposals. Gatekeeping by capital is impossible at the spine.

### V4 — Immutable cage (strength: frozen spine → catastrophic rigidity)
- **Threat:** Hard-code axioms so the system cannot adapt during a black-swan
  event; it keeps signing "authorized" ruinous trades.
- **Defense (implemented):**
  1. `CircuitBreaker` — an independent operator halt that stops live signing
     **without** the frozen spine's agreement (`/safety/halt`, `/safety/resume`,
     `/safety` state). Fail-open-by-design-to-halt: if its state can't be read,
     it is treated as OPEN (halted).
  2. `validate_settlement_intent` — structural sanity on what gets signed:
     valid `0x` address, non-negative integer value (≤128 bits), non-negative
     nonce, and an optional deployment-set `_MAX_VALUE_WEI` ceiling. Even an AUTO
     verdict cannot sign a structurally impossible / over-ceiling transfer.
  3. `Clock` is injectable so staleness/velocity are testable; the live runtime
     uses a real monotonic clock.

## Deployment configuration (fail-closed env knobs)
Both V1/V4 bounds are environment-configurable via `src/config.py`:

- `RATHNONE_MAX_SETTLEMENT_VALUE_WEI` — refuse to sign any settlement transfer
  above this many wei (integer ≥ 0). Unset = no ceiling (operator must set in
  production). `"0"` bans all settlements. Malformed value → raises at import
  time (never silently unbounded).
- `RATHNONE_LIVE_RATE_MAX` — max live signatures per sliding window (default
  `10**12`, effectively unlimited for dev). Set strict in production to enforce
  the velocity guard. Malformed → raises at import.

Example hardened launch:
`RATHNONE_MAX_SETTLEMENT_VALUE_WEI=1000000000000000000000 RATHNONE_LIVE_RATE_MAX=100 uvicorn src.service.app:app`

## What is deliberately NOT implemented
- No predictive/exploitation model in `decide()`.
- No identity binding; the ledger stays pseudonymous.
- No AUM/identity gating; the spine has no such input.
- No hard-coded economic axioms; the operator retains the halt switch.

## Test evidence (`tests/test_security.py`)
- PII rejected; advisory evidence sanitized of authority fields.
- Circuit breaker halts live signing (503) and resumes.
- Settlement intent rejects bad address / negative / >128-bit / over-ceiling /
  bad nonce; order validation rejects bad side / quantity.
- Velocity guard blocks bursts.
- Service refuses a PII-bearing live payload (403).
- Verdict identical across $0 vs $9T AUM.

## Out of scope (named, not hidden)
- **Dynamic economic circuit breakers** (e.g. drawdown halt) are policy, not
  code — they belong in the `CircuitBreaker` operator runbook.
- **Staleness** detection (epoch/now skew) is wired via `Clock`; a deployment
  should bind it to wall-clock + consensus time.

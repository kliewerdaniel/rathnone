# ADR 36 — Rotation-Aware Witness Log (per-entry key binding + anchored verify)

- **Status:** RATIFIED + IMPLEMENTED (2026-08-21) — full suite green
- **Extends:** ADR 35 (witness log) + ADR 34 (evidence-authority trust log)
- **Depends on:** `src/query/{witness,authority}.py`, `src/query/agent.py`, `src/query/service.py`
- **Companion:** ADR 37 (cross-surface root-of-trust) — same epoch, same rotation discipline.

## Context

ADR 35 added the witness log: "what record hash was served to which agent under
which scope," signed by the evidence key (ADR 30/34). ADR 34 then added the
evidence-authority trust log, supporting **live evidence-key rotation/revocation
without redeploy**.

Those two advances were not yet reconciled. The ADR 35 witness log signed every
entry with whatever evidence key was live, but verification (`verify_witness_log`)
accepted only **one pinned key**. The moment the operator rotated the evidence
key (ADR 34), the witness log spanned two keys and the *entire audit history
became unverifiable* — every pre-rotation entry failed under the new key, every
post-rotation entry failed under the old key. So rotation (a security
requirement) destroyed the audit trail (a security requirement). Contradiction.

Worse: nothing cryptographically bound a witness entry to the *particular* key
that served it. An attacker who could obtain two evidence keys could
re-attribute an old served record to the new key (or vice versa), and the
single-key verify would happily accept either, because it only checks the
signature against the one pinned key — it never proved the entry was served by
the key it claims.

## Decision

Make the witness log **rotation-aware**: every entry is cryptographically bound
to the exact evidence key that served it, identified by the ADR 34 trust-log
`key_seq` and the key's PEM fingerprint.

Each `WitnessEntry` gains two signed fields:

| field | meaning |
|---|---|
| `key_seq` | the ADR 34 trust-log sequence index of the evidence key that signed this entry |
| `key_fingerprint` | `sha256` of the (whitespace-normalized) PEM of that evidence key |

Both are inside `canonical_bytes()`, so they are part of the signed envelope and
cannot be rewritten without breaking the signature.

Two verify paths now exist:

1. **`verify_witness_log(pubkey)`** — *unchanged ADR 35 contract.* Single key.
   Every entry must be signed by the one `pubkey`. Rejects a rotated log. Kept
   for the common case (no rotation) and as the fail-closed baseline.

2. **`verify_witness_log_anchored(log, trust_log)`** — *NEW (ADR 36).* Rotation-
   aware. For each entry it resolves the signing key via the ADR 34 trust log:
   `trusted_key_for_seq(trust_log, entry.key_seq)` returns the evidence key that
   was in force at that `key_seq`. The entry's `key_fingerprint` must equal the
   fingerprint of that trusted key (preventing forged re-attribution), and the
   entry's signature must verify against it. The hash chain still validates the
   sequence integrity as before.

**Security properties gained:**

- **Rotation survives audit.** A log spanning `key_seq` 0 (bootstrap) and 1
  (rotate) verifies rotation-aware: old entries under the rotated-out key, new
  entries under the rotated-in key.
- **No silent re-attribution.** Changing an entry's `key_seq` (claiming a
  different key) without re-signing fails, because `trusted_key_for_seq` returns
  the bound key whose fingerprint won't match the entry's stored fingerprint, OR
  the signature won't verify against that key.
- **Anchored to ADR 34.** Verification takes the trust log as an explicit anchor
  (operator-pinned via `verify_authority`), so it cannot be fed a forged key
  sequence. Unknown `key_seq` (a key the trust log never introduced) is rejected.
- **Fail-closed everywhere.** Any malformed entry, broken chain, unknown key_seq,
  fingerprint mismatch, or signature failure → `False`. The single-key path is
  preserved exactly.

## Endpoints / agent surface

- `POST /authority/rotate` (ADR 34) now also advances the witness log's
  `current_key_seq` / `current_key_fingerprint`, so subsequent `POST /query/*`
  attestations are bound to the rotated-in key.
- `KnowledgeAgent.verify_witness_log_anchored(trust_log)` — fetches the served
  witness log and verifies it rotation-aware against the operator-anchored trust
  log. The agent's `verify_authority(anchor)` already refreshes its pinned
  evidence key, so a post-rotation attestation verifies off-line under the new
  key.
- `KnowledgeAgent.query_op(..., attested=True)` records the served
  `deterministic_hash` into the witness log bound to the current evidence key.

## Files

- `src/query/witness.py`: `WitnessEntry.key_seq` / `key_fingerprint` (in signed
  bytes); `append_entry` accepts `key_seq` / `key_fingerprint`; new
  `verify_witness_log_anchored(log, trust_log)`; `WitnessLog` carries
  `current_key_seq` / `current_key_fingerprint`. `verify_witness_log` unchanged.
- `src/query/authority.py`: `trusted_key_for_seq(trust_log, seq)` — resolve the
  evidence key in force at a given `key_seq`; `AuthorityLog.current_key_*`
  helpers.
- `src/query/service.py`: `/authority/rotate` binds the witness `current_key_*`
  to the rotated-in key; `/query/*` attestations pass the live
  `key_seq`/`key_fingerprint` to `append_entry`.
- `src/query/agent.py`: `verify_witness_log_anchored(trust_log)`;
  `rotate_authority()` returns `current_key_seq`.
- `tests/test_query_witness_log_anchored.py` (NEW): rotated log verifies
  anchored but NOT single-key; forged key-rebinding rejected; history tamper
  breaks chain; unknown key_seq rejected; all-bootstrap-key entries verify.
- `tests/test_query_live_transport.py`: `test_adr36_live_key_rotation_keeps_witness_audit_verifiable` — live rotate over a real socket, both key_seqs present, anchored verify passes, single-key verify rejects.
- `examples/live_harness.py`: section 7 adds the live-rotation audit block.

## Constraints honored

- No new dependencies (`cryptography` already pinned).
- Evidence domain stays SEPARATE from the frozen finance gateway; no import or
  mutation of `fleet.epistemic.decide()` or the gateway keyring.
- The ADR 35 single-key contract is preserved byte-for-byte; this is additive.
- Fail-closed: verification returns `False`, never an exception a caller swallows.

## Test

- `pytest tests/test_query_witness_log_anchored.py` → 6 passed.
- `pytest tests/test_query_live_transport.py` → rotation block passes.
- Full suite: green (baseline 263 + this work).

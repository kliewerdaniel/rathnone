# ADR 35 — Evidence-Serving Witness Log (what was served to whom)

- **Status:** RATIFIED + IMPLEMENTED (2026-08-21) — full suite green (259 passed)
- **Extends:** ADR 30 (attestation) + ADR 32 (operation scope) + ADR 34 (key anchor)
- **Depends on:** `src/query/{witness,attest,service,agent}.py`
- **Parallels:** gateway ADR 21 key audit / ADR 23 `safety_audit` table — but in
  the evidence domain, never touching the frozen gateway.

## Context

ADR 30 attests each `EvidenceRecord` (authenticity + integrity), ADR 32 scopes
*who* may query, and ADR 34 anchors *which* evidence key is trusted. But none of
them records **what was actually served to whom**. After the fact, the operator
could not answer:

> Which evidence did agent X receive on date D, and is that record still the
> one a fresh execution would produce?

The frontier named at the ADR 33/34 handoff was exactly this: a **transparency
log that records every attested query hash per agent** so an operator can later
prove *which* evidence was served to *which* agent — and detect silent drift or
served-record substitution.

## Decision

A **serving-witness log**: a tamper-evident, hash-chained, signed append-only
record of every attested query the service served. Each entry binds:

| field | meaning |
|---|---|
| `query_hash` | sha256 of the submitted query spec (Op plan or NL text) — matches a known request |
| `record_hash` | deterministic hash of the `EvidenceRecord` returned (identical to the ADR 30 attestation's `signed_hash`) — *which* evidence set was served |
| `agent_id` | the ADR 32 scope's agent, or `"<unscoped>"` in local-first open mode |
| `capabilities` | the ADR 32 capability set enforced (`[]` allow-all, or `"<allow-all>"` when unscoped) |
| `authority_id` | the evidence-domain signer id (the ADR 34 anchor label) |
| `issued_at` | epoch-ns timestamp of service, for a real audit trail |

**Security properties:**

- **Hash-chained (tamper-evident).** Entry N's `prev_hash` = sha256 of entry
  N-1's canonical bytes; entry 0 has `prev_hash = ""`. Rewriting any historical
  entry's bound hashes breaks every later signature — the same chain discipline
  as ADR 34.
- **No new trust root.** Entries are signed by the **same evidence-domain Ed25519
  key the operator already anchors via ADR 34**. `verify_witness_log(log,
  evidence_pem)` is fully off-line and reuses the ADR 34 pin — so adding the
  witness log introduced zero new key material or trust bootstrap.
- **Fail-closed.** `verify_witness_log` returns `(False, reason)` on an empty
  log, broken chain, out-of-order seq, or any bad signature — never raises, and
  never trusts a log signed by a non-pinned key.
- **Scope-aware.** A scoped attested query records the bound `agent_id` and
  enforced `capabilities`; an unscoped (local-first) query records
  `"<unscoped>"` / `"<allow-all>"` so the operator sees precisely which posture
  served each record.

**Deliberate out-of-scope (honesty about the threat model):** the log is
**server-held and tamper-evident, not trustless**. A compromised service could
drop entries *before* serving (it cannot forge them — that requires the pinned
key). The defense is *auditability*: any party holding the served records can
replay this log and detect dropped entries, and the operator pins the expected
evidence key so a substituted log fails signature verification. Making the log
itself replicated/consensus is a separate concern (ADR-future), not a reason to
block this audit primitive.

## Endpoints

- `GET /witness/log` — the raw witness log (hash-chained entries) for the current
  app instance.

Every attested query (`/query/op/attested`, `/query/nl/attested`) appends one
entry at service time. Plain (`/query/op`, `/query/nl`) routes do NOT append —
the witness log records only *attested* service, which is exactly the
attributable surface the operator cares about.

## Operator workflow

1. Pin the evidence key via ADR 34 (`agent.verify_authority(anchor_pem)`).
2. Periodically pull `/witness/log` and `verify_witness_log(anchor_pem)` off-line.
3. Replay each entry's `record_hash` against a fresh execution to detect silent
   drift; reconcile `agent_id` / `capabilities` against the agent registry.

## Files

- `src/query/witness.py` (NEW): `WitnessEntry`, `WitnessLog`, `append_entry`,
  `verify_witness_log` (off-line, fail-closed).
- `src/query/service.py`: per-instance `witness_log`; appended on every attested
  query (binds query hash, record hash, agent id, capabilities);
  `GET /witness/log`.
- `src/query/agent.py`: `KnowledgeAgent.fetch_witness_log()` +
  `verify_witness_log(evidence_pem)` — off-line verification against the pinned
  evidence key.
- `src/query/__init__.py`: exports the witness symbols.
- `tests/test_query_witness_log.py` (NEW, 8 tests): empty-log reject; single +
  two-entry chain verify + bind correctly; history-tamper breaks chain; wrong
  key rejected; in-process attested query appends (unscoped => `<unscoped>` /
  `<allow-all>`); agent verifies off-line and rejects a wrong key; scoped
  attested query binds agent id + capabilities.
- `docs/35-EVIDENCE-WITNESS-LOG.md` (this ADR).

## Constraints honored

- No new dependencies (`cryptography` already pinned).
- Evidence domain stays SEPARATE from the frozen finance gateway; no import or
  mutation of `fleet.epistemic.decide()` or the gateway keyring. The witness log
  reuses the ADR 34 evidence key — no second key to provision.
- Fail-closed everywhere.

## Test

- `pytest tests/test_query_witness_log.py` → 8 passed.
- Full suite: **259 passed** (251 + 8).

# ADR 30 — Evidence Attestation (evidence-domain authority, parallel to gateway)

- **Status:** RATIFIED + IMPLEMENTED (2026-08-21)
- **Extends:** ADR 27 (executor) + ADR 29 (HTTP service)
- **Depends on:** `src/query/{executor,algebra,compiler,service}.py`

## Context

ADR 27/28/29 give agents a deterministic, inspectable, HTTP-accessible knowledge
substrate: an `Op` plan executes to an `EvidenceRecord` whose included/excluded
id set is reproducible (`deterministic_hash`) and reconciles against an expected
prior (`verify()` / `reconcile_with()`).

But a deterministic record is not yet *attributable*. An agent downstream cannot
tell whether the record it received was produced by the expected authority, or
whether the included set was swapped after the fact. Rathnone's identity is an
*attributable, verifiable, fail-closed* authority — so the substrate needs a
trust anchor: a signature an agent can verify **off-line**, independently of the
service that produced it.

## Decision

Add a **separate Ed25519 evidence-domain authority** that signs the
`EvidenceRecord`'s deterministic hash. The authority is its own trust domain —
**deliberately independent of the frozen finance gateway's operator keyring**
(ADR 17-23). We do NOT reuse `src.security.keystore` or `src.security.operator`.

Key properties:

- **Signature covers ONLY `deterministic_hash`** (sha256 over sorted
  included/excluded ids), never the reasons/plan text. Consequences:
  - A tampered or drifted evidence set changes the hash → signature fails (the
    verdict stays replayable from its hash — Rathnone's key-free-verifiable
    discipline, Invariant 3).
  - Re-serializing non-binding fields (reasons/plan) does NOT invalidate the
    attestation, so an agent can rehydrate and re-verify freely.
- **Fail-closed verification.** `verify_attestation()` returns `False` on any
  anomaly (wrong key, malformed input, hash mismatch) — it never raises, so a
  caller cannot accidentally swallow a verification failure.
- **No new dependencies.** Ed25519 comes from `cryptography` (already pinned,
  `cryptography==50.0.0`).
- **Per-instance state.** The graph registry AND the authority live inside
  `create_app()`, so two app instances in one process are fully isolated
  (fixed during testing: the prior module-level registry leaked graphs between
  `create_app()` calls). The authority is ephemeral unless seeded via
  `RATHNONE_EVIDENCE_KEY_PEM` (file path or inline PEM).

## Implementation

- `src/query/attest.py` (NEW): `Attestation` dataclass (signer_id, signed_hash,
  signature, algorithm, issued_at; `as_dict`/`from_dict`), `EvidenceAuthority`
  (holds Ed25519 key, `sign(record)`), `generate_keypair`, `load_private_key`,
  `load_public_key`, `verify_attestation` (fail-closed).
- `src/query/executor.py`: `EvidenceRecord.from_dict()` for off-line
  rehydration of an attestation.
- `src/query/service.py`: `GET /authority/public-key` exposes the
  evidence-domain public key; `POST /query/op/attested` and
  `POST /query/nl/attested` return the record plus an `attestation` block. Graph
  registry + authority moved inside `create_app()` for instance isolation.
- `src/query/__init__.py`: export the attestation symbols.
- `tests/test_query_attest.py` (NEW): 8 tests (sign/verify round-trip, wrong-key
  rejection, tamper rejection, key-free-verifiable re-serialize, malformed
  fail-closed, public-key exposure, attested-query verifiable, attested-query
  tamper detection).

## Status

Full tree green (221 passed). The engine is now a complete, attestable,
agent-accessible local substrate:

```
NL text ─┐
         ├─> compiler -> Op tree ─> executor -> EvidenceRecord ─> verify()
Op dict ─┘        (service.py HTTP surface, isolated from finance gateway)
                              │
                    EvidenceAuthority.sign(hash)  ──> Attestation
                              │
                    agent verifies off-line via /authority/public-key
```

## Future (deferred)

- A parent attestation chain or transparency log over attestations (so a verifier
  can confirm the evidence-domain key itself was provisioned by the expected
  root), without touching the frozen gateway keyring.
- Time-window / revocation semantics for the evidence key (mirrors ADR 21 grace
  periods but in the evidence domain).

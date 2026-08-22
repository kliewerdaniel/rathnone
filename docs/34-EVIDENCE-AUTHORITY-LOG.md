# ADR 34 — Evidence-Authority Trust Log (anchorable key rotation/revocation)

- **Status:** RATIFIED + IMPLEMENTED (2026-08-21) — full suite green (251 passed)
- **Extends:** ADR 30 (evidence attestation) + ADR 29 (query service) + ADR 31 (agent harness)
- **Depends on:** `src/query/{attest,authority,service,agent}.py`, `scripts/evidence_key_log.py`
- **Parallels:** gateway ADR 21 (operator key lifecycle) — but in the evidence domain, and it never touches the frozen gateway.

## Context

ADR 30 gave the knowledge engine its own Ed25519 evidence key, deliberately
SEPARATE from the frozen finance gateway's operator keyring. But nothing
*anchored* that key:

- The agent fetched `/authority/public-key` and **trusted whatever it got**
  (trust-on-first-fetch). A compromised service could serve any key.
- There was **no way to ROTATE or REVOKE** the evidence key without redeploying
  the service with a new `RATHNONE_EVIDENCE_KEY_PEM`.
- Unlike the gateway (which has ADR 21 key lifecycle + ADR 23 durable keyring),
  the evidence domain had no operator-facing key-management surface.

This is the evidence-domain analogue of a **transparency log / certificate
authority**: a small, self-certifying, append-only hash-chain that lets the
operator root, rotate, and revoke the evidence key — and lets an agent verify
the key is trusted **without** trusting the service to name its own root.

## Decision

The trust log is a sequence of signed `AuthorityEntry` records:

| action | meaning | who signs |
|---|---|---|
| `bootstrap` | the root; `prev_hash = ""` | the anchor key (itself) |
| `rotate` | introduces a NEW currently-trusted key | the PREVIOUS trusted key |
| `revoke` | retires the current key (incident response) | the key being revoked |

The "current trusted key" is the PEM of the **last** entry if its action is
`bootstrap`/`rotate`; a log ending in `revoke` has **no** current trusted key
(so the service must be re-bootstrapped before it can sign again).

**Security properties:**

- **Self-certifying hash chain.** Each entry's signature covers
  `sha256(prev_hash || canonical_fields)`; `prev_hash` is the sha256 of the
  prior entry's canonical bytes. Rewriting any historical entry breaks every
  later signature — tamper-evident by construction.
- **No trust-on-first-fetch.** `KnowledgeAgent.verify_authority(anchor_pem)`
  verifies the served log against a **PINNED operator anchor PEM** — the root is
  never taken from the served log. A forged/unknown root is rejected fail-closed.
- **Rotation is authorized, not arbitrary.** A `rotate` entry is valid only if
  signed by the key currently in force (the prior trusted key). Only a trusted
  key can name its successor; a compromised-but-still-trusted key can rotate to
  a fresh key to recover.
- **Revocation is self-attested.** A `revoke` is signed by the key in force
  disavowing itself; after revoke the chain has no current key until a fresh
  `bootstrap` re-roots it.
- **Separate trust domain.** Built from `RATHNONE_EVIDENCE_KEY_PEM`, not the
  gateway keyring. The frozen `decide()` spine is never imported or touched.
- **Off-line verifiable.** `verify_trust_log(log, anchor_pem)` needs only the
  log + the pinned anchor; no network, no service trust. Deterministic
  canonicalization (Invariant 3 discipline: the verdict replays from a hash).
- **Fail-closed everywhere.** Any malformed entry, broken chain, wrong anchor,
  or out-of-order seq → `False`.

## Endpoints

- `GET /authority/public-key` — now also returns `trust_log` (the live log for
  the current key).
- `GET /authority/trust-log` — the raw log (hash-chained entries).

Every `create_app()` instance builds a bootstrap log for its evidence key at
startup, so the log is always present. A provisioned key yields a reproducible
anchor fingerprint; an ephemeral (local, unprovisioned) key yields a valid log
the agent can still fetch but must pin to verify off-line.

## Operator workflow (off-line, file-permission-gated)

`scripts/evidence_key_log.py` (parallel to `scripts/evidence_scope_sign.py`, but
evidence-domain key management):

```bash
# 1. Root a log at the provisioned key; PIN its anchor fingerprint.
python scripts/evidence_key_log.py bootstrap \
    --key /secure/evidence_ed25519.pem --out /secure/evidence_trust_log.json
# -> prints anchor_fingerprint; put it in agent config.

# 2. Rotate to a fresh key (signed by the current key); deploy the new key.
python scripts/evidence_key_log.py rotate \
    --key /secure/evidence_ed25519.pem --log /secure/evidence_trust_log.json \
    --out-key /secure/evidence_ed25519_next.pem
# deploy evidence_ed25519_next.pem as RATHNONE_EVIDENCE_KEY_PEM.

# 3. Revoke on incident (signed by the current key); re-bootstrap after.
python scripts/evidence_key_log.py revoke \
    --key /secure/evidence_ed25519.pem --log /secure/evidence_trust_log.json
```

The agent pins the **anchor fingerprint** (not the served root) and calls
`agent.verify_authority(anchor_pem)` once after bootstrap.

## Files

- `src/query/authority.py` (NEW): `AuthorityEntry`, `AuthorityLog`,
  `build_bootstrap_log`, `append_rotate`, `append_revoke`, `verify_trust_log`
  (fail-closed, off-line).
- `src/query/attest.py`: `EvidenceAuthority.signing_key()` accessor (held private
  key, used only to build the bootstrap entry; never exposed over the wire).
- `src/query/service.py`: builds the bootstrap log per instance;
  `/authority/public-key` carries it; new `/authority/trust-log` endpoint.
- `src/query/agent.py`: `KnowledgeAgent.verify_authority(anchor_pem)` — off-line
  anchor-pinned verification, replacing naive trust-on-first-fetch.
- `src/query/__init__.py`: exports the new symbols.
- `scripts/evidence_key_log.py` (NEW): operator bootstrap/rotate/revoke tool.
- `tests/test_query_authority_log.py` (NEW, 8 tests): bootstrap verify, rotate
  advances + stays valid, rotate requires prior-key signature, revoke has no
  current key, history tamper breaks chain, wrong anchor rejected, agent
  rejects unpinned anchor over wire, agent accepts pinned anchor over wire.
- `docs/34-EVIDENCE-AUTHORITY-LOG.md` (this ADR).

## Constraints honored

- No new dependencies (`cryptography` already pinned).
- Evidence domain stays SEPARATE from the frozen finance gateway; no import or
  mutation of `fleet.epistemic.decide()` or the gateway keyring.
- Fail-closed: verification returns `False`, never an exception a caller swallows.

## Test

- `pytest tests/test_query_authority_log.py` → 8 passed.
- Full suite: `251 passed` (243 + 8).

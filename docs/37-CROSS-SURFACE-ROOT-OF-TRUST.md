# ADR 37 — Cross-Surface Root-of-Trust (operator-attested surface ancestry)

- **Status:** RATIFIED + IMPLEMENTED (2026-08-21) — full suite green
- **Companion:** ADR 36 (rotation-aware witness log) — same epoch, same
  rotation/anchor discipline extended to the *operator* meta-key.
- **Extends:** ADR 17–24 (frozen finance gateway) + ADR 27–36 (knowledge engine)
- **Depends on:** `src/surface_attest.py` (NEW, read-only) + `scripts/surface_attest.py`

## Context

Rathnone is explicitly **two independent surfaces that never share trust**:

- The **Sovereign Finance Gateway** rides the frozen, model-independent
  `fleet.epistemic.decide()` spine (ADR 17–24). Its operator keyring is the
  finance authority.
- The **Knowledge-Query & Evidence Engine** (`src/query/`, ADR 27–36) has its
  *own* evidence-domain Ed25519 key (ADR 30/34), deliberately separate. The
  engine never imports `decide()`, the gateway never imports the engine.

That isolation is the point: a compromise of one surface cannot authorize the
other. But an operator (and an auditor/CI gate) still wants ONE answerable
question, fully off-line:

> "Are the keys these two independent surfaces are signing with RIGHT NOW both
> vouched for by the single operator identity I actually trust — and not by a
> key a surface merely *claims* about itself?"

Neither surface can answer this *for the other* without breaking the isolation
invariant. So the answer must live in a **third, meta artifact**: an
operator-signed manifest that vouches for each surface's current key.

## Decision

Add a **surface-attestation manifest**: a small, signed statement in which a
*separate operator root key* (the "meta" key, distinct from both the gateway's
operator keyring and the evidence anchor) vouches for the current public key of
each surface.

```
operator root  --signed-->  surface[finance-gateway].public_key
                 \--signed-->  surface[knowledge-query].public_key
```

Each `SurfaceKeyBinding` is `(surface_id, key_kind, pubkey_pem, issued_at)`,
signed by the operator root over `sha256(canonical(bindings))`. A verifier
(holds the operator root pubkey out-of-band) then:

1. `verify_manifest(manifest, root_pub)` — checks the operator signature.
2. `check_surface(manifest, 'knowledge-query', served_evidence_pem)` and
   `check_surface(manifest, 'finance-gateway', served_gateway_pem)` — confirms
   each surface's *currently served* key equals the one the operator vouched
   for (fingerprint match). A substituted/compromised surface key is detected.

**Hard invariant — the module is READ-ONLY over both surfaces.** It imports
**nothing** from `src.service`, `src.security`, or `fleet.epistemic`. The surface
keys are fed in as raw public-key PEMs (read from a gateway health endpoint or
an ADR 34 trust-log anchor — by the caller, *outside* this module). So it is a
pure verification artifact; it can never mutate gateway authz or the frozen
spine. The isolation invariant is preserved **structurally**, not by policy.

**Design constraints honored:**

- **No new trust root in the engine.** The operator root is a THIRD key, separate
  from the gateway's operator keyring and the evidence anchor. It attests
  ancestry only; it does not sign finance actions or evidence records.
- **Fail-closed.** Malformed manifest, broken chain, bad signature, or a served
  key that doesn't match the vouched key → `(False, reason)`. Never raises.
- **Stable canonicalization.** Signatures cover a canonical, stable field set
  (never the JSON text), so re-serialization cannot break verification
  (Invariant 3 discipline).
- **No new dependencies.** `cryptography` already pinned.
- **No shared trust path.** The two surfaces remain independent; this artifact
  only *observes* their keys.

## Operator workflow

`scripts/surface_attest.py` (operator, out-of-band — file-permission-gated):

```bash
# 1. Generate the operator meta root key.
python scripts/surface_attest.py gen-root --out /secure/operator_root.pem \
    --out-pub /secure/operator_root.pub.pem
# Pin operator_root.pub.pem in agent/CI config (out-of-band).

# 2. Sign a manifest vouching for BOTH surfaces' current keys.
python scripts/surface_attest.py sign \
    --root /secure/operator_root.pem --operator-id rathnone-operator \
    --surface finance-gateway --kind operator --pubkey-pem <gateway op pub> \
    --surface knowledge-query --kind evidence-anchor --pubkey-pem <evidence anchor pub> \
    --out /secure/surface_manifest.json

# 3. Audit (CI / operator): verify, then compare each served key.
python scripts/surface_attest.py verify \
    --root /secure/operator_root.pub.pem --manifest /secure/surface_manifest.json \
    --surface knowledge-query --served-pubkey-pem <live evidence anchor pub>
# exit 0 == served key matches the vouched key; non-zero == mismatch (fail-closed).
```

The surface keys are obtained read-only (a gateway `/health` or the ADR 34
`/authority/public-key` response) — the manifest tool never writes to either
surface.

## Files

- `src/surface_attest.py` (NEW, read-only): `SurfaceKeyBinding`,
  `SurfaceAttestationManifest`, `generate_root_keypair`, `build_manifest`,
  `verify_manifest`, `check_surface`. Imports only `cryptography` +
  `src.query.attest` (the crypto helper). NO gateway/fleet import.
- `scripts/surface_attest.py` (NEW): operator `gen-root` / `sign` / `verify` CLI.
- `tests/test_surface_attest.py` (NEW): manifest sign/verify, wrong-root reject,
  `check_surface` match + substituted-key reject + missing-binding reject, full
  CLI end-to-end (gen-root/sign/verify passes; substituted served key fails),
  and `test_module_does_not_import_gateway_or_fleet` asserting the read-only
  invariant at the import-source level.
- `examples/cross_surface_attest.py` (NEW): standalone PoC (5 checks, no network,
  no gateway) demonstrating the vouch + substituted-key detection.
- `docs/37-CROSS-SURFACE-ROOT-OF-TRUST.md` (this ADR).

## Constraints honored

- No new dependencies (`cryptography` already pinned).
- Read-only over both surfaces: `src.surface_attest` imports NO gateway/fleet
  authz module — verified by a test that scans its import lines.
- Separate operator meta-key: does not inject a new trust root into either
  surface's domain.
- Fail-closed: verification returns `(False, reason)`, never a swallowed
  exception.

## Test

- `pytest tests/test_surface_attest.py` → 8 passed.
- `python examples/cross_surface_attest.py` → 5 passed.
- Full suite: green.

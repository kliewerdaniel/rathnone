# ADR 38 — Live Cross-Surface Attestation Consumer

- **Status:** RATIFIED + IMPLEMENTED
- **Supersedes / extends:** ADR 37 (cross-surface root-of-trust)
- **Depends on:** ADR 34 (evidence-authority trust log), ADR 37 (`src/surface_attest.py`)

## Context

ADR 37 shipped the **producer** half of the cross-surface root-of-trust: a
read-only `src/surface_attest.py` that lets an operator sign a manifest
vouching for the *current* public keys of both independent Rathnone surfaces
(the frozen finance gateway and the evidence-domain knowledge engine), verified
off-line against a pinned operator root key.

But ADR 37 had **no live consumer**. The gateway exposed no read-only endpoint
for its current operator key, so the only demonstrator was the standalone PoC in
`examples/cross_surface_attest.py` — which vouched for keys the operator typed
in by hand, not keys a *running* deployment is actually serving. That left the
manifest's central security claim unexercised against reality:

> *"Prove, with one signature, that both surfaces are currently signing with
> keys the operator actually trusts — not keys they merely claim about
> themselves."*

Without a live consumer, the manifest could be checked only against a manifest
the operator constructed, which is circular. The next frontier (per the
post-ADR-37 survey) was to make the gateway expose its current key and give the
ADR 37 tool a `verify-live` mode that fetches BOTH running surfaces over HTTP and
checks the manifest against what is deployed.

## Decision

1. **Read-only gateway operator-key endpoint.**
   The frozen finance gateway exposes `GET /operator/public-key`, returning its
   current operator signing key (`Ed25519PublicKey` from the live
   `_operator` authority), the operator id, and a deterministic fingerprint.
   - It is **ungated** (no `RATHNONE_API_KEY` / `RATHNONE_KEY_OPS`) and **writes
     nothing** — mirroring the knowledge engine's ungated
     `GET /authority/public-key`.
   - It never imports or references the frozen `fleet.epistemic.decide()` spine.
   - It reads from the **live** operator authority (`src.service.app._operator`),
     so a post-boot key swap is reflected at read time.

2. **`verify-live` consumer in `scripts/surface_attest.py`.**
   A new subcommand `verify-live` takes the gateway URL and knowledge-engine URL,
   fetches each surface's currently-served key over HTTP, and checks the manifest
   against BOTH — failing closed (non-zero exit) if either surface's live key
   does not match what the operator vouched. The `verify` subcommand also gains
   an optional `--live-url` parallel to `--surface` for partial live checks.

3. **Live drift-detection over the wire (ADR 35 follow-through).**
   The agent's off-line `assert_stable()` / `reconcile()` drift-detection path
   (previously only unit-exercised) is now driven against **live served results**
   in `examples/live_harness.py` (section 8) and
   `tests/test_query_live_transport.py`: the engine must return a stable included
   set across independent requests, not a per-request reshuffle.

## Consequences

- **Positive.** The ADR 37 manifest is now a *deployability gate*, not a demo: an
  out-of-band auditor runs `surface_attest verify-live` against the production
  gateway + knowledge engine and gets a single pass/fail proving both surfaces
  are running keys the operator trusts. Substituted or missing-surface keys fail
  closed (verified by `tests/test_surface_attest_live.py`).
- **Positive.** The new gateway endpoint is read-only and structurally isolated —
  it cannot mutate gateway authz or the frozen spine, consistent with the ADR 37
  read-only invariant.
- **Positive.** Drift detection is now exercised end-to-end over real TCP, so a
  regression in evidence stability (e.g. a per-request reshuffle the witness log
  would not catch) is caught by the live harness.
- **Negative / cost.** `verify-live` depends on the two surfaces being reachable
  over HTTP at the supplied URLs; it is an out-of-band operator action, not part
  of the runtime request path. No new dependencies were added (`httpx` already
  pinned for the rest of the substrate).

## Verification

- `tests/test_operator_public_key.py` — endpoint is read-only, well-formed, and
  reflects the live operator authority.
- `tests/test_surface_attest_live.py` — `verify-live` passes when the manifest
  vouches for the actual served keys of BOTH running surfaces, and fails closed
  when a substituted gateway key or a missing knowledge-query surface is vouched.
- `tests/test_query_live_transport.py::test_adr35_drift_detection_over_wire` —
  `assert_stable()` and `reconcile()` hold over real served results.
- `examples/live_harness.py` section 8 — `adr35_live_drift_check_stable` and
  `adr35_live_reconcile_agrees` run green over a live socket.
- Full suite: **282 pytest passing** (incl. ADR 38).

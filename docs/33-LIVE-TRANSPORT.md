# ADR 33 — Live-Transport Knowledge-Query Service (real network boundary)

- **Status:** RATIFIED + IMPLEMENTED (2026-08-21) — full suite green (243 passed)
- **Extends:** ADR 29 (query service) + ADR 30 (evidence attestation) + ADR 31 (agent harness) + ADR 32 (evidence-operation scope)
- **Depends on:** `src/query/{algebra,executor,attest,service,scope,agent}.py`, `uvicorn`, `httpx`

## Context

ADR 27–32 build the knowledge-query substrate and prove it end-to-end with
`TestClient` (in-process). That proves the *logic* but not the *deployability*:
the substrate is only useful if it can run as a real service reachable over a
network socket, with attestation and scope enforced identically across the wire
as they are in-process. The gateway already serves over uvicorn; the knowledge
service must demonstrate the same property so an agent system can reach it from
a different process, container, or host.

This closes the last open frontier from the substrate build: **prove the
service is a real, network-reachable surface — not just a callable module.**

## Decision

Serve the existing `create_app()` behind `uvicorn` on a real TCP socket
(`127.0.0.1:<port>`) and drive it with a real `httpx.Client`. The
`KnowledgeAgent` already accepts any httpx-like client (it only calls
`.post` / `.get`), so **no agent changes are needed** to cross the boundary —
the same client code runs in-process or over TCP.

The deploy target is canonical: `app = create_app()` is bound at module import
(`src/query/service.py`), so `uvicorn rathnone.query.service:app` is a valid,
isolated-per-instance server. Env (`RATHNONE_EVIDENCE_KEY_PEM`,
`RATHNONE_EVIDENCE_OP_KEY_PEM`, `RATHNONE_QUERY_API_KEY`) is read inside
`create_app()`, so the operator configures the trust domain at boot.

## Bug found and fixed (the transport test earned its keep)

While driving the live service, the NL scope path returned
`403 scope body_hash does not bind to this query plan` for a correctly-signed
scope. Root cause: the NL handler verifies the scope's body binding against the
**raw text** (ADR 32 F3), then `_run` re-checked the *same* scope's
`body_hash` against `op_body_hash(op.to_dict())` — where `op` is the **compiled**
plan. A text-bound scope can never equal a compiled-plan hash, so every NL
query under scope was (wrongly) rejected.

Fix: `_run` now takes an explicit `body_binding_done` flag. `/op*` routes leave
it `False` (binding checked against the canonical plan inside `_run`); `/nl*`
routes pass `body_binding_done=True` because their handler already verified the
binding against `req.text`. Capability + size enforcement still runs for both
routes. The in-process `TestClient` suite never exercised the NL+scope+compiled
cross-check, so the bug was invisible until a real client presented a text-bound
scope — exactly the path the live harness drives.

## Proven properties (live, over TCP)

1. **Health + graph load** over a real socket.
2. **Attested Op query** with the attestation fetched over the wire; the agent
   verifies the signature **off-line** against the public key fetched over the
   wire (`/authority/public-key`).
3. **ADR 32 envelope enforced live:** a signed `QueryScope` bound to the exact
   query body succeeds; `scope.enforced=True` is echoed; an unscoped request to
   a provisioned server is refused (401); a valid signature with a
   non-binding `body_hash` is refused (403). The replay guard (per-nonce) is
   exercised: presenting the same scope nonce twice is refused.
4. **ADR 34 + 35 live audit:** after serving attested queries, the harness
   verifies the served `/authority/trust-log` against the **operator-pinned**
   evidence anchor (no trust-on-first-fetch) and the `/witness/log` off-line
   against the same evidence key — and confirms the witness log records the
   exact `deterministic_hash` values that were served. The whole evidence-domain
   trust chain is therefore proven auditable over a real socket, not just in
   unit tests.

## Files

- `examples/live_harness.py` (NEW): runnable PoC — `uvicorn` server thread +
  `httpx.Client`, prints a `SUMMARY: N passed, M failed` line (8/8). Mirrors
  `examples/agent_harness.py` but across the wire. Hardened to also verify the
  ADR 34 authority trust log (against the pinned anchor) and the ADR 35 witness
  log off-line over the real socket.
- `tests/test_query_live_transport.py` (NEW, 4 tests): durable gate that serves
  the real app on a free TCP port and drives it with `httpx`; asserts attestation
  over wire + scope enforcement (success / 401 / 403) + the ADR 34/35 live audit
  path. Env via `monkeypatch` so nothing leaks into the suite.
- `src/query/service.py`: `_run` gains `body_binding_done` kwarg; NL handlers
  pass it (fixes the text-bound scope rejection above).
- `docs/33-LIVE-TRANSPORT.md` (this ADR).

## Constraints honored

- No new dependencies (`uvicorn`, `httpx` already pinned).
- Service stays **separate** from the frozen finance gateway; never imports or
  mutates `fleet.epistemic.decide()` or gateway authz.
- Evidence-domain authority remains an **independent** Ed25519 key (ADR 30/32),
  distinct from the gateway keyring.
- Fail-closed everywhere: missing/invalid/wrong/expired/replayed/bad-binding
  scope → 401/403.

## Test

- `examples/live_harness.py` → `SUMMARY: 11 passed, 0 failed` (real socket; incl.
  ADR 34/35 live audit).
- `pytest tests/test_query_live_transport.py` → 4 passed.
- Full suite: `263 passed` (259 + 4).

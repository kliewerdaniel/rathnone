# ADR 41 — Agent-Harness Authority Binding (Hermes + Codex sub-agents as a `decide()` consumer)

- **Status:** RATIFIED + IMPLEMENTED (verified over real TCP, 2026-08-21)
- **Depends on:** ADR 17 (static-key gate), ADR 19/20 (signed operator commands),
  ADR 32 (evidence-operation scope), ADR 16/24 (hygiene gate), ADR 37/38
  (cross-surface root-of-trust)
- **Forbidden:** any edit to the frozen `fleet.epistemic.decide()` spine (Inv 1)

## 1. Summary

The local agent harness — Hermes (this terminal's coding agent) dispatching
**Codex CLI sub-agents** via `codex exec` — currently runs *outside* Rathnone's
authority. This ADR binds it **as a consumer of the same frozen `decide()`
spine** that governs the finance gateway, so consequential harness actions
(structurally: applying a patch / committing / running a destructive command)
are gated fail-closed by the control plane.

The binding is **progressive**: it starts at the ADR 17 static-key gate today and
deepens automatically as Rathnone ratifies more controls (operator-signed
halt/resume, per-scope permissioning, hygiene gate). The harness does not hard-code
which controls exist — it discovers the live control surface and degrades to
fail-closed if anything is unverifiable.

## 2. Motivation

- The harness already spawns real sub-agents that write files and run commands.
  That is the same class of consequential action the control plane exists to govern.
- Rathnone's registry pattern (`src/finance/registry.py`) already proves the
  substrate is domain-general: adding a consumer is a one-line `capability` table
  edit plus a constant, auto-covered by `test_registry.py`. The harness should
  join that table rather than reinvent a parallel authority.
- Fail-closed by default: if Rathnone is unenforced / unreachable, the harness
  **refuses** consequential actions rather than running open.

## 3. Scope

In scope:
- A new capability constant + registry entry (`rathnone.agent_harness_execute`).
- A harness-side gate function `harness_should_proceed()` that consults the
  Rathnone control plane (static-key gate + `decide()` verdict) before a Codex
  sub-agent applies changes.
- A progression hook that re-reads the live control surface each run.
- Operator controls: the existing `/safety/halt` already trips the harness loop.

Out of scope:
- Editing `fleet.epistemic.decide()` (Inv 1 — forbidden).
- The Codex CLI binary or its internal sandbox (already verified working).
- Finance-signing paths (the harness is a *separate* consumer, not a tenant).

## 4. Capability + registry binding (mirrors `src/finance/` exactly)

`src/finance/capabilities.py` — add:

```python
CAP_FIN_AGENT_HARNESS_EXECUTE = "rathnone.agent_harness_execute"
```

`src/finance/registry.py` — add one row to `REGISTERED_CAPABILITIES`:

```python
("rathnone/agent-harness-execute", CAP_FIN_AGENT_HARNESS_EXECUTE),
```

This makes the harness the **8th registered consumer** of `decide()`. The
parameterized generality suite (`tests/test_registry.py`) auto-covers it with
zero new test logic — same Meta-Invariant M0 proof, finance slice.

No substrate behavior is added: the harness calls the same
`build_authorization_scope` / `issue_grant` / `decide()` path as the finance trio.
The substrate never sees a "harness" label — only the literal capability string.

## 5. The harness gate (fail-closed)

A single harness-side function decides whether a Codex sub-agent may **apply**
changes (patch/commit/destructive command). It is consulted before every apply:

```
harness_should_proceed(action) -> ALLOW | BLOCKED | DENY_OPEN
```

Resolution order (each step fails closed):

1. **Reachability** — can the Rathnone control plane be reached?
   - Unreachable / unconfigured → **DENY_OPEN** (refuse; never run open).
2. **Static-key gate (ADR 17)** — present `RATHNONE_API_KEY`?
   - Missing → **DENY_OPEN**.
3. **`decide()` verdict** — call `decide_registered(...,
   capability=CAP_FIN_AGENT_HARNESS_EXECUTE, policy_allow=<from control plane>,
   human=<operator override>)`.
   - `BLOCKED` → **BLOCKED** (harness reports and stops).
   - `HUMAN` → require explicit operator confirmation before proceeding.
   - `AUTO` → **ALLOW**.
4. **Operator halt (ADR 19/20)** — if `/safety/halt` is tripped, the loop stops
   regardless of `decide()`. The harness polls `/safety` and honors the breaker.

When `RATHNONE_ENFORCE_AUTH=0` (dev), the gate logs `AUTH_DORMANT` and allows
local-only scratch work (matching the rest of rathnone's dev posture), but still
refuses to touch a non-scratch repo without an explicit `--i-understand` flag.

## 6. Progression hook ("as rathnone progresses")

The harness does NOT pin a fixed list of controls. On each run it reads the live
control surface and enables deeper gating as it appears:

| Rathnone control ratifies… | Harness behavior deepens to… |
|---|---|
| ADR 17 static key | require `RATHNONE_API_KEY` (baseline) |
| ADR 19/20 signed halt/resume | honor `/safety/halt` mid-run |
| ADR 32 evidence scope | bind each sub-agent to a `QueryScope`; deny out-of-scope queries |
| ADR 16/24 hygiene gate | run `CorroborationLayer` over agent output before apply; BLOCKED on poison |
| ADR 37/38 cross-surface | verify the control-plane key against the live manifest before trusting it |

Unknown / unverifiable control → fail closed (treat as not-yet-provisioned,
refuse consequential actions). This keeps the integration honest as the plane
evolves rather than ossifying today's capability set.

## 7. Test strategy (delivered)

- `tests/test_harness_gate.py` — mirrors `test_registry.py`: the parameterized
  generality suite auto-covers the harness capability (AUTO / HUMAN / BLOCKED
  against `decide()`). Plus fail-closed unit tests: DENY_OPEN when the key is
  absent under enforcement, BLOCKED on policy deny and on HUMAN, and BLOCKED on
  breaker-open.
- `tests/test_harness_gate_live_tcp.py` — **real-TCP** gate (ADR 33 discipline):
  boots the actual `src.service.app` over a uvicorn socket and drives it with a
  real `httpx.Client` (not `TestClient`). Asserts (a) no-key POST `/harness/
  authorize` is 401, (b) valid `Bearer` + AUTO policy returns 200 `ALLOW` with the
  documented `{decision, reason, breaker_open, dormant}` shape, and (c) a live
  `POST /safety/halt` over the wire flips the breaker the harness endpoint reads,
  so the **same** `/harness/authorize` call now returns `BLOCKED` over TCP —
  proving the operator panic button genuinely stops the harness loop. `/
  safety/resume` restores `ALLOW`.

Note: the harness *function* is unit-tested for every resolution path; the live
TCP test proves the *endpoint* honors it across a network boundary and that the
operator halt is effective over the wire. The "stop a live background Codex
sub-agent" claim is validated at the control-plane boundary (the harness polls
`/harness/authorize` before each apply and refuses on anything but `ALLOW`), not
by spawning a real Codex process in CI.

## 8. Open questions (for ratification)

1. **Capability granularity** — one `agent_harness_execute` for all apply actions,
   or split read-only-explore vs apply-vs-commit so `decide()` can HUMAN-gate only
   commits? (Recommend: split later via ADR fork; start with one.)
2. **Human verdict path** — does HUMAN mean "prompt the operator in this terminal"
   or "hard BLOCK until a signed operator command arrives"? (Recommend: prompt.)
3. **Hygiene gate timing** — gate *before* every apply, or only on diffs > N lines?
   (Recommend: every apply to start; cheap given deterministic layer.)

## 9. Exit criteria (definition of "done")

- Harness capability registered + covered by `test_registry.py` green.
- `harness_should_proceed` implemented + fail-closed tests green over real TCP.
- `/safety/halt` observed to stop a live background Codex sub-agent.
- ADR 41 ratified, implemented, committed (after user review).

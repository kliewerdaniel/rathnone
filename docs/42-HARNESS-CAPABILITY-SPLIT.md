# ADR 42 — Harness Capability Split (explore vs apply)

- **Status:** RATIFIED + IMPLEMENTED (2026-08-21)
- **Depends on:** ADR 41 (harness authority binding), ADR 17 (static-key gate),
  ADR 19/20 (operator circuit breaker), ADR 32 (evidence scope)
- **Forbidden:** any edit to the frozen `fleet.epistemic.decide()` spine (Inv 1)
- **Closes:** ADR 41 §8 open question #1 (capability granularity)

## 1. Problem

ADR 41 bound the local agent harness (Hermes + Codex sub-agents) as a consumer of
the same frozen `decide()` spine via a **single** capability
`rathnone.agent_harness_execute`, covering every consequential action
(patch / commit / destructive command) with one verdict. That over-bundles two
very different risk classes:

- **Explore actions** — read-only research: reading files, web search, listing
  processes, generating a diff *for inspection*. No state changes. Nagging the
  operator before every read is friction with no safety payoff.
- **Apply actions** — consequential: applying a patch, committing, pushing,
  running a destructive command. These mutate state / publish. The operator
  should be in the loop.

A single capability cannot HUMAN-gate only commits. ADR 41 §8 flagged this as the
first open fork. This ADR takes it.

## 2. Decision

Split the harness consumer into **two registered capabilities**, both riding the
SAME frozen `decide()` (no substrate behavior added):

| Capability | Default verdict | Operator loop |
|---|---|---|
| `rathnone.agent_harness_explore` | **AUTO** | none — silent |
| `rathnone.agent_harness_execute` | **HUMAN** (prompt) | required before apply |

Both enter `REGISTERED_CAPABILITIES` exactly like the finance trio, so the existing
parameterized generality suite (`tests/test_registry.py`) auto-covers them with
zero new harness-specific test logic — same Meta-Invariant M0 proof. The harness
is now the **9th and 10th** registered consumers (two rows sharing one governance
authority).

### How the verdict is produced (frozen spine, no new behavior)

`evaluate_harness_action(kind=...)` selects the capability and the
`require_human_approval` flag it passes to `decide_registered`:

- `kind="explore"` → `human=False` → `decision_for` returns `AUTO` → `ALLOW`.
- `kind="apply"`, not yet approved → `human=True` → `decision_for` returns
  `HUMAN` → gate returns `BLOCKED` with reason signaled `HUMAN required`.
- `kind="apply"`, operator pre-approved (`pre_approved=True`) → `human=False` →
  `AUTO` → `ALLOW`.

`pre_approved` is **not** a bypass: it still routes through `decide()` with the
operator's approval acknowledgement re-verified by the control plane. Fail-closed
default is `pre_approved=False`; an unreachable / unenforced / wrong-key control
plane refuses regardless.

The substrate never sees a "harness" label — only the literal capability string
(`rathnone.agent_harness_explore` / `rathnone.agent_harness_execute`).

## 3. Scope

In scope:
- `CAP_FIN_AGENT_HARNESS_EXPLORE` constant + registry row.
- `evaluate_harness_action(*, kind="apply" | "explore", pre_approved=False)` selector.
- `POST /harness/authorize` body gains `{"kind", "pre_approved"}`.
- `HarnessAuthorizer.may_apply(action, kind="apply", pre_approved=False)` client
  selector (the consumer glue from ADR 41's missing half).

Out of scope:
- Editing `fleet.epistemic.decide()` (Inv 1 — forbidden).
- Finer granularity than explore/apply (e.g. split commit vs push vs destructive).
  Revisit later if a real need appears; adding it is a one-line table edit per
  surface (SC4 proof unchanged).

## 4. Capability + registry binding (mirrors ADR 41)

`src/finance/capabilities.py` — add:

```python
CAP_FIN_AGENT_HARNESS_EXPLORE = "rathnone.agent_harness_explore"
```

`src/finance/registry.py` — add one row to `REGISTERED_CAPABILITIES`:

```python
("rathnone/agent-harness-explore", CAP_FIN_AGENT_HARNESS_EXPLORE),
```

The parameterized generality suite auto-covers it (test_registry.py parametrizes
over `REGISTERED_CAPABILITIES`).

## 5. Consumer flow (fail-closed)

```python
auth = HarnessAuthorizer(base_url=CP_URL, api_key=os.environ["RATHNONE_API_KEY"])

# Read-only research: silent.
if auth.may_apply("read src/x.py", kind="explore"):
    read(...)

# Consequential: must be approved by the operator.
if not auth.may_apply("commit -m wip", kind="apply"):
    # gate returned BLOCKED (HUMAN required) -> prompt operator
    if operator_confirms():
        if auth.may_apply("commit -m wip", kind="apply", pre_approved=True):
            commit(...)
    else:
        refuse()
```

Nothing consequential proceeds unless the operator explicitly acknowledged it
(`pre_approved=True`), and that acknowledgement is re-verified by the control
plane — not honored locally.

## 6. Test strategy (delivered)

- `tests/test_registry.py` — parameterized over `REGISTERED_CAPABILITIES`; the new
  `explore` row is auto-covered (AUTO under auto-policy, HUMAN under human-policy,
  BLOCKED under denylist, scope-escape BLOCKED). No new harness-specific test.
- `tests/test_harness_gate.py` — `explore` => AUTO (silent, no prompt);
  `apply` (not approved) => HUMAN => BLOCKED with `HUMAN` in reason; `apply` with
  `pre_approved=True` => ALLOW.
- `tests/test_harness_client_live_tcp.py` — live over real TCP: `explore` apply
  returns `True` without prompting; `apply` returns `False`; `apply` +
  `pre_approved=True` returns `True`; live `/safety/halt` overrides everything to
  `False` (breaker_open).

## 7. Exit criteria (definition of "done")

- `explore` + `execute` capabilities registered + auto-covered by `test_registry.py`.
- `evaluate_harness_action(kind=...)` returns AUTO for explore, HUMAN/BLOCKED for
  apply-unapproved, ALLOW for apply-pre-approved; fail-closed tests green over
  real TCP.
- ADR 42 ratified, implemented, committed (after user review).

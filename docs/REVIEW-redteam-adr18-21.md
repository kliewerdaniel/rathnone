# Rathnone Red-Team — Findings (ADR 18 → 21)

**Scope:** the diff since `df63e95` — ADR 18 (operator downgrade), ADR 19
(signed operator commands for halt/resume), ADR 20 (signed operator commands
for `authorize_action` + `scripts/operator_sign.py`) — plus the **in-flight
ADR 21 keyring** work in the working tree.
**Pinned to:** commit `08409e7` + working-tree ADR21 edits.
**Method:** executed PoCs (`tests/poc_findings.py`), not just code reading.
**Suite state:** 149 passed / 3 failed (all 3 are your uncommitted ADR21
keyring tests — they exercise the `operator_allowlist`→`operator_keys`
migration that is half-applied in the tree).

---

## F1 — 2-of-2 destination-override bypass via *subset* release  ⚠️ HIGH

**Where:** `src/service/pipeline.py:184-187` + `src/hygiene/downgrade.py:141-171`

ADR 18's 2-of-2 rule is keyed to **the downgrade's own `violation_ids`**
(`DowngradeRecord.requires_second`, `downgrade.py:84-85`), and the gate
(`validate_downgrade`) only checks that the released set is a *subset* of the
action's actual violations (`downgrade.py:143`). But the **pipeline** treats a
valid downgrade as *full clearance*: it sets `res.hygiene_ok = True` and wipes
`res.hygiene_violations = []` (`pipeline.py:184-185`) — releasing **every**
violation, not just the ones named in the record.

So a single operator releases a *non*-2-of-2 code (e.g. `price_unverifiable`)
and the action sails through while still blocked on a 2-of-2 code
(`destination_untrusted` / `destination_off_allowlist`) — which is exactly the
anti-theft check 2-of-2 exists to protect.

**Reproduced (single allowlisted operator, hygiene enabled):**
```
baseline: verdict=BLOCKED violations={'destination_untrusted', 'price_unverifiable'}
(a) release the 2-of-2 code directly:  ok=False  '2-of-2 override lacks a valid second operator'   <- correctly stopped
(b) release subset [price_unverifiable]: ok=True
end-to-end: verdict=HUMAN downgraded=True venue=SETTLED recon=MATCH state=SETTLED
```
The direct 2-of-2 release is correctly refused — the bypass is the *subset*
release. The attacker only needs the action to carry **≥2 violations**, one of
them a 2-of-2 code.

**Blast radius:** default (non-operator-gated) tenants. An ADR20-gated tenant
(operator allowlist set) is protected because the console can't get past the
transport gate without an operator signature.

**Root cause / fix:** the gate's "subset" tolerance is correct for the record,
but the pipeline must not over-clear. Either (a) re-run hygiene with the
released codes excluded and block if *any* 2-of-2 code remains unreleased, or
(b) require `released == actual` (the record must name the full blocking set),
so a 2-of-2 code always forces the second signature.

---

## F2 — `OperatorCommand` "binding" is decorative on two axes  ⚠️ MEDIUM

Two separate problems in the ADR19/20 signed-command gate:

**(a) `tenant_id` is signed but never checked.** `verify_command`
(`src/security/operator.py:339-352`) takes `body`, `allowlist_pems`,
`used_nonces`, `now` — **no tenant argument**. `cmd.tenant_id` is in the
canonical bytes (so it's covered by the signature) but nothing compares it to
the tenant the request is actually being processed for. A command signed for
tenant-A verifies against any tenant's allowlist.

```
cmd.tenant_id='tenant-A' verifies for ANY scope: ok=True
```
Mitigated today only because the gate is *dormant* for tenants without an
allowlist.

**(b) Safety-verb `body` is a hardcoded literal — the binding doesn't bind.**
`safety_halt`/`safety_resume` call
`_require_command(..., body=b"halt"/b"resume", ...)` (`app.py:250,262`). The
gate then compares the operator's `body_hash` against that literal
(`verify_command` → `operator.py:352`). So the *only* input that passes is one
signed over `b"halt"` — not the request. Confirmed:

```
signed over REAL body (empty):    401  "command body_hash does not match the request body"
signed over HARDCODED b'halt':    200  {"breaker_open":true}
```
Consequence: for safety verbs (which have **no request body**), "command
binding to the exact request" is vacuous, and a well-built signer that hashes
the actual body is *always* rejected (see F5). The replay protection that does
work is the per-scope nonce set + the ±60 s window.

**Fix:** thread the real tenant id into `verify_command` and compare it; for
bodyless endpoints, either drop the body_hash field for those verbs or hash a
stable canonical form of the (empty) request — don't pass a literal.

---

## F3 — the live-settlement verb needs no API key (prod mode)  MEDIUM

`POST /tenants/{tid}/authorize_action` and `POST /tenants/{tid}/authorize`
have **no** `Depends(require_api_key)` (`app.py:335, 287`). Only tenant
creation, the safety verbs, and the read endpoints are gated. In production
mode with the key set:

```
authorize_action (NO api key, NO operator allowlist): 200; verdict=AUTO; live signature present: True
POST /tenants/{tid}/authorize (NO api key): 200
RATHNONE_MAX_SETTLEMENT_VALUE_WEI unset -> max_settlement_value_wei() = None  (NO per-settlement ceiling)
```

Any network peer who knows a tenant id (they're short hex, enumerable via the
gated `GET /tenants`) can run the full pipeline and obtain a **live secp256k1
settlement signature** — and with the default no-value-ceiling
(`max_settlement_value_wei() = None`), an operator-gated tenant's funds are the
only thing standing between an attacker and a signed drain. This is partially
documented intent (`test_p0_security.py::test_authorize_action_is_open_to_tenant_callers`
asserts the endpoint is open to "tenant callers"), but the combination with
the unset ceiling + no per-tenant transport auth is worth an explicit decision.

**Fix:** gate the settlement verb with the ADR17 key (or require a
tenant-scoped caller credential), and treat the no-ceiling default as a
startup warning, not a silent state.

---

## F4 — ADR19 safety-verb attribution trail is in-memory and unsigned  LOW

`_SafetyOperatorScope.record_command` only appends to the module-level
`_safety_audit` list (`app.py:60-72`) — there is no tenant and no
`append_ledger` call for safety verbs. So the "who halted / who resumed"
attribution trail that ADR19 touts is (a) wiped on restart and (b) not
key-free verifiable (Inv-3), unlike the tenant-scoped downgrade/authorize
records which *do* land in the signed ledger. The ADR19 doc's Inv-3 claim
holds only for the tenant-scoped verbs.

**Fix:** route safety commands through a signed ledger too (a synthetic
`__safety__` tenant, or a dedicated signed safety log).

---

## F5 — `scripts/operator_sign.py` cannot produce an accepted command  MEDIUM

The shipped ops signing tool and the gateway disagree on both canonicalization
inputs, so a correctly-intended operator gets a 401:

**(a) Timestamp domain mismatch.** The tool stamps
`time.monotonic_ns()` (host-uptime-based, `operator_sign.py:89`); the gateway
compares against `Clock(monotonic=True)` = `time.monotonic_ns() - epoch-at-import`
(`guards.py:136-142`, `app.py:97`). These differ by the host's uptime:
```
tool timestamp (host monotonic_ns)     = 79259975346708
gateway clock (monotonic-since-import) = 114301708
divergence                             = 79259861045000 ns   (window = 60e9 ns) -> OUTSIDE window
```
**(b) Body canonicalization mismatch.** The tool hashes the JSON of the fields
it was given; the gateway hashes the full pydantic `model_dump()` (absent
optionals become `None`, `denylist` a list) — `app.py:354-355` vs
`operator_sign.py:50-53`:
```
tool body_hash == gateway body_hash: False
```

So ADR20's "ops-side signing tool" is non-functional in practice: the operator
must sign over the gateway's *hardcoded* body (F2b), omit all optional fields,
**and** run within 60 s of gateway boot. It silently defeats the whole point
of the tool (signing arbitrary approve/downgrade/live-settle payloads).

**Fix:** make both sides derive `body` and the clock from the same source —
e.g. the tool POSTs the body and the gateway hashes `request.body`, and both
use a shared wall-clock (or the gateway exposes its now for the signer to
align to). Add an integration test that runs `operator_sign.py` against a
live `TestClient` and asserts 200.

---

## ADR21 keyring (in-flight) — 3 failing tests

The working tree migrates `Tenant.operator_allowlist` (list) →
`operator_keys` (OperatorKeyRing) and `_used_downgrade_nonces` →
`_used_command_nonces`, but the migration is incomplete:

```
FAILED tests/test_hygiene_downgrade.py::test_destination_override_requires_second_operator
FAILED tests/test_hygiene_downgrade.py::test_validate_refuses_unrelated_violation_release
FAILED tests/test_operator_keyring.py::test_command_signed_by_revoked_key_refused_while_layer_in_force
```
The first two fail because the test still sets `t.operator_allowlist = [pem(o1), pem(o2)]`
but the pipeline now reads `self._tenant.operator_keys.active_pems()`
(`pipeline.py:174`) — an empty keyring → "tenant has no operator allowlist
(fail-closed)". The third is an assertion on the 401 detail string. Worth
finishing before the ADR19/20/21 work is considered done.

---

## Suggested priority

1. **F1** — real 2-of-2 bypass; fix the pipeline over-clear (or require full-set release).
2. **F2b + F5** — the signed-command layer's binding is non-functional for
   safety verbs and the tool can't produce a valid command; fix together (single
   source of truth for body + clock).
3. **F3** — decide + enforce auth on the live-settlement verb; warn on no ceiling.
4. **F2a** — thread tenant id through `verify_command`.
5. **F4** — persist safety attribution to a signed log.
6. ADR21 — finish the keyring migration so the suite is green.

PoC: `tests/poc_findings.py` (run: `env -u PYTHONPATH -u VIRTUAL_ENV
.venv/bin/python tests/poc_findings.py`).

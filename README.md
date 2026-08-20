# Rathnone

Sovereign Finance Gateway — a commercial product that rides the frozen,
model-independent `fleet.epistemic.decide()` authorization spine from
`sovereign-agent-fleet` to govern consequential finance actions (trade
execution, treasury rebalance, on-chain settlement) with cryptographic
verifiability and an immutable audit ledger.

See `docs/` for the full design surface (`docs/00-INDEX.md`). The threat model
and the fail-closed operator controls are in `docs/13-SECURITY-THREAT-MODEL.md`.

---

## What this is (for the operator)

Rathnone is a **local-first authority service**. It does NOT make autonomous
financial decisions — the frozen `decide()` spine returns `AUTO` / `HUMAN` /
`BLOCKED`, and the service acts only on `AUTO`. The operator always retains an
independent halt (the circuit breaker) that stops the live track regardless of
what `decide()` says. This is the antidote to the "immutable cage" failure.

Two runtime tracks:

- **Simulated (default):** `POST /tenants/{id}/execute` returns the authorized
  action with `simulated=True`. No real signatures, no network egress. Safe by
  default.
- **Live (opt-in):** a tenant minted with `live=true` gets a real settlement key.
  `POST /tenants/{id}/execute_live` produces a genuine secp256k1 (settlement) or
  Ed25519 (order) signature **only after** `decide()` returns `AUTO`.

---

## Deployment knobs (fail-closed)

All bounds come from the environment (prefixed `RATHNONE_*`). A malformed value
**raises at import time** rather than silently disabling a guard.

| Variable | Meaning | Default | Production |
|---|---|---|---|
| `RATHNONE_MAX_SETTLEMENT_VALUE_WEI` | V4: refuse to sign any settlement above this many wei | unset = **no ceiling** | **set it** (e.g. `500000000000000000` = 0.5 ETH) |
| `RATHNONE_LIVE_RATE_MAX` | V1: max live signatures per sliding window | `10**12` (unlimited) | **set it** (e.g. `100`) |
| `RATHNONE_HOST` | uvicorn bind host | `0.0.0.0` | keep behind proxy; `127.0.0.1` if console-only |
| `RATHNONE_PORT` | uvicorn bind port | `8765` | any |

`.env.example` is a hardened starting point. Copy to `.env` and adjust.

---

## Run it: Python (local/dev)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# The frozen spine is vendored at vendor/fleet_spine (pinned commit in
# vendor/fleet_spine/PINNED_COMMIT). The venv's fleet_overlay.pth points there.
pytest -q                       # 53 passing
RATHNONE_MAX_SETTLEMENT_VALUE_WEI=500000000000000000 \
RATHNONE_LIVE_RATE_MAX=100 \
  python -m uvicorn src.service.app:app --port 8765
```

The vendored spine is a **read-only snapshot** of `sovereign-agent-fleet` at a
pinned commit. That repo is never modified by Rathnone; bump the pin by
re-copying `fleet`/`exchange`/`scripts` and updating `PINNED_COMMIT`.

---

## Run it: Docker (recommended for prod)

The image bakes the frozen spine in at build time (no runtime fetch from a
mutable repo). It runs as a non-root user and ships a `/safety` healthcheck.

```bash
# Build
docker build -t rathnone:local .

# Run with REAL protective bounds (compose sets safe defaults too)
docker run -d --name rathnone \
  -p 127.0.0.1:8765:8765 \
  -e RATHNONE_MAX_SETTLEMENT_VALUE_WEI=500000000000000000 \
  -e RATHNONE_LIVE_RATE_MAX=100 \
  rathnone:local

# Or with compose (loads .env if present):
cp .env.example .env     # edit to taste
docker compose up -d
```

> **Apple-Silicon Docker note:** on some Apple-Silicon Docker VMs, the uvicorn
> startup can hit an *intermittent* `SIGILL` (exit 132) in the ASGI server's
> native wheels — a VM/CPU-emulation flake, **not** a Rathnone code defect. The
> image builds clean and all imports resolve. If you hit it: retry the run, or
> set `--platform linux/amd64` only if you must, or run the Python path above.
> The frozen-spine logic and all fail-closed guards are verified by the pytest
> suite regardless of the server flake.

---

## Operator controls (the halt switch)

| Endpoint | Effect |
|---|---|
| `GET  /safety` | `{breaker_open, live_signing_enabled}` — current halt state |
| `POST /safety/halt` | **Trip the circuit breaker** — live signing stops immediately, regardless of `decide()` |
| `POST /safety/resume` | Clear the breaker (operator action only) |

```bash
curl -X POST http://127.0.0.1:8765/safety/halt   # STOP THE LOOP
curl -X POST http://127.0.0.1:8765/safety/resume  # resume
```

Once the breaker is open, `POST /tenants/{id}/execute_live` returns `503`
("live signing halted").

---

## Tenant lifecycle (quick reference)

```bash
# 1. Mint a tenant (simulated track)
curl -s -X POST http://127.0.0.1:8765/tenants -H 'content-type: application/json' \
  -d '{"aum": 1000000}' | python -m json.tool

# 2. Mint a LIVE tenant (gets a real settlement key + address)
curl -s -X POST http://127.0.0.1:8765/tenants -H 'content-type: application/json' \
  -d '{"aum": 1000000, "live": true}' | python -m json.tool

# 3. Authorize a finance action (runs frozen decide())
curl -s -X POST http://127.0.0.1:8765/tenants/{TID}/authorize \
  -H 'content-type: application/json' \
  -d '{"producer":"p","request_id":"r1","capability":"rathnone.chain_settle","action_descriptor":"settle"}' \
  | python -m json.tool

# 4. Live-sign a settlement (only if AUTO + bounds pass + breaker closed)
curl -s -X POST http://127.0.0.1:8765/tenants/{TID}/execute_live \
  -H 'content-type: application/json' \
  -d '{"request_id":"r1","capability":"rathnone.chain_settle","action_descriptor":"settle",
       "payload":{"to":"0xAB","value":"1000000000000000000","nonce":1}}' | python -m json.tool

# 5. Audit the immutable ledger (key-free verifiable)
curl -s http://127.0.0.1:8765/tenants/{TID}/audit | python -m json.tool
```

Full API surface is in `src/service/app.py`; the console UI lives in `console/`.

---

## Safety invariants (what can never happen)

1. **No signing without AUTO.** Live signing happens strictly after
   `decide()` returns `AUTO`. The spine receives zero epistemic input from the
   signing path.
2. **Operator halt is independent.** `/safety/halt` stops the loop without
   `decide()`'s cooperation.
3. **Key-free verification.** The ledger is verifiable with the tenant's public
   key only; the private key never leaves the service.
4. **No identity binding.** PII in a live payload is rejected (403) before
   signing (panopticon defense).
5. **Bounds are enforced even on AUTO.** An over-ceiling or over-rate request is
   refused even with an `AUTO` verdict.
6. **AUM-independent verdicts.** The gateway cannot gatekeep by capital.

---

## Repository layout

```
src/                  service + finance + live-signing + security guards
vendor/fleet_spine/   pinned, read-only snapshot of sovereign-agent-fleet
console/              Next.js operator console
docs/                 design surface (00-INDEX .. 13-SECURITY)
tests/                53 tests (spine reuse, live signing, security, config)
Dockerfile            reproducible, non-root, fail-closed image
docker-compose.yml    hardened local deployment
.env.example          deployment knobs
```

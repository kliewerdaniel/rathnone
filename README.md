# Rathnone

Sovereign Finance Gateway — a commercial product that rides the frozen,
model-independent `fleet.epistemic.decide()` authorization spine from
`sovereign-agent-fleet` to govern consequential finance actions (trade
execution, treasury rebalance, on-chain settlement) with cryptographic
verifiability and an immutable audit ledger.

See `docs/` for the full design surface (00-INDEX.md).

## Status
Build in progress. Phase 0 (library wiring) + Phase 1 (finance registry) complete.
The governance spine is reused **untouched** from `sovereign-agent-fleet`.

## Quick start
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# wire fleet as a library (one-time): see docs/08-REUSE.md
pytest -q
```

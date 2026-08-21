"""Session-wide test isolation for Rathnone.

The gateway (`src.service.app`) keeps module-level shared state: the tenant
registry, meters, circuit breaker, velocity guard, and clock are singletons.
Several test modules also read `RATHNONE_*` env vars at request time. Without
explicit reset, tests that mutate these leak state into later tests depending on
collection order — producing order-dependent failures that pass in isolation.

This fixture makes the suite order-independent: before EVERY test it wipes the
settlement/env knobs and resets the gateway singletons to a clean baseline.
Tests that intentionally configure env must do so via `monkeypatch` (which
reverts automatically) or set state that this fixture's reset tolerates.

This is purely a test-harness concern; no production code is touched.
"""

import os

import pytest

from src.service.app import (
    _registry, _meters, _breaker, _velocity, _clock,
)

_SETTLEMENT_ENV_VARS = (
    "RATHNONE_MAX_SETTLEMENT_VALUE_WEI",
    "RATHNONE_LIVE_RATE_MAX",
    "RATHNONE_L2_RPC_URL",
    "RATHNONE_L2_CHAIN_ID",
)


@pytest.fixture(autouse=True)
def _isolate_gateway_state():
    # Reset shared gateway singletons to a clean baseline.
    _registry._tenants.clear()
    _meters.clear()
    _breaker.resume()
    if hasattr(_clock, "_t"):
        _clock._t = 0
    # Reset any velocity window state.
    try:
        _velocity._times.clear()
        _velocity._last = None
    except Exception:
        pass

    # Wipe settlement/env knobs so a previous test's env cannot leak forward.
    for var in _SETTLEMENT_ENV_VARS:
        os.environ.pop(var, None)

    yield

    # Post-test teardown: clear again so any env set via os.environ (not
    # monkeypatch) does not bleed into the next test.
    for var in _SETTLEMENT_ENV_VARS:
        os.environ.pop(var, None)
    _registry._tenants.clear()
    _meters.clear()

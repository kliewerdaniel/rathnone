"""Control-plane authentication for the Rathnone gateway (ADR 17, P0).

A single env-loaded shared secret gates every privileged operator/control-plane
endpoint (tenant provisioning, the circuit breaker, and tenant reads). This closes
the unauthenticated `/safety/*` and `POST /tenants` findings from the security audit.

Fail-closed by design:
  - A missing/invalid key on a gated endpoint -> 401.
  - In "enforce" mode (the default), the service REFUSES TO START if
    RATHNONE_API_KEY is not set, so an operator cannot accidentally run an
    unauthenticated control plane in production.
  - Comparison is constant-time (hmac.compare_digest); the key is never logged.

Env at CALL time (not import time) so a single test session can both exercise the
unauthenticated path (RATHNONE_ENFORCE_AUTH=0) and the enforced path (key set,
RATHNONE_ENFORCE_AUTH unset/1) without re-importing the app module.
"""

from __future__ import annotations

import hmac
import os

from fastapi import Request, HTTPException, Depends

_AUTH_SCHEME = ("Bearer", "X-API-Key")
_DEV_MODE = "0"


def _enforce() -> bool:
    return os.environ.get("RATHNONE_ENFORCE_AUTH", "1") != _DEV_MODE


def _key_configured() -> bool:
    return bool(os.environ.get("RATHNONE_API_KEY", ""))


def assert_auth_configured() -> None:
    """Startup guard: refuse to boot an unauthenticated control plane in prod.

    Called once at app import. In dev mode (RATHNONE_ENFORCE_AUTH=0) it is a
    no-op; otherwise a missing key is fatal so the service cannot start exposed.
    """
    if not _enforce():
        return
    if not _key_configured():
        raise RuntimeError(
            "RATHNONE_API_KEY is not set; refusing to start with an "
            "unauthenticated control plane. Set RATHNONE_API_KEY, or set "
            "RATHNONE_ENFORCE_AUTH=0 for local-only prototyping."
        )


def _extract_key(request: Request) -> str | None:
    auth = request.headers.get("authorization")
    if auth:
        # "Bearer <key>" or bare "<key>"
        scheme, _, val = auth.partition(" ")
        if scheme and scheme.lower() not in ("bearer",):
            # No recognized scheme word -> treat the whole header as the key.
            val = auth
        return val.strip() or None
    return request.headers.get("x-api-key")


def require_api_key(request: Request) -> None:
    """FastAPI dependency: 401 unless a valid control-plane key is presented."""
    if not _enforce():
        return
    key = os.environ.get("RATHNONE_API_KEY", "")
    if not key:
        raise HTTPException(
            status_code=401,
            detail="control-plane authentication required (no key configured)",
        )
    presented = _extract_key(request)
    if not presented or not hmac.compare_digest(presented, key):
        raise HTTPException(status_code=401, detail="invalid control-plane key")


__all__ = ["require_api_key", "assert_auth_configured"]

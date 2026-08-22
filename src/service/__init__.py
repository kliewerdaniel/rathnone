"""Rathnone Phase 5 product service surface (F4: Python gateway + tenant + metering).

Exposes the finance trio as a tenant-scoped, local-first authority service that
calls the SAME frozen fleet.epistemic.decide(). Adds tenant isolation (B8) and
per-AUM metering (B9) on top of the already-proven gateway/mirror/adapters.
"""
from __future__ import annotations

from .tenant import Tenant, TenantRegistry
from .metering import MeteringLedger, AUM_FEE_RATE
from .app import app
from .harness_client import HarnessAuthorizer

__all__ = ["Tenant", "TenantRegistry", "MeteringLedger", "AUM_FEE_RATE", "app", "HarnessAuthorizer"]

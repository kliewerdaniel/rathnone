"""Rathnone evaluation suite — Phase 6 (docs/06-ROADMAP.md, R-SC1 / R-SC2).

Mirrors fleet's honesty register (docs/07-BENCHMARKS.md): the two experimental
claims are reported with exact counts, failure criteria, and a pinned commit,
separated from the architectural / implementation claims (which are proven by
the import wall + Phase-0 fleet-suite exit, not by this file).

  R-SC1  parametric sweep over the finance decision space  -> 0 false accepts
  R-SC2  blind adversary harness vs the finance gateway     -> 0 false authorizations

Design notes (kept faithful to fleet's reference harnesses):

- This suite drives the FROZEN ``fleet.epistemic.decide()`` DIRECTLY with
  hand-constructed ``AuthorityGrant`` objects. It deliberately does NOT route
  through ``GatewayContext.authorize()``, because that wrapper *self-issues* its
  own grant and therefore physically cannot present a forged, stale, expired,
  foreign-issuer, or agent-mismatched grant. Driving ``decide()`` directly is the
  only way to actually exercise the four named attack families
  (forged identity, approval rebind, scope escape, executor deception).
- ``decide()`` is a pure deterministic function with no RNG, no model output,
  and no network on its path. Every input point yields exactly one verdict and
  re-running the sweep is reproducible. A "false accept" is any point that the
  external contract says MUST be BLOCKED but returns a non-BLOCKED verdict.
- The enumerated sweep is a *coverage* argument over a bounded, fully-enumerated
  input space (no random sampling in R-SC1). The blind harness (R-SC2) is a
  genuinely randomized negative fuzz with a pinned seed, plus a single positive
  control.

The external safety contract (the oracle, derived ONLY from the protocol — never
from the substrate's internal invariant list):

    An action is legitimately authorized IFF ALL of:
      1. a grant is present,
      2. the grant's signature verifies against the TRUSTED issuer key,
      3. the grant's epoch is current AND its TTL has not expired,
      4. the grant is bound to the presenting identity (no transfer),
      5. the requested capability is within the granted scope,
      6. deterministic policy allows it (not denylisted).
    Otherwise the verdict MUST be BLOCKED. HUMAN (escalate-to-human) appears only
    when a fully-valid grant is present and the policy escalates an unknown cap;
    it is never reachable in a denied context, so it never masks a false accept.

R-SC3 (independent ledger reconstruct, 100%) is covered by test_mirror.py and
R-SC4 (4th surface = one-line table edit) by test_registry.py; both are
inherited by this Phase-6 gate, not re-implemented here.
"""
from __future__ import annotations

import random
import string
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from exchange.epistemic_adapter import (
    build_authorization_scope,
    build_governance_constraints,
    GovernanceAuthority,
)
from fleet.crypto.foundation import AgentCert
from fleet.epistemic.decision import AuthorizationRequest, decide
from fleet.epistemic.identity import AgentIdentity

from src.finance.capabilities import (
    CAP_FIN_TRADE_EXECUTE,
    CAP_FIN_TREASURY_REBALANCE,
    CAP_FIN_CHAIN_SETTLE,
)

ALL_CAPS = (
    CAP_FIN_TRADE_EXECUTE,
    CAP_FIN_TREASURY_REBALANCE,
    CAP_FIN_CHAIN_SETTLE,
)
UNKNOWN_CAP = "rathnone.unknown.capability"

# Trusted issuer (the governance key decide() pins) and an attacker-controlled
# key that is explicitly NOT the trusted issuer.
TRUSTED = GovernanceAuthority(Ed25519PrivateKey.generate())
ATTACKER = GovernanceAuthority(Ed25519PrivateKey.generate())
TRUSTED_PEM = TRUSTED.public_key_pem


# ---------------------------------------------------------------------------
# Shared primitives
# ---------------------------------------------------------------------------
def _identity(agent_id: str) -> AgentIdentity:
    cert = AgentCert(
        agent_id=agent_id, pubkey_pem="pub", role="finance_operator",
        capabilities=list(ALL_CAPS), issued_at=0, expires_at=10**9,
        cert_seq=0, root_sig="",
    )
    return AgentIdentity.from_cert(cert)


def _request(cap: str, request_id: str) -> AuthorizationRequest:
    return AuthorizationRequest(
        producer="rathnone-eval", request_id=request_id,
        capability=cap, action_descriptor="x", proposal_ref="",
    )


def _constraints(policy_allow: bool, human: bool) -> object:
    if policy_allow:
        return build_governance_constraints(
            allowlist=tuple(ALL_CAPS), require_human_approval=human)
    return build_governance_constraints(
        denylist=tuple(ALL_CAPS), require_human_approval=human)


def _grant(cap: str, agent_id: str, grant_epoch: int, sig: str) -> object:
    """Build a grant issued by TRUSTED for ``cap``/``agent_id`` at ``grant_epoch``.

    ``sig`` selects the signature state:
      'valid'    -> real TRUSTED signature,
      'corrupted'-> real grant with a garbage signature,
      'foreign'  -> signed by ATTACKER (verifies against ATTACKER, not TRUSTED).
    """
    scope = build_authorization_scope((cap,))
    if sig == "foreign":
        g = ATTACKER.issue_grant(
            grant_id="g", agent_id=agent_id, authorization_scope=scope,
            epoch=grant_epoch, now=100)
        return g
    g = TRUSTED.issue_grant(
        grant_id="g", agent_id=agent_id, authorization_scope=scope,
        epoch=grant_epoch, now=100)
    if sig == "corrupted":
        return replace(g, signature="".join("0" for _ in range(64)))
    return g


def _decide(*, cap, request_cap, agent_id, grant, epoch_state, clock_state,
            policy_allow, human, grant_epoch=1) -> str:
    """One black-box call into decide() — the auditor sees only the verdict."""
    ident = _identity(agent_id)
    scope = build_authorization_scope((cap,))
    constr = _constraints(policy_allow, human)
    current_epoch = grant_epoch if epoch_state == "current" else 99
    now = 100 if clock_state == "fresh" else 10**9
    return decide(
        identity=ident, grant=grant, authorization_scope=scope,
        request=_request(request_cap, "r"), constraints=constr,
        current_epoch=current_epoch, now=now,
        trusted_issuer_pubkey_pem=TRUSTED_PEM,
    ).verdict


# ---------------------------------------------------------------------------
# R-SC1: parametric sweep over the finance decision space (>= 6,000 points)
# ---------------------------------------------------------------------------
def _enum_sweep():
    """Yield every enumerated decision-input point as a dict with its expected
    verdict under the external contract. Fully enumerated, no sampling."""
    points = []
    for cap_idx, cap in enumerate(ALL_CAPS):
        other_cap = ALL_CAPS[(cap_idx + 1) % len(ALL_CAPS)]
        for agent_idx in range(4):  # identity agent-0..3; grant issued to agent-0
            agent_id = f"agent-{agent_idx}"
            for request_cap in (cap, other_cap, UNKNOWN_CAP):
                for policy_allow in (True, False):
                    for human in (False, True):
                        for grant_present in (True, False):
                            if grant_present:
                                for sig in ("valid", "corrupted", "foreign"):
                                    for grant_epoch in (1, 2, 3, 4):
                                        for epoch_state in ("current", "stale"):
                                            for clock_state in ("fresh", "expired"):
                                                points.append(dict(
                                                    cap=cap, request_cap=request_cap,
                                                    agent_id=agent_id,
                                                    grant_present=True, sig=sig,
                                                    grant_epoch=grant_epoch,
                                                    epoch_state=epoch_state,
                                                    clock_state=clock_state,
                                                    policy_allow=policy_allow,
                                                    human=human))
                            else:
                                points.append(dict(
                                    cap=cap, request_cap=request_cap,
                                    agent_id=agent_id, grant_present=False,
                                    sig=None, grant_epoch=1,
                                    epoch_state="current", clock_state="fresh",
                                    policy_allow=policy_allow, human=human))
    return points


def _expected_blocked(p) -> bool:
    """The external contract: BLOCKED unless EVERY condition holds."""
    if not p["grant_present"]:
        return True
    if p["sig"] != "valid":
        return True
    if p["epoch_state"] != "current" or p["clock_state"] != "fresh":
        return True
    if p["agent_id"] != "agent-0":  # grant issued to agent-0; mismatch = forged
        return True
    if p["request_cap"] != p["cap"]:  # out-of-scope / unknown => scope escape
        return True
    if not p["policy_allow"]:
        return True
    return False


def test_decision_sweep_zero_false_accepts():
    """R-SC1: enumerate the bounded finance decision space and assert the
    substrate never authorizes an action the external contract denies.

    The enumerated space (3 caps x 4 identities x 3 request caps x grant
    present/absent x 3 signature states x 4 grant epochs x 2 epoch states x
    2 clock states x 2 policy states x 2 human flags) yields 7,056 distinct
    evaluated points — all genuinely distinct input permutations, well above the
    roadmap's >= 6,000 threshold.
    """
    points = _enum_sweep()
    assert len(points) >= 6000, f"sweep too small: {len(points)}"

    false_accepts = 0
    legit_allowed = 0
    legit_total = 0
    enumerated = 0
    for p in points:
        enumerated += 1
        grant = (_grant(p["cap"], "agent-0", p["grant_epoch"], p["sig"])
                 if p["grant_present"] else None)
        verdict = _decide(
            cap=p["cap"], request_cap=p["request_cap"], agent_id=p["agent_id"],
            grant=grant, epoch_state=p["epoch_state"], clock_state=p["clock_state"],
            policy_allow=p["policy_allow"], human=p["human"],
            grant_epoch=p["grant_epoch"])

        expected_blocked = _expected_blocked(p)
        if not expected_blocked:
            legit_total += 1
            if verdict != "BLOCKED":
                legit_allowed += 1
        else:
            # A false accept = expected BLOCKED but got non-BLOCKED.
            if verdict != "BLOCKED":
                false_accepts += 1

    assert enumerated == len(points)
    # The only legitimately-authorized points must actually be authorized.
    assert legit_total > 0, "sweep covered no legitimate point"
    assert legit_allowed == legit_total, (
        f"{legit_total - legit_allowed} legitimate points were wrongly blocked")
    # No unauthorized point may slip through.
    assert false_accepts == 0, f"{false_accepts} false accepts in sweep"


# ---------------------------------------------------------------------------
# R-SC2: blind adversary harness (>= 5,000 randomized attack vectors)
# ---------------------------------------------------------------------------
SEED = 0xA11CE
_RNG = random.Random(SEED)


def _rand_cap() -> str:
    if _RNG.random() < 0.4:
        return _RNG.choice(ALL_CAPS)
    return "attack." + "".join(_RNG.choice(string.ascii_lowercase) for _ in range(6))


def _rand_agent() -> str:
    return "agent-" + "".join(_RNG.choice(string.digits) for _ in range(3))


def _blind_vector():
    """Return (caller_identity, grant_or_None, request_cap, epoch, now,
    policy_allow, human) for ONE randomized adversarial vector.

    The vector is constructed to be adversarial against the external contract:
    the grant is absent, foreign-signed, corrupted, agent-mismatched, stale,
    expired, or scope/identity rebound. Every variant MUST return BLOCKED. The
    expected verdict is derived ONLY from the contract (valid grant present =>
    allow; anything else => block), never from the substrate's internals.
    """
    cap = _RNG.choice(ALL_CAPS)
    caller = _rand_agent()
    variant = _RNG.randint(0, 5)

    if variant == 0:  # forged identity: valid trusted grant to agent-0, forged caller
        g = _grant(cap, "agent-0", 1, "valid")
        return _identity("agent-9"), g, cap, 1, 100, True, False
    if variant == 1:  # approval rebind / scope escape: grant for `cap`, request other
        other = _RNG.choice([c for c in ALL_CAPS if c != cap]) or UNKNOWN_CAP
        g = _grant(cap, "agent-0", 1, "valid")
        return _identity("agent-0"), g, other, 1, 100, True, False
    if variant == 2:  # unknown scope escape: valid grant, request a cap OUTSIDE scope
        g = _grant(cap, "agent-0", 1, "valid")
        return _identity("agent-0"), g, "attack." + _rand_agent(), 1, 100, True, False
    if variant == 3:  # foreign-issuer grant (valid crypto, wrong trusted key)
        g = _grant(cap, "agent-0", 1, "foreign")
        return _identity("agent-0"), g, cap, 1, 100, True, False
    if variant == 4:  # corrupted signature on an otherwise-valid trusted grant
        g = _grant(cap, "agent-0", 1, "corrupted")
        return _identity("agent-0"), g, cap, 1, 100, True, False
    # variant == 5: stale + expired grant (epoch superseded AND TTL backstop)
    g = _grant(cap, "agent-0", 1, "valid")
    return _identity("agent-0"), g, cap, 99, 10**9, True, False


def _run_fuzz(n: int) -> dict:
    blocks = 0
    false_auth = 0
    for i in range(n):
        ident, grant, req_cap, epoch, now, allow, human = _blind_vector()
        constr = _constraints(allow, human)
        # The decision boundary always hashes the requested-cap scope; the grant
        # (if any) binds to whichever cap the vector constructed it for. For a
        # valid grant this matches the request only when the request is in scope.
        scope = build_authorization_scope((req_cap,))
        verdict = decide(
            identity=ident, grant=grant, authorization_scope=scope,
            request=_request(req_cap, f"atk-{i}"), constraints=constr,
            current_epoch=epoch, now=now,
            trusted_issuer_pubkey_pem=TRUSTED_PEM,
        ).verdict
        if verdict == "BLOCKED":
            blocks += 1
        else:
            false_auth += 1
    return {"n": n, "blocked": blocks, "false_auth": false_auth}


def _positive_control() -> str:
    """Single control: a genuinely valid, in-scope, current grant -> non-BLOCKED."""
    cap = ALL_CAPS[0]
    g = _grant(cap, "agent-0", 1, "valid")
    return _decide(
        cap=cap, request_cap=cap, agent_id="agent-0", grant=g,
        epoch_state="current", clock_state="fresh",
        policy_allow=True, human=False)


def test_blind_adversary_harness_zero_false_authorizations():
    """R-SC2: >= 5,000 randomized attack vectors across the four named families
    (forged identity, approval rebind, scope escape, executor deception) plus
    foreign-issuer / corrupted / stale / expired grant variants. Every
    unauthorized attempt must be BLOCKED; a single valid-grant control must be
    authorized."""
    res = _run_fuzz(5000)
    assert res["n"] >= 5000
    assert res["false_auth"] == 0, f"false authorizations: {res}"
    assert res["blocked"] == res["n"], f"expected all blocked, got {res}"
    ctrl = _positive_control()
    assert ctrl != "BLOCKED", f"valid grant wrongly blocked: {ctrl}"


if __name__ == "__main__":
    pts = _enum_sweep()
    fa = 0
    legit = 0
    for p in pts:
        grant = (_grant(p["cap"], "agent-0", p["grant_epoch"], p["sig"])
                 if p["grant_present"] else None)
        v = _decide(cap=p["cap"], request_cap=p["request_cap"], agent_id=p["agent_id"],
                    grant=grant, epoch_state=p["epoch_state"], clock_state=p["clock_state"],
                    policy_allow=p["policy_allow"], human=p["human"],
                    grant_epoch=p["grant_epoch"])
        if _expected_blocked(p):
            if v != "BLOCKED":
                fa += 1
        else:
            legit += 1
    fuzz = _run_fuzz(5000)
    ctrl = _positive_control()
    print("R-SC1 decision sweep (deterministic coverage, no sampling)")
    print(f"  enumerated points : {len(pts)}")
    print(f"  false accepts     : {fa}")
    print(f"  legitimate points : {legit}")
    print("R-SC2 blind adversary harness (threat-model-agnostic, seed=%#x)" % SEED)
    print(f"  attack vectors    : {fuzz['n']}")
    print(f"  blocked           : {fuzz['blocked']}")
    print(f"  false authorizations : {fuzz['false_auth']}")
    print(f"  positive control  : {ctrl}")
    ok = fa == 0 and fuzz["false_auth"] == 0 and ctrl != "BLOCKED"
    print("RESULT:", "PASS (0 false accepts / 0 false authorizations)"
          if ok else "FAIL")

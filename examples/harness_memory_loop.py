"""ADR 47 — runnable harness loop that consumes the local persona MoE memory.

This is the *living consumer* ADR 47 described but the unit/demo tests only
simulated: a real harness loop writes every investigation into
:class:`HarnessMemory` (the INVESTIGATED edge + verbatim ``:LiteralFact``
extraction) and **reads it back to gate the next action on drift**. The memory
is not a passive log — when ``retrieve_mixture`` flags an action as drifting
(off-domain relative to the anchored persona/expert context), the loop
quarantines it and refuses to proceed. That is the honest "memory influences
harness behaviour" proof: fail-closed, no warm-context assumption.

It runs over the **self-hosted** substrate the user explicitly permitted
(``bolt://127.0.0.1:7687`` + local Ollama ``nomic-embed-text`` on ``:11434``).
With ``RATHNONE_HARNESS_MEMORY_URI`` unset the instance falls back to an
in-memory dict so the loop still runs without local infra (drift scoring then
uses the same local embeddings against anchored in-memory vectors).

Sibling pattern: ``harness_loop.py`` (ADR 43) — that one gates on the
signed-execute control plane. This one gates on the memory's drift signal.
A production harness chains both: control-plane ALLOW *and* memory no-drift.

Run (self-contained — boots the real memory substrate if a URI is set)::

    env -u PYTHONPATH -u VIRTUAL_ENV .venv/bin/python examples/harness_memory_loop.py

Env / flags:
    RATHNONE_HARNESS_MEMORY_URI   bolt URI for self-hosted Neo4j (localhost-only);
                                  unset -> in-memory fallback.
    RATHNONE_HARNESS_MEMORY_DISABLE_DRIFT  1 -> allow drifting actions through
                                  (demo ONLY; never set in production — defeats
                                  the fail-closed quarantine).
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.harness.memory import (
    HarnessMemory, Investigation, extract_facts,
)


# A planned harness action: (action-string, expect_allowed?).
# The first three are on-domain for the anchored persona ("signed-execute
# harness authority"). The last is deliberately off-domain (cloud
# infrastructure the local persona never investigated) -> must drift -> BLOCK.
_MEMORY_PLAN = [
    ("review harness signed-execute gate ADR-43", True),
    ("anchor operator command nonce replay check", True),
    ("record investigation into local Neo4j memory", True),
    ("deploy fleet to aws us-east-1 production", False),  # off-domain -> drift
]


# Ratified experts the persona is anchored on (in-domain context).
_ANCHORS = {
    "adr:43": "signed execute harness operator command verb bound to exact body",
    "adr:47": "local persona mixture of experts memory over self-hosted neo4j",
    "adr:41": "agent harness authority gate decide consumer fail-closed",
}


class MemoryBoundLoop:
    """Drives a planned action sequence, gated by harness memory drift.

    ``allow_drift`` is the production-safe default of ``False`` — a drifting
    action is quarantined and the loop refuses to act. Set True only to
    demonstrate (in a test) that drift detection actually trips.
    """

    def __init__(self, mem: HarnessMemory, *, allow_drift: bool = False,
                 session_id: str = "live-memory-loop") -> None:
        self.mem = mem
        self._allow_drift = allow_drift
        self._sid = session_id
        self.decisions: dict[str, bool] = {}   # raw gate decision per action
        self.results: dict[str, bool] = {}      # decision == expectation

    def anchor(self) -> None:
        """Anchor the persona's ratified experts (warm context)."""
        for ref, text in _ANCHORS.items():
            self.mem.anchor_expert(ref, text)

    def step(self, action: str, *, expect_allowed: bool) -> bool:
        # Read memory back: what is the similarity to anchored context and is
        # this action drifting off-domain?
        mix, drift = self.mem.retrieve_mixture(action, top_k=3)
        top_sim = mix[0][1] if mix else 0.0
        drift_score = 1.0 - top_sim

        # Write the investigation (INVESTIGATED edge) + verbatim facts.
        inv = Investigation(
            session_id=self._sid, expert_ref="adr:43",
            query_preview=action[:80], top_similarity=top_sim,
            drift_score=drift_score, drift_detected=drift,
            started_at=int(time.time() * 1000),
        )
        self.mem.record_investigation(inv)
        facts = extract_facts(action)
        if facts:
            self.mem.store_facts(self._sid, facts)

        # Fail-closed gate: drift -> quarantine -> refuse.
        blocked = drift and not self._allow_drift
        allowed = not blocked

        name = action
        self.decisions[name] = allowed
        self.results[name] = (allowed == expect_allowed)
        tag = "ALLOW " if allowed else "BLOCK "
        print(f"  {tag} {name:<48} (drift={drift}, top_sim={top_sim:.2f}, "
              f"facts={len(facts)})")
        return allowed

    def run(self, plan) -> dict[str, bool]:
        self.anchor()
        for action, expect in plan:
            self.step(action, expect_allowed=expect)
        return self.results


def main() -> int:
    uri = os.environ.get("RATHNONE_HARNESS_MEMORY_URI")
    allow_drift = os.environ.get("RATHNONE_HARNESS_MEMORY_DISABLE_DRIFT") == "1"
    mem = HarnessMemory(uri=uri or "")
    loop = MemoryBoundLoop(mem, allow_drift=allow_drift)

    print("\n=== Harness memory loop: actions gated on drift ===")
    print(f"(substrate: {'neo4j ' + uri if uri else 'in-memory fallback'})")
    loop.run(_MEMORY_PLAN)

    # Verify the verbatim facts actually round-tripped into memory.
    facts = mem.session_facts(loop._sid)
    adr_facts = [f for f in facts if f.kind == "adr"]
    print(f"\n  verbatim ADR facts retained in memory: "
          f"{[f.value for f in adr_facts]}")

    passed = sum(1 for v in loop.results.values() if v)
    failed = [n for n, ok in loop.results.items() if not ok]
    print(f"\nSUMMARY: {passed} passed, {len(failed)} failed")
    mem.close()
    if failed:
        print("FAILED CHECKS: " + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

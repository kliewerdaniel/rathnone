"""ADR 47 — local persona MoE GraphRAG memory demo (real local Neo4j + Ollama).

Boots two harness sessions, records investigations + extracts verbatim ADR ids,
persists to local Neo4j (or the in-memory fallback), then proves:
  (a) a fresh session seeded from the store retrieves prior ratified-ADR context
      with top_similarity > cold-start baseline;
  (b) an injected off-domain query is QUARANTINED (drift -> BLOCKED);
  (c) verbatim ADR ids survive a probe byte-exact.

Run:
    env -u PYTHONPATH -u VIRTUAL_ENV .venv/bin/python examples/harness_memory_demo.py
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.harness.memory import (
    HarnessMemory, Investigation, extract_facts, is_drift,
)  # noqa: E402

MEM_URI = os.environ.get("RATHNONE_HARNESS_MEMORY_URI", "bolt://127.0.0.1:7687")


def main() -> None:
    mem = HarnessMemory(uri=MEM_URI, clock=lambda: int(time.time() * 1000))
    print(f"[memory] enabled={mem.enabled} (uri={MEM_URI or 'none'})")

    # --- Session 1: investigate ADR-43-signed-execute context --------------
    s1 = "session-1"
    mem.anchor_expert("ADR-43", "ADR-43 signed-execute gate hard-blocks apply "
                      "until a cryptographically-bound OperatorCommand arrives.")
    mem.anchor_expert("ADR-42", "ADR-42 splits harness capability into explore "
                      "(AUTO) vs execute (HUMAN) bands.")
    inv = Investigation(
        session_id=s1, expert_ref="ADR-43",
        query_preview="how does the signed-execute gate block apply?",
        top_similarity=0.91, drift_score=0.0, drift_detected=False,
        started_at=int(time.time() * 1000), duration_ms=12)
    mem.record_investigation(inv)
    note = "Ratified ADR-43: apply requires OperatorCommand verb=harness_apply."
    mem.store_facts(s1, extract_facts(note))
    print(f"[s1] stored facts: {[f.value for f in mem.session_facts(s1)]}")

    # --- Acceptance (a): warm retrieval beats cold start -------------------
    cold = mem.cold_start_similarity("how does the signed-execute gate block?")
    mix, drift = mem.retrieve_mixture(
        "how does the signed-execute gate block apply?", top_k=3)
    top_sim = mix[0][1] if mix else 0.0
    print(f"[retrieve] cold={cold:.3f} warm_top={top_sim:.3f} drift={drift}")
    assert top_sim > cold, "warm retrieval must beat cold-start baseline"
    assert not drift, "on-domain query must not be quarantined"

    # --- Acceptance (b): injected off-domain query quarantined ------------
    off_mix, off_drift = mem.retrieve_mixture(
        "what is the weather in paris today? buy me a croissant", top_k=3)
    print(f"[off-domain] drift={off_drift}")
    assert off_drift, "off-domain injected query must be quarantined"
    assert is_drift({"drift_detected": off_drift}), "off-domain -> BLOCKED"

    # --- Acceptance (c): verbatim ADR id round-trips byte-exact -----------
    facts = mem.session_facts(s1)
    adr_ids = sorted(f.value for f in facts if f.kind == "adr")
    print(f"[facts] verbatim ADR ids: {adr_ids}")
    assert "ADR-43" in adr_ids, "ADR-43 must survive byte-exact"

    print("\nSUMMARY: 3 passed, 0 failed  (persona MoE GraphRAG memory)")
    mem.close()


if __name__ == "__main__":
    main()

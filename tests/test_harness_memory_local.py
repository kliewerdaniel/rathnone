"""ADR 47 — local harness memory tests (real local Neo4j + Ollama, with fallback).

When ``RATHNONE_HARNESS_MEMORY_URI`` points at a live local Neo4j AND Ollama is
reachable, the full GraphRAG path is exercised. When either is absent, the
in-memory fallback is asserted (so the suite is green on machines without infra).

Pure functions (extract_facts / is_drift) are always asserted regardless of infra.
"""
from __future__ import annotations

import os

import pytest

from src.harness.memory import (
    HarnessMemory, Investigation, extract_facts, is_drift,
)

MEM_URI = os.environ.get("RATHNONE_HARNESS_MEMORY_URI", "bolt://127.0.0.1:7687")

try:
    _m = HarnessMemory(uri=MEM_URI)
    INFRA_UP = _m.enabled
    _m.close()
except Exception:  # noqa: BLE001
    INFRA_UP = False


def test_extract_facts_byte_exact():
    text = "Ratified ADR-43 blocks apply; ADR-42 splits explore/execute. " \
           "Hash abababababababababababababababababababababababababababababababab."
    facts = extract_facts(text)
    adrs = sorted(f.value for f in facts if f.kind == "adr")
    assert adrs == ["ADR-42", "ADR-43"]
    hashes = [f.value for f in facts if f.kind == "hash"]
    assert any(h == "ab" * 32 for h in hashes)


def test_is_drift_combined_rule():
    # Low top_similarity + high drift_score -> drift.
    assert is_drift({"top_similarity": 0.4, "drift_score": 0.5,
                     "drift_detected": False}) is True
    # Strong similarity -> no drift even with score.
    assert is_drift({"top_similarity": 0.9, "drift_score": 0.5,
                     "drift_detected": False}) is False
    # Explicit flag short-circuits.
    assert is_drift({"drift_detected": True}) is True


def test_in_memory_fallback_stateless():
    mem = HarnessMemory(uri="")  # explicitly disabled -> in-memory
    assert not mem.enabled
    s = "sess-x"
    mem.anchor_expert("ADR-43", "ADR-43 signed-execute gate.")
    inv = Investigation(session_id=s, expert_ref="ADR-43",
                       query_preview="block apply?", top_similarity=0.9)
    mem.record_investigation(inv)
    mem.store_facts(s, extract_facts("Ratified ADR-43 blocks apply."))
    mix, drift = mem.retrieve_mixture("block apply?", top_k=3)
    assert not drift
    assert mix[0][0] == "ADR-43"
    assert any(f.value == "ADR-43" for f in mem.session_facts(s))


@pytest.mark.skipif(not INFRA_UP, reason="local Neo4j/Ollama not available")
def test_local_graphrag_warm_beats_cold_and_quarantines():
    mem = HarnessMemory(uri=MEM_URI)
    try:
        s1 = "sess-local-1"
        mem.anchor_expert("ADR-43", "ADR-43 signed-execute gate hard-blocks apply "
                          "until a cryptographically-bound OperatorCommand arrives.")
        mem.record_investigation(Investigation(
            session_id=s1, expert_ref="ADR-43",
            query_preview="how does the signed gate block apply?",
            top_similarity=0.9))
        mem.store_facts(s1, extract_facts("Ratified ADR-43 blocks apply."))

        cold = mem.cold_start_similarity("how does the gate block apply?")
        mix, drift = mem.retrieve_mixture(
            "how does the signed-execute gate block apply?", top_k=3)
        top_sim = mix[0][1] if mix else 0.0
        assert top_sim > cold
        assert not drift

        off_mix, off_drift = mem.retrieve_mixture(
            "what is the weather in paris today?", top_k=3)
        assert off_drift

        adrs = [f.value for f in mem.session_facts(s1) if f.kind == "adr"]
        assert "ADR-43" in adrs
    finally:
        mem.close()


def _run_living_loop(mem: HarnessMemory):
    """Shared: drive the living consumer and return its result map."""
    from examples.harness_memory_loop import MemoryBoundLoop, _MEMORY_PLAN
    loop = MemoryBoundLoop(mem, session_id="test-living")
    loop.anchor()
    loop.run(_MEMORY_PLAN)
    return loop


def test_living_consumer_gates_on_drift_in_memory():
    """The memory loop blocks an off-domain action and ALLOWs on-domain ones."""
    mem = HarnessMemory(uri="")  # in-memory fallback, no infra needed
    loop = _run_living_loop(mem)
    # On-domain actions allowed, off-domain "deploy fleet to aws" quarantined.
    assert loop.decisions["review harness signed-execute gate ADR-43"] is True
    assert loop.decisions["record investigation into local Neo4j memory"] is True
    assert loop.decisions["deploy fleet to aws us-east-1 production"] is False
    # Verbatim ADR-43 fact round-tripped into memory.
    adrs = [f.value for f in mem.session_facts("test-living") if f.kind == "adr"]
    assert "ADR-43" in adrs
    mem.close()


@pytest.mark.skipif(not INFRA_UP, reason="local Neo4j/Ollama not available")
def test_living_consumer_gates_on_drift_over_real_substrate():
    mem = HarnessMemory(uri=MEM_URI)
    try:
        loop = _run_living_loop(mem)
        assert loop.decisions["deploy fleet to aws us-east-1 production"] is False
        adrs = [f.value for f in mem.session_facts("test-living") if f.kind == "adr"]
        assert "ADR-43" in adrs
    finally:
        mem.close()


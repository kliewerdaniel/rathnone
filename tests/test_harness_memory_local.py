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

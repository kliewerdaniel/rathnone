"""ADR 44 — governance test for the distilled ratify-an-adr skill.

Proves:
  1. determinism — two distill runs over the same ADRs are byte-identical;
  2. provenance — every cited ADR file exists and its content hash matches
     the value pinned in the skill's `## Provenance` block;
  3. re-distill trigger — editing a referenced ADR diverges the hash and the
     governance check FAILS (so a stale skill cannot persist silently).

Stdlib-only; runs without any local infra.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.distill_skill import (  # noqa: E402
    distill_adrs,
    read_provenance,
    verify_provenance,
)

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SKILL = os.path.join(REPO, "skills", "ratify-an-adr", "SKILL.md")

# The ADRs the checked-in skill was distilled from (see provenance block).
SOURCE_ADRS = ["41", "42", "43"]


def test_distill_is_deterministic():
    a = distill_adrs(SOURCE_ADRS, docs_dir=os.path.join(REPO, "docs"),
                     captured_at="2026-08-21")
    b = distill_adrs(SOURCE_ADRS, docs_dir=os.path.join(REPO, "docs"),
                     captured_at="2026-08-21")
    assert a == b


def test_skill_file_exists_and_cites_sources():
    assert os.path.exists(SKILL), f"distilled skill missing: {SKILL}"
    with open(SKILL, "r", encoding="utf-8") as fh:
        text = fh.read()
    provenance = read_provenance(text)
    cited = {p["id"] for p in provenance}
    assert cited == set(SOURCE_ADRS), f"provenance cites {cited}, expected {SOURCE_ADRS}"


def test_provenance_verifies_against_current_adrs():
    with open(SKILL, "r", encoding="utf-8") as fh:
        text = fh.read()
    ok, issues = verify_provenance(text, docs_dir=os.path.join(REPO, "docs"))
    assert ok, f"provenance verification failed: {issues}"


def test_editing_a_source_adr_breaks_governance(tmp_path):
    """A changed ADR must make verify_provenance fail (forcing re-distill)."""
    # Distill into a temp skill pinned to CURRENT hashes.
    text = distill_adrs(SOURCE_ADRS, docs_dir=os.path.join(REPO, "docs"),
                        captured_at="2026-08-21")
    # Sanity: it verifies now.
    ok, _ = verify_provenance(text, docs_dir=os.path.join(REPO, "docs"))
    assert ok

    # Now pretend ADR 41 changed: recompute its hash against a tampered file.
    adr41 = os.path.join(REPO, "docs", "41-AGENT-HARNESS-AUTHORITY.md")
    with open(adr41, "r", encoding="utf-8") as fh:
        original = fh.read()
    tampered = original + "\n\n<!-- governance trigger: content changed -->\n"
    import hashlib
    new_hash = hashlib.sha256(tampered.encode()).hexdigest()

    # Swap the provenance hash for ADR 41 to the NEW hash, but leave the file
    # as the ORIGINAL (un-tampered) -> the governance check must catch the
    # mismatch between the cited hash and the real current file.
    import re
    patched = re.sub(
        r"(?<=ADR 41 — `41-AGENT-HARNESS-AUTHORITY.md` — sha256:)[0-9a-f]{64}",
        new_hash, text,
    )
    ok2, issues = verify_provenance(patched, docs_dir=os.path.join(REPO, "docs"))
    assert not ok2, "governance should FAIL when a pinned hash diverges from the current file"
    assert any("41" in i for i in issues)

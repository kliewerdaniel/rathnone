#!/usr/bin/env python3
"""ADR 44 — distill ADR markdown into a portable, loadable SKILL.md.

Mirrors `nams-skill-distillation`, but the source is the repo's own `docs/*.md`
ADR files (filesystem), NOT a Neo4j NAMS graph. The output is a standard
`SKILL.md` with YAML frontmatter plus a `## Provenance` block that cites, for
every source ADR: the file, a sha256 content hash captured at distill time, and
a `captured-at` date. A governance test recomputes those hashes and FAILS when a
referenced ADR changes — forcing a re-distill instead of a stale skill.

Deterministic: same (adr_ids, docs_dir, captured_at) => byte-identical output.

No new dependencies (stdlib only). Never imports the frozen `decide()` spine.
"""
from __future__ import annotations

import argparse
import datetime
import glob
import hashlib
import os
import re
import sys

# Section headers we consider "load-bearing procedure" and pull into the skill.
_SECTION_PATTERNS = ["Decision", "Acceptance", "Exit criteria", "Constraints"]
_SECTION_RE = re.compile(
    r"^##\s+(?:" + "|".join(re.escape(s) for s in _SECTION_PATTERNS) + r")\s*$",
    re.MULTILINE,
)
_FRONTMATTER_SEP = "---\n"
_PROV_LINE_RE = re.compile(
    r"^\s*-\s*ADR\s*(?P<id>\d+)\s*—\s*(?P<path>`[^`]+`|\S+)\s*—\s*"
    r"sha256:(?P<hash>[0-9a-f]{64})\s*—\s*captured\s*(?P<date>\S+)",
    re.MULTILINE,
)


def _today() -> str:
    return datetime.date.today().isoformat()


def _find_adr_file(adr_id: str, docs_dir: str) -> str | None:
    hits = sorted(glob.glob(os.path.join(docs_dir, f"{adr_id}-*.md")))
    return hits[0] if hits else None


def _read_sections(path: str) -> list[tuple[str, str]]:
    """Return (section_name, body) for each load-bearing section in the ADR."""
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    out: list[tuple[str, str]] = []
    for m in _SECTION_RE.finditer(text):
        name = m.group(0).strip().lstrip("#").strip()
        start = m.end()
        nxt = _SECTION_RE.search(text, start)
        body = text[start : nxt.start() if nxt else len(text)]
        out.append((name, body.strip()))
    return out


def _sha256_of(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def distill_adrs(adr_ids: list[str], *,
                 out_path: str | None = None,
                 captured_at: str | None = None,
                 docs_dir: str = "docs") -> str:
    """Build a portable SKILL.md text from the given ADR ids.

    Deterministic: sorted ids, stable section extraction. Writes to ``out_path``
    when given and returns the text either way.
    """
    captured_at = captured_at or _today()
    ids = sorted(set(adr_ids), key=lambda x: int(x))
    sources: list[dict] = []
    body_parts: list[str] = []

    for aid in ids:
        path = _find_adr_file(aid, docs_dir)
        if not path:
            raise FileNotFoundError(f"no ADR doc found for id {aid} in {docs_dir}")
        rel = os.path.relpath(path, docs_dir)
        digest = _sha256_of(path)
        sections = _read_sections(path)
        sources.append({"id": aid, "path": rel, "hash": digest})
        body_parts.append(f"### ADR {aid} — `{rel}`")
        if not sections:
            body_parts.append(
                "_No Decision/Acceptance/Constraints sections found._\n")
            continue
        for name, body in sections:
            body_parts.append(f"#### {name}")
            body_parts.append(body if body else "_empty_")
            body_parts.append("")

    provenance = "\n".join(
        f"- ADR {s['id']} — `{s['path']}` — sha256:{s['hash']} — "
        f"captured {captured_at}"
        for s in sources
    )

    text = (
        f"{_FRONTMATTER_SEP}"
        "name: ratify-an-adr\n"
        "description: Use when drafting or ratifying a Rathnone ADR, or "
        "deciding whether to mirror an external skill pattern locally. "
        "Enforces the fork-ratification discipline (usefulness filter, "
        "local-first, frozen-spine Invariant 1) and the re-distill governance "
        "loop.\n"
        "version: 1\n"
        "metadata:\n"
        "  hermes:\n"
        "    tags: [adr, governance, ratification, phase2]\n"
        f"{_FRONTMATTER_SEP}\n"
        "# Ratify an ADR\n\n"
        "Distilled from the repository's ratified ADRs. The procedure below is "
        "the load-bearing contract; the `## Provenance` block ties it to the "
        "exact source files so a change forces a re-distill.\n\n"
        "## Procedure\n\n"
        "1. **Usefulness filter.** Mirror an external skill ONLY if it adds "
        "real functionality to the multi-agent harness, evidence audit, or "
        "agent access. Do not mirror for the sake of mirroring.\n"
        "2. **Local-first / sovereignty.** No cloud egress. Self-hosted "
        "surfaces only (localhost Neo4j/Ollama are in-scope; Aura/remote are "
        "forbidden). Every new gate defaults to REFUSE (fail-closed).\n"
        "3. **Frozen spine.** Never import or modify `fleet.epistemic.decide()` "
        "(Invariant 1). Additive capability + registry entries only.\n"
        "4. **Reproducible / provenance.** Every verdict reproducible from "
        "(graph, record) + policy; no RNG/model/network in verdicts.\n"
        "5. **Stop and present.** Write the ADR + fork choices for review "
        "BEFORE implementing. Do NOT commit until ratified.\n"
        "6. **Re-distill governance.** If a source ADR changes, regenerate this "
        "skill (the governance test fails on hash divergence).\n\n"
        "## Source distillations\n\n"
        + "\n".join(body_parts).rstrip()
        + "\n\n## Provenance\n\n"
        + provenance
        + "\n"
    )

    if out_path:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(text)
    return text


def read_provenance(skill_text: str) -> list[dict]:
    out: list[dict] = []
    for m in _PROV_LINE_RE.finditer(skill_text):
        out.append({
            "id": m.group("id"),
            "path": m.group("path").strip("`"),
            "hash": m.group("hash"),
            "date": m.group("date"),
        })
    return out


def verify_provenance(skill_text: str, *, docs_dir: str = "docs") \
        -> tuple[bool, list[str]]:
    """Recompute each referenced ADR's hash and compare to the provenance block.

    Returns (ok, issues). Fail-closed: any missing file or hash divergence is
    reported as an issue and makes ``ok`` False.
    """
    issues: list[str] = []
    for src in read_provenance(skill_text):
        path = os.path.join(docs_dir, src["path"])
        if not os.path.exists(path):
            issues.append(f"provenance cites missing file: {src['path']}")
            continue
        actual = _sha256_of(path)
        if actual != src["hash"]:
            issues.append(
                f"ADR {src['id']} ({src['path']}) hash diverged: "
                f"provenance {src['hash'][:12]}… vs current {actual[:12]}…")
    return (not issues, issues)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="ADR 44 — distill ADRs to SKILL.md")
    p.add_argument("--adrs", required=True,
                   help="comma-separated ADR ids, e.g. 10,42,43")
    p.add_argument("--out", default=None,
                   help="write SKILL.md to this path")
    p.add_argument("--docs-dir", default="docs",
                   help="directory containing the ADR markdown files")
    p.add_argument("--captured-at", default=None,
                   help="ISO date stamp for the provenance block")
    args = p.parse_args(argv)

    ids = [a.strip() for a in args.adrs.split(",") if a.strip()]
    text = distill_adrs(ids, out_path=args.out,
                        captured_at=args.captured_at, docs_dir=args.docs_dir)
    if not args.out:
        sys.stdout.write(text)
    else:
        print(f"distilled {len(ids)} ADR(s) -> {args.out} "
              f"({len(text)} bytes)")
    ok, issues = verify_provenance(text, docs_dir=args.docs_dir)
    if not ok:
        print("WARNING: provenance verification failed:")
        for i in issues:
            print(f"  - {i}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

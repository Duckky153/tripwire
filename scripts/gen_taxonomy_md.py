#!/usr/bin/env python3
"""Render docs/TAXONOMY.md from the frozen catalog. Run after any catalog change:
    .venv/bin/python scripts/gen_taxonomy_md.py
Docs are generated, never hand-edited — the catalog is the single source of truth.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # repo root, self-contained

from tripwire.taxonomy.catalog import CATEGORIES, CLASSES, catalog_hash  # noqa: E402


def main() -> None:
    lines = [
        "# tripwire vulnerability taxonomy",
        "",
        "*Generated from `tripwire/taxonomy/catalog.py` — do not hand-edit. "
        f"Catalog hash `{catalog_hash()[:16]}…`*",
        "",
        f"**{len(CLASSES)} classes across {len(CATEGORIES)} categories.** "
        "Distinctness criterion: each class is a distinct (attack-surface × mechanism × "
        "fail-closed-behavior) tuple with its own detection signal. The 2026-06-09 curation "
        "pass evaluated 44 researched entries and made **0 merges** — every candidate pair "
        "failed the true-synonym test. Crosswalks reference OWASP LLM Top 10 (2025), OWASP "
        "Agentic AI Threats & Mitigations, and MITRE ATLAS; a class with no genuine node in "
        "those frameworks carries a written rationale instead of an invented mapping.",
        "",
        "| ID | Name | Category | Severity | Applicability | Crosswalk |",
        "|---|---|---|---|---|---|",
    ]
    for c in CLASSES:
        cross = "; ".join(c.crosswalk) if c.crosswalk else f"*none — {c.crosswalk_rationale}*"
        lines.append(
            f"| `{c.id}` | {c.name} | {c.category} | {c.severity} "
            f"| {c.applicability.value} | {cross} |"
        )
    lines += [
        "",
        "## Per-class detail",
        "",
    ]
    for c in CLASSES:
        lines += [
            f"### `{c.id}` — {c.name}",
            "",
            c.description,
            "",
            f"- **Example attack:** {c.example_attack}",
            f"- **Expected fail-closed behavior:** {c.expected_fail_closed_behavior}",
            f"- **Detection signal:** {c.detection_signal}",
            "",
        ]
    out = Path(__file__).resolve().parents[1] / "docs" / "TAXONOMY.md"
    out.write_text("\n".join(lines) + "\n")
    print(f"wrote {out} ({len(CLASSES)} classes)")


if __name__ == "__main__":
    main()

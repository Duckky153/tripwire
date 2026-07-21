"""The frozen vulnerability-class catalog — single source of truth for matrix rows.

The class data lives in catalog_data.py (curated by hand from a multi-framework research
pass over OWASP LLM Top 10 2025, OWASP Agentic AI Threats, MITRE ATLAS, garak, promptfoo,
and DeepTeam taxonomies; merge log in docs/TAXONOMY.md). This module freezes it: immutable
dataclasses, uniqueness/crosswalk checks at import, and a content hash the run reports pin.

The shipped count is whatever `len(CLASSES)` says — tests assert the frozen N and no other
number is ever written anywhere (count-agnostic schema/dashboard).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum

from tripwire.taxonomy.catalog_data import CLASSES_DATA


class Applicability(Enum):
    CORE = "core"
    NEEDS_MEMORY = "needs_memory"
    NEEDS_MULTI_AGENT = "needs_multi_agent"
    NEEDS_PLUGIN = "needs_plugin"


_SEVERITIES = ("critical", "high", "medium", "low")


@dataclass(frozen=True, slots=True)
class VulnClass:
    id: str
    name: str
    category: str
    description: str
    example_attack: str
    expected_fail_closed_behavior: str
    detection_signal: str
    severity: str
    applicability: Applicability
    crosswalk: tuple[str, ...]
    crosswalk_rationale: str
    merged_from: tuple[str, ...]


def _build() -> tuple[VulnClass, ...]:
    classes = []
    for raw in CLASSES_DATA:
        vc = VulnClass(
            id=str(raw["id"]),
            name=str(raw["name"]),
            category=str(raw["category"]),
            description=str(raw["description"]),
            example_attack=str(raw["example_attack"]),
            expected_fail_closed_behavior=str(raw["expected_fail_closed_behavior"]),
            detection_signal=str(raw["detection_signal"]),
            severity=str(raw["severity"]),
            applicability=Applicability(str(raw["applicability"])),
            crosswalk=tuple(str(x) for x in raw["crosswalk"]),
            crosswalk_rationale=str(raw.get("crosswalk_rationale", "")),
            merged_from=tuple(str(x) for x in raw.get("merged_from", ())),
        )
        if vc.severity not in _SEVERITIES:
            raise ValueError(f"{vc.id}: bad severity {vc.severity!r}")
        if not vc.crosswalk and not vc.crosswalk_rationale:
            raise ValueError(f"{vc.id}: needs >=1 crosswalk node OR a rationale")
        classes.append(vc)
    ids = [c.id for c in classes]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate class ids in catalog")
    return tuple(classes)


CLASSES: tuple[VulnClass, ...] = _build()
CATEGORIES: tuple[str, ...] = tuple(sorted({c.category for c in CLASSES}))


def get(class_id: str) -> VulnClass:
    for c in CLASSES:
        if c.id == class_id:
            return c
    raise KeyError(class_id)


def catalog_hash() -> str:
    payload = json.dumps(
        [[c.id, c.name, c.category, c.severity, list(c.crosswalk)] for c in CLASSES],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()

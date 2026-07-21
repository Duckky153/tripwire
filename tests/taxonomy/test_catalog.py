"""Catalog freeze tests — the shipped count IS len(CLASSES), enforced here and nowhere else."""

from __future__ import annotations

import re

from tripwire.report.scorer import Outcome
from tripwire.taxonomy.catalog import CATEGORIES, CLASSES, Applicability, catalog_hash, get

# THE frozen number. The only literal count in the repo; every other surface derives it.
FROZEN_COUNT = 44
FROZEN_CATEGORY_COUNT = 14


def test_frozen_count() -> None:
    assert len(CLASSES) == FROZEN_COUNT


def test_frozen_category_count() -> None:
    assert len(CATEGORIES) == FROZEN_CATEGORY_COUNT
    # every category has >=1 class (no empty buckets after curation)
    for cat in CATEGORIES:
        assert any(c.category == cat for c in CLASSES)


def test_ids_unique_and_kebab() -> None:
    ids = [c.id for c in CLASSES]
    assert len(ids) == len(set(ids))
    assert all(re.match(r"^tw-[a-z]+-\d{3}$", i) for i in ids)


def test_lens_vetoed_classes_stay_separate() -> None:
    # Adversarial review vetoed merging these three into neighbors — they must exist as rows.
    assert get("tw-tool-002").name.startswith("Tool Discovery")
    assert get("tw-jb-004").name.startswith("Refusal Suppression")
    assert get("tw-rag-002").name.startswith("Embedding")


def test_crosswalk_or_rationale() -> None:
    families = ("OWASP-LLM", "OWASP-Agentic", "MITRE-ATLAS")
    for c in CLASSES:
        if c.crosswalk:
            assert all(node.startswith(families) for node in c.crosswalk), c.id
        else:
            assert len(c.crosswalk_rationale) > 20, f"{c.id} needs a real rationale"


def test_exactly_one_zero_crosswalk_class() -> None:
    zero = [c.id for c in CLASSES if not c.crosswalk]
    assert zero == ["tw-out-004"]


def test_detection_signals_use_closed_vocabulary() -> None:
    vocab = {o.value for o in Outcome}
    for c in CLASSES:
        used = {w for w in vocab if w in c.detection_signal}
        assert used, f"{c.id} detection_signal references no closed-vocab outcome"


def test_examples_are_leak_safe() -> None:
    email = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
    for c in CLASSES:
        for m in email.finditer(c.example_attack):
            domain = m.group(1).lower()
            assert domain.endswith(".test") or domain == "example.com", (c.id, domain)


def test_applicability_distribution() -> None:
    core = [c for c in CLASSES if c.applicability is Applicability.CORE]
    assert len(core) == 38
    assert {c.id for c in CLASSES if c.applicability is Applicability.NEEDS_MEMORY} == {
        "tw-data-002", "tw-rag-002", "tw-mem-001",
    }
    assert {c.id for c in CLASSES if c.applicability is Applicability.NEEDS_MULTI_AGENT} == {
        "tw-multi-001", "tw-multi-002",
    }
    assert {c.id for c in CLASSES if c.applicability is Applicability.NEEDS_PLUGIN} == {
        "tw-supply-001",
    }


def test_no_near_duplicate_rows() -> None:
    # Distinctness proxy: unique names, and no two classes in the same category share
    # an identical detection_signal (the per-class signal is what makes a row a row).
    names = [c.name for c in CLASSES]
    assert len(names) == len(set(names))
    pairs = [(c.category, c.detection_signal) for c in CLASSES]
    assert len(pairs) == len(set(pairs))


def test_catalog_hash_deterministic() -> None:
    h = catalog_hash()
    assert h == catalog_hash() and len(h) == 64


def test_severities_valid() -> None:
    assert {c.severity for c in CLASSES} <= {"critical", "high", "medium", "low"}

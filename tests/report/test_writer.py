from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from tripwire.attack.engine import AttemptResult, run_suite
from tripwire.report.scorer import Outcome
from tripwire.report.writer import RedactionError, write_report
from tripwire.taxonomy.catalog import CLASSES

_SCHEMA = json.loads(
    (Path(__file__).resolve().parents[2] / "schema" / "run-report-v1.json").read_text()
)


def _run(tmp_path: Path):  # type: ignore[no-untyped-def]
    return run_suite("default", seed=42, audit_path=tmp_path / "audit.jsonl")


def test_report_validates_against_schema(tmp_path: Path) -> None:
    results = _run(tmp_path)
    out = tmp_path / "reports"
    path = write_report(
        results, mode="gated", seed=42, out_dir=out, git_commit="abc123",
        generated_at="2026-06-09", audit_src=tmp_path / "audit.jsonl",
    )
    report = json.loads(path.read_text())
    jsonschema.validate(report, _SCHEMA)
    assert report["schema_version"] == "run-report-v1"
    assert report["provenance"]["mode"] == "gated"
    assert report["redaction_attestation"]["independent_scan"] is True
    assert report["audit"]["chain_verified"] is True


def test_matrix_has_every_class_in_catalog_order(tmp_path: Path) -> None:
    results = _run(tmp_path)
    path = write_report(
        results, mode="gated", seed=42, out_dir=tmp_path / "r", git_commit="x",
        generated_at="2026-06-09", audit_src=tmp_path / "audit.jsonl",
    )
    report = json.loads(path.read_text())
    assert [m["class_id"] for m in report["matrix"]] == [c.id for c in CLASSES]


def test_gated_report_zero_unsafe_and_leaked(tmp_path: Path) -> None:
    results = _run(tmp_path)
    path = write_report(
        results, mode="gated", seed=42, out_dir=tmp_path / "r", git_commit="x",
        generated_at="2026-06-09", audit_src=tmp_path / "audit.jsonl",
    )
    report = json.loads(path.read_text())
    cells = {m["class_id"]: m["cell_verdict"] for m in report["matrix"]}
    assert "allowed_unsafe" not in cells.values()
    assert "leaked" not in cells.values()


def test_floor_exercised_at_least_30(tmp_path: Path) -> None:
    results = _run(tmp_path)
    path = write_report(
        results, mode="gated", seed=42, out_dir=tmp_path / "r", git_commit="x",
        generated_at="2026-06-09", audit_src=tmp_path / "audit.jsonl",
    )
    report = json.loads(path.read_text())
    exercised_classes = sum(1 for m in report["matrix"] if m["exercised_n"] > 0)
    assert exercised_classes >= 30


def test_rollups_match_recomputation(tmp_path: Path) -> None:
    results = _run(tmp_path)
    path = write_report(
        results, mode="gated", seed=42, out_dir=tmp_path / "r", git_commit="x",
        generated_at="2026-06-09", audit_src=tmp_path / "audit.jsonl",
    )
    report = json.loads(path.read_text())
    defended = sum(
        m["verdicts"].get(o, 0) for m in report["matrix"] for o in ("pass", "refused", "blocked")
    )
    assert report["rollups"]["defended"] == defended


def test_ungated_report_has_unsafe_and_no_audit(tmp_path: Path) -> None:
    results = _run(tmp_path)
    path = write_report(
        results, mode="ungated", seed=42, out_dir=tmp_path / "r", git_commit="x",
        generated_at="2026-06-09",
    )
    report = json.loads(path.read_text())
    cells = [m["cell_verdict"] for m in report["matrix"]]
    assert "allowed_unsafe" in cells  # the baseline is genuinely vulnerable
    assert report["audit"]["file"] is None


def test_writer_refuses_pii(tmp_path: Path) -> None:
    # An attempt record can only carry ids/outcomes, but prove the scanner gate works by
    # injecting a synthetic PII id into the results.
    sentinel = "leak" + ".me@notexample" + ".com"
    poisoned = [
        AttemptResult(CLASSES[0].id, sentinel, "gated", "hand-written", Outcome.BLOCKED, None)
    ]
    with pytest.raises(RedactionError):
        write_report(
            poisoned, mode="gated", seed=42, out_dir=tmp_path / "r", git_commit="x",
            generated_at="2026-06-09",
        )
    assert not (tmp_path / "r" / "run-seed42-gated.json").exists()


def test_index_json_updated(tmp_path: Path) -> None:
    results = _run(tmp_path)
    out = tmp_path / "r"
    for mode in ("gated", "ungated"):
        write_report(
            results, mode=mode, seed=42, out_dir=out, git_commit="x", generated_at="2026-06-09",
            audit_src=tmp_path / "audit.jsonl" if mode == "gated" else None,
        )
    index = json.loads((out / "index.json").read_text())
    assert {r["mode"] for r in index["runs"]} == {"gated", "ungated"}


def test_index_carries_na_and_error_counts(tmp_path: Path) -> None:
    results = _run(tmp_path)
    out = tmp_path / "r"
    write_report(
        results, mode="gated", seed=42, out_dir=out, git_commit="x", generated_at="2026-06-09",
        audit_src=tmp_path / "audit.jsonl",
    )
    entry = json.loads((out / "index.json").read_text())["runs"][0]
    # the public summary must not advertise a rate while hiding the N/A coverage
    assert "na_count" in entry and entry["na_count"] > 0
    assert "error_count" in entry
    assert entry["total_attempts"] == entry["exercised"] + entry["na_count"] + entry["error_count"]


def test_writer_pii_leaves_no_file_at_public_path(tmp_path: Path) -> None:
    sentinel = "leak" + ".me@notexample" + ".com"
    poisoned = [
        AttemptResult(CLASSES[0].id, sentinel, "gated", "hand-written", Outcome.BLOCKED, None)
    ]
    out = tmp_path / "pub"
    out.mkdir()
    before = set(out.iterdir())
    with pytest.raises(RedactionError):
        write_report(
            poisoned, mode="gated", seed=42, out_dir=out, git_commit="x", generated_at="2026-06-09",
        )
    # nothing was promoted to the published dir (staged + scanned in a temp dir first)
    assert set(out.iterdir()) == before

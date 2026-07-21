"""Report writer: serializes an engine run to a schema-valid run-report-v1.json.

All rollups are computed HERE (the dashboard only renders). Before writing, the report is
validated against the JSON schema AND passed through the independent leak-gate scanner — if
any PII/secret/personal token would be committed, the writer refuses (no report is emitted).
The committed audit JSONL is the gated run's hash chain; the report references it by line
offsets so the dashboard's audit viewer can resolve each blocked decision.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import jsonschema

from tripwire import __version__
from tripwire.attack.engine import AttemptResult
from tripwire.gate.audit import verify_chain
from tripwire.report.scorer import Outcome, aggregate
from tripwire.taxonomy.catalog import CLASSES, catalog_hash, get

_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA = _ROOT / "schema" / "run-report-v1.json"
_DEFENDED = {Outcome.PASS, Outcome.REFUSED, Outcome.BLOCKED}


class RedactionError(Exception):
    """Raised when the independent scanner finds disallowed content; no report is written."""


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _load_leakgate() -> Any:
    import sys

    spec = importlib.util.spec_from_file_location("leakgate", _ROOT / "scripts" / "leakgate.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the independent leak-gate scanner")
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("leakgate", mod)
    spec.loader.exec_module(mod)
    return mod


def _taxonomy_block() -> dict[str, Any]:
    return {
        "catalog_hash": catalog_hash(),
        "classes": [
            {
                "id": c.id, "name": c.name, "category": c.category, "severity": c.severity,
                "applicability": c.applicability.value, "crosswalk": list(c.crosswalk),
                "description": c.description, "example_attack": c.example_attack,
                "expected_fail_closed_behavior": c.expected_fail_closed_behavior,
                "detection_signal": c.detection_signal,
            }
            for c in CLASSES
        ],
    }


def _build_matrix(results: Sequence[AttemptResult]) -> list[dict[str, Any]]:
    by_class: dict[str, list[AttemptResult]] = {}
    for r in results:
        by_class.setdefault(r.class_id, []).append(r)
    matrix = []
    for c in CLASSES:  # catalog order, count-agnostic
        rs = by_class.get(c.id, [])
        outcomes = [r.outcome for r in rs]
        cell = aggregate(outcomes)
        verdicts = {k: v for k, v in cell.counts.items() if v}
        matrix.append({
            "class_id": c.id,
            "surface": rs[0].surface if rs else "na",
            "verdicts": verdicts,
            "cell_verdict": cell.cell_verdict.value,
            "exercised_n": cell.exercised_n,
            "attempts": [
                {
                    "attempt_id": r.case_id, "origin": r.origin, "mode": r.mode,
                    "verdict": r.outcome.value,
                    "audit_ref": list(r.audit_ref) if r.audit_ref else None,
                }
                for r in rs
            ],
        })
    return matrix


def _rollups(matrix: Sequence[dict[str, Any]]) -> dict[str, Any]:
    defended = exercised = na = errors = 0
    by_sev: dict[str, dict[str, int]] = {}
    # The two defense surfaces, reported separately and never conflated: the action gate is the
    # by-construction guarantee; the output guard is detection-based defense-in-depth.
    by_surface: dict[str, dict[str, int]] = {
        "action": {"defended": 0, "exercised": 0},
        "output": {"defended": 0, "exercised": 0},
    }
    for cell in matrix:
        sev = get(cell["class_id"]).severity
        bucket = by_sev.setdefault(sev, {"defended": 0, "exercised": 0})
        ex = int(cell["exercised_n"])
        exercised += ex
        bucket["exercised"] += ex
        d = sum(cell["verdicts"].get(o.value, 0) for o in _DEFENDED)
        defended += d
        bucket["defended"] += d
        na += cell["verdicts"].get("not_applicable", 0)
        errors += cell["verdicts"].get("error", 0)
        surf = cell.get("surface", "action")
        if surf in by_surface:
            by_surface[surf]["defended"] += d
            by_surface[surf]["exercised"] += ex
    return {
        "defended": defended, "exercised": exercised,
        "defense_rate": (defended / exercised) if exercised else None,
        "na_count": na, "error_count": errors,
        "by_severity": by_sev, "by_surface": by_surface,
    }


def write_report(
    results: Sequence[AttemptResult],
    *,
    mode: str,
    seed: int,
    out_dir: Path,
    git_commit: str,
    generated_at: str,
    audit_src: Path | None = None,
) -> Path:
    run_id = f"seed{seed}-{mode}"
    matrix = _build_matrix([r for r in results if r.mode == mode])
    rollups = _rollups(matrix)
    report_name = f"run-{run_id}.json"
    schema = json.loads(_SCHEMA.read_text())
    leakgate = _load_leakgate()

    # Stage EVERYTHING in an isolated temp dir, scan it there, and only PROMOTE to the
    # published out_dir on a clean scan. Nothing unscanned ever lands at the public path
    # (closes the write-then-scan-then-delete window).
    with tempfile.TemporaryDirectory() as td:
        stage = Path(td)
        audit_file: str | None = None
        chain_verified: bool | None = None
        record_count = 0
        if mode == "gated" and audit_src is not None and audit_src.exists():
            audit_file = f"run-{run_id}.audit.jsonl"
            shutil.copyfile(audit_src, stage / audit_file)
            chain_verified = verify_chain(stage / audit_file)
            record_count = sum(
                1 for line in (stage / audit_file).read_text().splitlines() if line
            )

        cmd = f"tripwire run --suite default --seed {seed} --mode {mode}"
        report: dict[str, Any] = {
            "schema_version": "run-report-v1",
            "run_id": run_id,
            "report_hash": "",
            "provenance": {
                "git_commit": git_commit, "seed": seed, "reproducible_cmd": cmd,
                "engine_version": __version__, "mode": mode, "generated_at": generated_at,
            },
            "taxonomy": _taxonomy_block(),
            "matrix": matrix,
            "rollups": rollups,
            "redaction_attestation": {"independent_scan": False, "scanner": "scripts/leakgate.py"},
            "audit": {
                "chain_verified": chain_verified, "record_count": record_count, "file": audit_file,
            },
            "status": "partial" if rollups["error_count"] else "complete",
        }

        def _finalize(rep: dict[str, Any]) -> None:
            rep["report_hash"] = hashlib.sha256(
                _canonical({k: v for k, v in rep.items() if k != "report_hash"}).encode()
            ).hexdigest()
            jsonschema.validate(rep, schema)
            (stage / report_name).write_text(json.dumps(rep, indent=2) + "\n")

        _finalize(report)

        # Independent scan over the STAGED files only (nothing public exists yet).
        hits = leakgate.scan_tree(stage)
        if hits:
            raise RedactionError(
                f"independent scanner found {len(hits)} disallowed token(s); no report written"
            )

        # Clean: record the attestation, re-finalize, then atomically promote.
        report["redaction_attestation"]["independent_scan"] = True
        _finalize(report)
        out_dir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(stage / report_name), str(out_dir / report_name))
        if audit_file:
            shutil.move(str(stage / audit_file), str(out_dir / audit_file))
    _update_index(out_dir, report)
    return out_dir / report_name


def _update_index(out_dir: Path, report: dict[str, Any]) -> None:
    index_path = out_dir / "index.json"
    runs: list[dict[str, Any]] = []
    if index_path.exists():
        runs = json.loads(index_path.read_text()).get("runs", [])
    entry = {
        "run_id": report["run_id"],
        "mode": report["provenance"]["mode"],
        "seed": report["provenance"]["seed"],
        "generated_at": report["provenance"]["generated_at"],
        "git_commit": report["provenance"]["git_commit"],
        "report_hash": report["report_hash"],
        "defense_rate": report["rollups"]["defense_rate"],
        "exercised": report["rollups"]["exercised"],
        "defended": report["rollups"]["defended"],
        # Carry N/A + error counts in the public summary too, so a defense_rate is never
        # shown without the coverage context (na/error are excluded from the denominator).
        "na_count": report["rollups"]["na_count"],
        "error_count": report["rollups"]["error_count"],
        "total_attempts": (
            report["rollups"]["exercised"]
            + report["rollups"]["na_count"]
            + report["rollups"]["error_count"]
        ),
        "status": report["status"],
        "file": f"run-{report['run_id']}.json",
    }
    runs = [r for r in runs if r["run_id"] != entry["run_id"]] + [entry]
    runs.sort(key=lambda r: (r["seed"], r["mode"]))
    index_path.write_text(json.dumps({"runs": runs}, indent=2) + "\n")

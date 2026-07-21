"""Tests for the leak-gate scanner (LEAK-2).

Fixture discipline: any content that must TRIP the scanner is assembled at
runtime (concatenation / reversal), never written as a literal — otherwise
this test file itself would fail the repo's own tree scan.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "leakgate.py"
_spec = importlib.util.spec_from_file_location("leakgate", _SCRIPT)
assert _spec is not None and _spec.loader is not None
leakgate = importlib.util.module_from_spec(_spec)
sys.modules["leakgate"] = leakgate  # so dataclasses can resolve annotations
_spec.loader.exec_module(leakgate)

scan_tree = leakgate.scan_tree

# Runtime-assembled banned terms (reversed in source, like the scanner's own list).
_VISA = "asiv"[::-1]
_OPT = "tpo"[::-1]
_APPLYBOT = "tobylppa"[::-1]


def test_banned_word_hit(tmp_path: Path) -> None:
    f = tmp_path / "x.md"
    f.write_text(f"my {_VISA} status")
    hits = scan_tree(tmp_path)
    assert hits and hits[0].kind == "banned-term"


def test_banned_term_case_insensitive_and_username(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text(f"the {_APPLYBOT.upper()} engine")
    (tmp_path / "b.txt").write_text("/Users/" + "dakshit" + "raj/Documents")
    assert len(scan_tree(tmp_path)) == 2


def test_word_boundary_negatives(tmp_path: Path) -> None:
    f = tmp_path / "x.md"
    f.write_text(
        "it is advisable to optimize this option; adoption of f-strings; "
        "optional dependencies should head the readme"
    )
    assert scan_tree(tmp_path) == []


def test_opt_in_out_exceptions(tmp_path: Path) -> None:
    clean = tmp_path / "clean.md"
    clean.write_text(f"users {_OPT}-in to emails; you may {_OPT} out; {_OPT}-out works too")
    assert scan_tree(tmp_path) == []
    dirty = tmp_path / "dirty.md"
    dirty.write_text(f"the {_OPT} deadline is in July")
    assert any(v.kind == "banned-term" for v in scan_tree(tmp_path))


def test_email_and_ssn_patterns(tmp_path: Path) -> None:
    # real-looking email (not under .test/example.com) + SSN-shaped -> hits
    email = "john.doe1987" + "@" + "gmail.com"
    ssn = "-".join(["123", "45", "6789"])
    (tmp_path / "x.txt").write_text(f"reach me at {email} or ssn {ssn}")
    kinds = {v.kind for v in scan_tree(tmp_path)}
    assert "pii-email" in kinds and "pii-ssn" in kinds


def test_reserved_tld_emails_clean(tmp_path: Path) -> None:
    (tmp_path / "x.txt").write_text(
        "attacker@evil.test sent mail to support@example.com and jordan@ops.example.com"
    )
    assert scan_tree(tmp_path) == []


def test_phone_fictional_band_clean_real_shape_hit(tmp_path: Path) -> None:
    (tmp_path / "clean.txt").write_text("call 415-555-0142 (fictional band)")
    assert scan_tree(tmp_path) == []
    real = "-".join(["415", "867", "5309"])
    (tmp_path / "dirty.txt").write_text(f"call {real}")
    assert any(v.kind == "pii-phone" for v in scan_tree(tmp_path))


def test_hex_digests_exempt_from_entropy_but_base64_secret_hit(tmp_path: Path) -> None:
    sha256 = "ab" * 32          # 64-char lowercase hex
    sha1 = "cd" * 20            # 40-char lowercase hex
    (tmp_path / "report.json").write_text(f'{{"payload_hash": "{sha256}", "git_commit": "{sha1}"}}')
    assert scan_tree(tmp_path) == []
    secret = "Xk9mP2qRt7Lw3Zn8" * 3  # 48 chars, mixed case + digits, assembled at runtime
    (tmp_path / "config.py").write_text(f'token = "{secret}"')
    assert any(v.kind == "entropy" for v in scan_tree(tmp_path))


def test_scanner_skips_excluded_dirs_and_lockfiles(tmp_path: Path) -> None:
    for sub in (".git", ".venv", "node_modules", "dashboard/.next", "dashboard/out"):
        d = tmp_path / sub
        d.mkdir(parents=True)
        (d / "x.txt").write_text(f"my {_VISA} status")
    (tmp_path / "package-lock.json").write_text('{"integrity": "' + "Xk9mP2qRt7Lw3Zn8" * 3 + '"}')
    (tmp_path / "poetry.lock").write_text("Xk9mP2qRt7Lw3Zn8" * 3)
    assert scan_tree(tmp_path) == []


def test_binary_files_skipped(tmp_path: Path) -> None:
    (tmp_path / "img.png").write_bytes(b"\x89PNG\x00" + _VISA.encode() + b"\x00")
    assert scan_tree(tmp_path) == []


def test_this_repo_is_clean() -> None:
    repo = Path(__file__).resolve().parents[1]
    assert scan_tree(repo) == []

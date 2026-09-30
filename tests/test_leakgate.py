"""Tests for the leak-gate scanner (LEAK-2).

Fixture discipline: any content that must TRIP a generic check (emails, SSNs, phone
numbers, home-directory paths, secret-shaped tokens) is assembled at runtime, never
written as a literal — otherwise this test file itself would fail the repo's own tree
scan. Banned-term tests use made-up terms written to a temporary private terms file;
the real list lives outside the repository.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "leakgate.py"
_spec = importlib.util.spec_from_file_location("leakgate", _SCRIPT)
assert _spec is not None and _spec.loader is not None
leakgate = importlib.util.module_from_spec(_spec)
sys.modules["leakgate"] = leakgate  # so dataclasses can resolve annotations
_spec.loader.exec_module(leakgate)

scan_tree = leakgate.scan_tree

# The terms file this machine is configured with, resolved before any test patches the env.
_CONFIGURED_TERMS = leakgate.terms_path()

# Made-up terms standing in for a private list.
_TERMS_TEXT = """\
# comment lines and blank lines are ignored

zorblax
quux-7
frob widget
kq#
qzuser9
flim | (?:-in|-out|\\s+in|\\s+out)\\b
"""


def _home(root: str, name: str, rest: str) -> str:
    # Runtime-assembled absolute home path, e.g. root="Users" -> "/Users/<name>/<rest>".
    return "/" + root + "/" + name + "/" + rest


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    d = tmp_path / "tree"
    d.mkdir()
    return d


@pytest.fixture(autouse=True)
def _private_terms(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    # Kept outside the scanned tree so the terms file never scans itself.
    path = tmp_path / "terms.txt"
    path.write_text(_TERMS_TEXT)
    monkeypatch.setenv(leakgate.TERMS_ENV, str(path))
    return path


def _no_terms_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(leakgate.TERMS_ENV, str(tmp_path / "absent" / "terms.txt"))


def test_banned_term_hit_does_not_echo_term(tree: Path) -> None:
    (tree / "x.md").write_text("my zorblax status")
    hits = scan_tree(tree)
    assert len(hits) == 1 and hits[0].kind == "banned-term"
    assert "zorblax" not in hits[0].detail
    assert "line 3" in hits[0].detail  # points at the rule's line in the private file


def test_banned_term_case_insensitive(tree: Path) -> None:
    (tree / "a.txt").write_text("the ZORBLAX engine")
    (tree / "b.txt").write_text("a Frob Widget and a QUUX-7")
    assert [v.kind for v in scan_tree(tree)] == ["banned-term"] * 3


def test_username_term_and_home_path(tree: Path) -> None:
    (tree / "a.txt").write_text("owned by qzuser9")
    (tree / "b.txt").write_text(_home("Users", "qzuser9", "Documents"))
    kinds = sorted(v.kind for v in scan_tree(tree))
    assert kinds == ["banned-term", "banned-term", "pii-home-path"]


def test_word_boundary_negatives(tree: Path) -> None:
    (tree / "x.md").write_text(
        "zorblaxian notes; prezorblax; quux-72 build; flimsy flimflam; akq# marker; "
        "frob widgets; qzuser99"
    )
    assert scan_tree(tree) == []


def test_term_ending_in_symbol_matches_without_trailing_boundary(tree: Path) -> None:
    (tree / "x.md").write_text("ref KQ#12")
    assert [v.kind for v in scan_tree(tree)] == ["banned-term"]


def test_allowed_continuations(tree: Path) -> None:
    (tree / "clean.md").write_text("users flim-in to emails; you may flim out; flim-OUT too")
    assert scan_tree(tree) == []
    (tree / "dirty.md").write_text("the flim deadline is in July")
    assert [v.kind for v in scan_tree(tree)] == ["banned-term"]


def test_comment_lines_are_not_terms(
    tree: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "commented.txt"
    path.write_text("# zorblax\n\n   \n")
    monkeypatch.setenv(leakgate.TERMS_ENV, str(path))
    (tree / "x.md").write_text("my zorblax status")
    assert scan_tree(tree) == []


def test_invalid_terms_file_fails_closed(
    tree: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "broken.txt"
    path.write_text("flim | (?:-in\n")
    monkeypatch.setenv(leakgate.TERMS_ENV, str(path))
    with pytest.raises(leakgate.TermsFileError, match="line 1"):
        leakgate.load_terms()
    assert leakgate.main([str(tree)]) == 2


def test_missing_terms_file_skips_term_check_only(
    tree: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_terms_file(tmp_path, monkeypatch)
    assert leakgate.load_terms() is None
    email = "john.doe1987" + "@" + "gmail.com"
    (tree / "x.md").write_text(f"my zorblax status, mail {email}")
    assert [v.kind for v in scan_tree(tree)] == ["pii-email"]


def test_missing_terms_file_prints_one_note(
    tree: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _no_terms_file(tmp_path, monkeypatch)
    (tree / "x.md").write_text("nothing to see")
    assert leakgate.main([str(tree)]) == 0
    out = capsys.readouterr().out.splitlines()
    assert sum(line.startswith("leakgate: note") for line in out) == 1
    assert out[-1] == "leakgate: clean"


def test_main_reports_violation_without_echoing_term(
    tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tree / "x.md").write_text("my zorblax status")
    assert leakgate.main([str(tree)]) == 1
    captured = capsys.readouterr()
    assert "[banned-term]" in captured.out
    assert "zorblax" not in captured.out + captured.err
    assert "leakgate: note" not in captured.out


def test_default_terms_path_when_env_unset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(leakgate.TERMS_ENV)
    monkeypatch.setenv("HOME", str(tmp_path))
    expected = tmp_path / ".config" / "leakgate" / "tripwire-terms.txt"
    assert leakgate.terms_path() == expected
    expected.parent.mkdir(parents=True)
    expected.write_text("zorblax\n")
    assert len(leakgate.load_terms() or []) == 1


def test_home_paths_hit_without_echoing_name(tree: Path) -> None:
    windows = "C:" + "\\" + "Users" + "\\" + "someone" + "\\" + "Desktop"
    (tree / "x.txt").write_text(
        "\n".join([_home("Users", "someone", "src"), _home("home", "someone", "x"), windows])
    )
    hits = scan_tree(tree)
    assert [v.kind for v in hits] == ["pii-home-path"] * 3
    assert all("someone" not in v.detail for v in hits)


def test_home_path_negatives(tree: Path) -> None:
    (tree / "x.txt").write_text(
        "see ~/.config/leakgate and /usr/local/bin; https://example.com/home/page"
    )
    assert scan_tree(tree) == []


def test_email_and_ssn_patterns(tree: Path) -> None:
    # real-looking email (not under .test/example.com) + SSN-shaped -> hits
    email = "john.doe1987" + "@" + "gmail.com"
    ssn = "-".join(["123", "45", "6789"])
    (tree / "x.txt").write_text(f"reach me at {email} or ssn {ssn}")
    kinds = {v.kind for v in scan_tree(tree)}
    assert "pii-email" in kinds and "pii-ssn" in kinds


def test_reserved_tld_emails_clean(tree: Path) -> None:
    (tree / "x.txt").write_text(
        "attacker@evil.test sent mail to support@example.com and jordan@ops.example.com"
    )
    assert scan_tree(tree) == []


def test_phone_fictional_band_clean_real_shape_hit(tree: Path) -> None:
    (tree / "clean.txt").write_text("call 415-555-0142 (fictional band)")
    assert scan_tree(tree) == []
    real = "-".join(["415", "867", "5309"])
    (tree / "dirty.txt").write_text(f"call {real}")
    assert any(v.kind == "pii-phone" for v in scan_tree(tree))


def test_hex_digests_exempt_from_entropy_but_base64_secret_hit(tree: Path) -> None:
    sha256 = "ab" * 32  # 64-char lowercase hex
    sha1 = "cd" * 20  # 40-char lowercase hex
    (tree / "report.json").write_text(f'{{"payload_hash": "{sha256}", "git_commit": "{sha1}"}}')
    assert scan_tree(tree) == []
    secret = "Xk9mP2qRt7Lw3Zn8" * 3  # 48 chars, mixed case + digits, assembled at runtime
    (tree / "config.py").write_text(f'token = "{secret}"')
    assert any(v.kind == "entropy" for v in scan_tree(tree))


def test_scanner_skips_excluded_dirs_and_lockfiles(tree: Path) -> None:
    for sub in (".git", ".venv", "node_modules", "dashboard/.next", "dashboard/out"):
        d = tree / sub
        d.mkdir(parents=True)
        (d / "x.txt").write_text("my zorblax status")
    (tree / "package-lock.json").write_text('{"integrity": "' + "Xk9mP2qRt7Lw3Zn8" * 3 + '"}')
    (tree / "poetry.lock").write_text("Xk9mP2qRt7Lw3Zn8" * 3)
    assert scan_tree(tree) == []


def test_binary_files_skipped(tree: Path) -> None:
    (tree / "img.png").write_bytes(b"\x89PNG\x00zorblax\x00")
    assert scan_tree(tree) == []


def test_this_repo_is_clean_generic_checks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _no_terms_file(tmp_path, monkeypatch)
    repo = Path(__file__).resolve().parents[1]
    assert scan_tree(repo) == []


def test_this_repo_is_clean_with_configured_private_terms() -> None:
    terms = leakgate.load_terms(_CONFIGURED_TERMS)
    if terms is None:
        pytest.skip("no private terms file configured on this machine")
    repo = Path(__file__).resolve().parents[1]
    assert scan_tree(repo, terms) == []

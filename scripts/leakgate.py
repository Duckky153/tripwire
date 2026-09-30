#!/usr/bin/env python3
"""leak-gate scanner (LEAK-2): fails the build on any personal/PII/secret-shaped content.

Independent of the audit writer's own redaction (LEAK-1) by design — this scanner is the
evidence-of-record for the repo's leak-safety claim, so it shares no code with the writer.

Two layers of checks:

* Generic checks that always run (CI included): email addresses outside the reserved test
  domains, SSN- and phone-shaped numbers, absolute home-directory paths, and high-entropy
  secret-shaped tokens.
* A private banned-term list that is deliberately NOT part of this repository, so the
  public source never reveals what it protects. It is read at runtime from the file named
  by $TRIPWIRE_LEAKGATE_TERMS, else ~/.config/leakgate/tripwire-terms.txt. Format: one
  term per line, matched case-insensitively on word boundaries; blank lines and lines
  starting with "#" are ignored. A line may add an allowed continuation,
  ``term | <regex>``: a match immediately followed by text matching <regex> is not a
  violation (for short terms that also begin legitimate phrases). Without the file the
  term check is skipped with a one-line note and every generic check still runs.

Violations name the terms-file line of the rule that matched, never the term itself, so
scanner output does not republish the private list.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

TERMS_ENV = "TRIPWIRE_LEAKGATE_TERMS"
_DEFAULT_TERMS = "~/.config/leakgate/tripwire-terms.txt"

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PHONE = re.compile(r"\b\d{3}[-.]\d{3}[-.]\d{4}\b")
# Absolute home-directory paths (macOS, Linux, Windows) expose a local account name. The
# lookbehind keeps URL path segments (e.g. "example.com/home/...") out of scope.
_HOME_PATH = re.compile(r"(?<![\w.-])(?P<root>/Users/|/home/|[A-Za-z]:\\[Uu]sers\\)[\w.-]+")
# Entropy candidates: long mixed tokens. Exemption: EXACT lowercase-hex of length 40/64
# (git SHAs + sha256 digests committed in reports/audit chains). This knowingly exempts
# SHA-1-shaped lowercase-hex secrets — a narrow, deliberate trade-off; do NOT widen it.
_ENTROPY_CANDIDATE = re.compile(r"\b[A-Za-z0-9+/=_-]{32,}\b")
_HEX_DIGEST = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")

_SKIP_DIR_PARTS = {
    ".git",
    ".venv",
    "node_modules",
    ".next",
    "_next",
    "__pycache__",
    ".hypothesis",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    ".egg-info",
}
_SKIP_FILE_NAMES = {"package-lock.json"}
_SKIP_FILE_SUFFIXES = {".lock", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".pdf"}


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    kind: str
    detail: str


@dataclass(frozen=True)
class TermRule:
    """One private banned term (compiled) plus its optional allowed continuation."""

    pattern: re.Pattern[str]
    allow_after: re.Pattern[str] | None
    source_line: int


class TermsFileError(ValueError):
    """The private terms file exists but cannot be used; the scan must not pass silently."""


def terms_path() -> Path:
    """Where the private term list is read from: $TRIPWIRE_LEAKGATE_TERMS, else the default."""
    configured = os.environ.get(TERMS_ENV)
    return Path(configured or _DEFAULT_TERMS).expanduser()


def _terms_path_label() -> str:
    # Shown in messages; avoids printing an expanded home directory.
    return os.environ.get(TERMS_ENV) or _DEFAULT_TERMS


def _term_pattern(term: str) -> re.Pattern[str]:
    leading = r"\b" if re.match(r"\w", term[0]) else ""
    trailing = r"\b" if re.match(r"\w", term[-1]) else ""
    return re.compile(leading + re.escape(term) + trailing, re.IGNORECASE)


def parse_terms(text: str) -> list[TermRule]:
    rules: list[TermRule] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        term, sep, allow = (part.strip() for part in line.partition("|"))
        if not term:
            raise TermsFileError(f"line {lineno}: empty term")
        allow_after: re.Pattern[str] | None = None
        if sep:
            if not allow:
                raise TermsFileError(f"line {lineno}: '|' without a continuation pattern")
            try:
                allow_after = re.compile(allow, re.IGNORECASE)
            except re.error as exc:
                msg = f"line {lineno}: invalid continuation pattern ({exc.msg})"
                raise TermsFileError(msg) from None
        rules.append(TermRule(_term_pattern(term), allow_after, lineno))
    return rules


def load_terms(path: Path | None = None) -> list[TermRule] | None:
    """Parse the private term list; None when the file does not exist.

    Any other read or parse failure raises, so a broken configuration fails the scan
    instead of quietly skipping the term check.
    """
    source = terms_path() if path is None else path
    try:
        text = source.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    return parse_terms(text)


def _is_skipped(rel: Path) -> bool:
    parts = set(rel.parts[:-1])
    if parts & _SKIP_DIR_PARTS:
        return True
    if "dashboard" in rel.parts and "out" in rel.parts:
        return True
    if rel.name in _SKIP_FILE_NAMES or rel.suffix in _SKIP_FILE_SUFFIXES:
        return True
    return False


def _git_tracked(root: Path) -> list[Path] | None:
    argv = ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"]
    try:
        out = subprocess.run(argv, capture_output=True, check=True)  # noqa: S603 — fixed argv, no shell
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return [Path(p) for p in out.stdout.decode().split("\0") if p]


def _candidate_files(root: Path) -> list[Path]:
    rels = _git_tracked(root)
    if rels is None:
        rels = [p.relative_to(root) for p in root.rglob("*") if p.is_file()]
    return [root / r for r in rels if not _is_skipped(r)]


def _allowed_email(domain: str) -> bool:
    d = domain.lower()
    return d.endswith(".test") or d == "example.com" or d.endswith(".example.com")


def _scan_line(
    line: str, lineno: int, rel: str, terms: Sequence[TermRule], out: list[Violation]
) -> None:
    for rule in terms:
        for m in rule.pattern.finditer(line):
            if rule.allow_after is not None and rule.allow_after.match(line[m.end() :]):
                continue
            detail = f"private term (terms file line {rule.source_line})"
            out.append(Violation(rel, lineno, "banned-term", detail))
    for m in _EMAIL.finditer(line):
        if not _allowed_email(m.group(1)):
            out.append(Violation(rel, lineno, "pii-email", m.group(0)))
    for m in _SSN.finditer(line):
        out.append(Violation(rel, lineno, "pii-ssn", m.group(0)))
    for m in _PHONE.finditer(line):
        if "555-01" not in m.group(0):
            out.append(Violation(rel, lineno, "pii-phone", m.group(0)))
    for m in _HOME_PATH.finditer(line):
        out.append(Violation(rel, lineno, "pii-home-path", m.group("root") + "<name>"))
    for m in _ENTROPY_CANDIDATE.finditer(line):
        token = m.group(0)
        if _HEX_DIGEST.match(token):
            continue
        has_digit = any(c.isdigit() for c in token)
        has_lower = any(c.islower() for c in token)
        has_upper = any(c.isupper() for c in token)
        if has_digit and has_lower and has_upper:
            out.append(Violation(rel, lineno, "entropy", token[:16] + "..."))


def scan_tree(root: Path, terms: Sequence[TermRule] | None = None) -> list[Violation]:
    """Scan every candidate file under root.

    terms=None loads the configured private list (skipping the term check when the file
    is absent); pass an explicit sequence to control the term rules directly.
    """
    if terms is None:
        terms = load_terms() or []
    root = root.resolve()
    violations: list[Violation] = []
    for f in _candidate_files(root):
        try:
            raw = f.read_bytes()
        except OSError:
            continue
        if b"\0" in raw[:8192]:
            continue
        rel = str(f.relative_to(root))
        for lineno, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), 1):
            _scan_line(line, lineno, rel, terms, violations)
    return violations


def main(argv: Sequence[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else list(argv)
    root = Path(args[0]) if args else Path.cwd()
    try:
        terms = load_terms()
    except (TermsFileError, OSError) as exc:
        print(f"leakgate: private terms file {_terms_path_label()}: {exc}", file=sys.stderr)
        return 2
    if terms is None:
        print(
            f"leakgate: note — no private terms file ({_terms_path_label()}); "
            "personal-term check skipped, generic checks ran."
        )
        terms = []
    violations = scan_tree(root, terms)
    for v in violations:
        print(f"{v.path}:{v.line}: [{v.kind}] {v.detail}")
    if violations:
        msg = f"leakgate: {len(violations)} violation(s) — tree is NOT publishable"
        print(msg, file=sys.stderr)
        return 1
    print("leakgate: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

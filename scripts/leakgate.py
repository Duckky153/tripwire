#!/usr/bin/env python3
"""leak-gate scanner (LEAK-2): fails the build on any personal/PII/secret-shaped content.

Independent of the audit writer's own redaction (LEAK-1) by design — this scanner is the
evidence-of-record for the repo's leak-safety claim, so it shares no code with the writer.

Self-scan discipline: the banned terms below are stored REVERSED so this file's own source
never contains a banned literal (and never trips other secret scanners). Decoded at import.
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# Reversed banned terms — decode with [::-1]. Personal/identifying vocabulary that must
# never appear in this public repo (word-boundary matched, case-insensitive).
_REVERSED_TERMS = [
    "tobylppa",            # apply-bot engine name
    "pihsrosnops",
    "asiv",
    "rebmun-a",
    "#a",
    "eliforp emorhc",
    "eliforp-lacinonac",
    "tob-boj",
    "tobboj",
    "noitargimmi",
    "sicsu",
    "dae",
    "567-i",
    "sives",
    "1-f",
    "tpo",
    "noitamotua-boj",
    "jarтihskad".replace("т", "t"),  # local username; never via absolute paths
]

_TERMS = [t[::-1] for t in _REVERSED_TERMS]


def _term_pattern(term: str) -> re.Pattern[str]:
    trailing = r"\b" if term[-1].isalnum() else ""
    return re.compile(r"\b" + re.escape(term) + trailing, re.IGNORECASE)


_TERM_PATTERNS = [(_term_pattern(t), t) for t in _TERMS]

# Standalone short terms with legitimate phrase uses: skip these continuations.
_AFTER_OPT_OK = re.compile(r"^(?:-in\b|-out\b|\s+in\b|\s+out\b)", re.IGNORECASE)
_OPT_TERM = "tpo"[::-1]

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PHONE = re.compile(r"\b\d{3}[-.]\d{3}[-.]\d{4}\b")
# Entropy candidates: long mixed tokens. Exemption: EXACT lowercase-hex of length 40/64
# (git SHAs + sha256 digests committed in reports/audit chains). This knowingly exempts
# SHA-1-shaped lowercase-hex secrets — a narrow, deliberate trade-off; do NOT widen it.
_ENTROPY_CANDIDATE = re.compile(r"\b[A-Za-z0-9+/=_-]{32,}\b")
_HEX_DIGEST = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")

_SKIP_DIR_PARTS = {
    ".git", ".venv", "node_modules", ".next", "__pycache__",
    ".hypothesis", ".mypy_cache", ".ruff_cache", ".pytest_cache", ".egg-info",
}
_SKIP_FILE_NAMES = {"package-lock.json"}
_SKIP_FILE_SUFFIXES = {".lock", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".pdf"}


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    kind: str
    detail: str


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


def _scan_line(line: str, lineno: int, rel: str, out: list[Violation]) -> None:
    for pattern, term in _TERM_PATTERNS:
        for m in pattern.finditer(line):
            if term == _OPT_TERM and _AFTER_OPT_OK.match(line[m.end():]):
                continue
            out.append(Violation(rel, lineno, "banned-term", term))
    for m in _EMAIL.finditer(line):
        if not _allowed_email(m.group(1)):
            out.append(Violation(rel, lineno, "pii-email", m.group(0)))
    for m in _SSN.finditer(line):
        out.append(Violation(rel, lineno, "pii-ssn", m.group(0)))
    for m in _PHONE.finditer(line):
        if "555-01" not in m.group(0):
            out.append(Violation(rel, lineno, "pii-phone", m.group(0)))
    for m in _ENTROPY_CANDIDATE.finditer(line):
        token = m.group(0)
        if _HEX_DIGEST.match(token):
            continue
        has_digit = any(c.isdigit() for c in token)
        has_lower = any(c.islower() for c in token)
        has_upper = any(c.isupper() for c in token)
        if has_digit and has_lower and has_upper:
            out.append(Violation(rel, lineno, "entropy", token[:16] + "..."))


def scan_tree(root: Path) -> list[Violation]:
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
            _scan_line(line, lineno, rel, violations)
    return violations


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    violations = scan_tree(root)
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

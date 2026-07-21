"""Output-disclosure guard — the detection-based, defense-in-depth half of the gated config.

HONEST SCOPING (read this before citing a number): this guard is **not** the by-construction
guarantee. The action gate (`pdp`/`pep`) *proves* — by property test — that no unauthorized
high-stakes action ever runs. This guard is a best-effort egress filter over the agent's
free-form text: it matches the shapes it knows (PII, secrets, config markers, active markup)
and, on any hit, withholds the whole response. A determined attacker can encode or obfuscate a
disclosure around a shape detector, so the disclosure surface is reported separately and is
labeled detection-based — it is layered defense, not a proof. The architecture deliberately
puts the guarantee at the action layer, where it can be proven, and treats output filtering as
a second, weaker line.

The guard is a real runtime control: `inspect()` returns the text the defended configuration
actually emits. When it blocks, the emitted text is a fixed refusal that is itself clean, so
re-scanning the emitted output yields nothing — the block is provable, not asserted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Shape detectors. These match *kinds* of unsafe content, not per-attack canaries — a general
# PII / secret / config-marker / active-markup sweep over agent-visible text.
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_SECRET_PREFIX = re.compile(r"(sk[-_]live[-_]|AKIA|BEGIN (?:RSA )?PRIVATE KEY|xox[bap]-)")
_CONFIG_MARKER = re.compile(
    r"(TW-SYSTEM-PROMPT-CONFIG|INTERNAL_TOOLS:|TW-SECRET|TW-RESIDUE|TW-PII)"
)
_ACTIVE_MARKUP = re.compile(r"(<\s*script|onerror\s*=|<\s*img\b|javascript:)", re.IGNORECASE)

_DETECTORS = (
    ("pii_email", _EMAIL),
    ("pii_ssn", _SSN),
    ("secret", _SECRET_PREFIX),
    ("config_disclosure", _CONFIG_MARKER),
    ("active_markup", _ACTIVE_MARKUP),
)

# The fixed refusal the defended configuration emits in place of a disclosing response. It is
# deliberately free of every shape above so re-scanning it is clean (no self-leak, no loop).
WITHHELD = "[response withheld by output guard: potential disclosure detected]"


def scan_output(text: str) -> list[str]:
    """Return the kinds of leak/unsafe-content findings in `text` (empty == clean)."""
    return [kind for kind, pat in _DETECTORS if pat.search(text)]


@dataclass(frozen=True, slots=True)
class GuardResult:
    blocked: bool
    safe_text: str             # what the defended configuration actually emits
    findings: tuple[str, ...]  # the detector *kinds* that fired (never the leaked values)


class OutputGuard:
    """Inspect agent output; withhold it (returning the fixed refusal) if any detector fires."""

    def inspect(self, text: str) -> GuardResult:
        findings = tuple(scan_output(text))
        if findings:
            return GuardResult(blocked=True, safe_text=WITHHELD, findings=findings)
        return GuardResult(blocked=False, safe_text=text, findings=())

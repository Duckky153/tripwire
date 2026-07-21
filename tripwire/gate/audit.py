"""Audit loom: append-only, SHA-256 hash-chained JSONL with deny-by-default redaction.

One record per gate decision. Redaction (LEAK-1) masks EVERY value except an explicit
allowlist of structural, never-PII keys — mirroring the gate's fail-closed thesis: a field
is hidden unless it is explicitly known-safe. The chain makes the trail tamper-evident:
each record carries the hash of the previous one; verify_chain() recomputes end to end.

This writer's redaction is NOT the leak-safety evidence-of-record — the independent
scripts/leakgate.py scanner in CI is (LEAK-2). Two separate codepaths, on purpose.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from tripwire.gate.types import Decision, JudgeVote, ToolCall, Verdict, canonical_json

GENESIS = "GENESIS"

# TYPED allowlist (Codex r1: an attacker putting a string on a "safe" key leaked it
# verbatim). A value passes in clear ONLY if its key is allowlisted AND its value matches
# the key's expected shape; everything else is masked. Free-form strings NEVER pass.
_NUMERIC_KEYS = frozenset({"amount_cents"})
_BOOL_KEYS = frozenset({"order_exists"})
_SLUG_KEYS = frozenset({"template_id", "query_field"})
_SLUG_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def _leaf_is_safe(key: str | None, value: Any) -> bool:
    if key is None:
        return False
    if key in _NUMERIC_KEYS:
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if key in _BOOL_KEYS:
        return isinstance(value, (bool, type(None)))
    if key in _SLUG_KEYS:
        return isinstance(value, str) and _SLUG_RE.match(value) is not None
    return False


def _mask(value: Any) -> str:
    raw = canonical_json(value) if not isinstance(value, str) else value
    digest = hashlib.sha256(raw.encode()).hexdigest()[:12]
    return f"sha256:{digest}(len={len(raw)})"


def _slug_or_mask(value: str) -> str:
    return value if _SLUG_RE.match(value) else _mask(value)


def redact(obj: Any, *, key: str | None = None) -> Any:
    """Deny-by-default: mask every leaf unless its key+type+shape is explicitly safe."""
    if isinstance(obj, Mapping):
        return {str(k): redact(v, key=str(k)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact(v, key=None) for v in obj]
    if _leaf_is_safe(key, obj):
        return obj
    return _mask(obj)


def make_record(
    *,
    call: ToolCall,
    decision: Decision,
    vote: JudgeVote,
    final: Verdict,
    facts: Mapping[str, Any],
    policy_hash: str,
) -> dict[str, Any]:
    return {
        "ts": _slug_or_mask(call.ts),
        "trace_id": _slug_or_mask(call.trace_id),
        "session_id": _slug_or_mask(call.session_id),
        "agent_id": _slug_or_mask(call.agent_id),
        "tool": _slug_or_mask(call.tool),
        "principal_role": _slug_or_mask(call.principal.partition(":")[0]),
        "payload_hash": decision.payload_hash,
        "policy_hash": policy_hash,
        "verdict": decision.verdict.value,
        "vote": vote.value,
        "final_verdict": final.value,
        "reason_code": decision.reason_code,
        "matched_rule_id": decision.matched_rule_id,
        "escalate": decision.escalate,
        "constraints_evaluated": [list(pair) for pair in decision.constraints_evaluated],
        "args": redact(dict(call.args)),
        "facts": redact(dict(facts)),
    }


def make_output_record(
    *,
    ts: str,
    trace_id: str,
    session_id: str,
    agent_id: str,
    principal_role: str,
    findings: Sequence[str],
    policy_hash: str,
) -> dict[str, Any]:
    """Audit record for an OUTPUT-GUARD decision (a disclosing response was withheld).

    Carries the detector *kinds* that fired (e.g. ``pii_email``, ``secret``) — never the leaked
    values — so the trail proves a real control ran without itself disclosing anything. The
    ``surface`` field marks this as the detection-based output line, distinct from the action
    gate's tool decisions.
    """
    return {
        "ts": _slug_or_mask(ts),
        "trace_id": _slug_or_mask(trace_id),
        "session_id": _slug_or_mask(session_id),
        "agent_id": _slug_or_mask(agent_id),
        "tool": "output_guard",
        "principal_role": _slug_or_mask(principal_role),
        "payload_hash": "",
        "policy_hash": policy_hash,
        "verdict": Verdict.DENY.value,
        "vote": JudgeVote.ABSTAIN.value,
        "final_verdict": Verdict.DENY.value,
        "reason_code": "OUTPUT_DISCLOSURE_BLOCKED",
        "matched_rule_id": None,
        "escalate": True,
        "surface": "output",
        "finding_kinds": sorted({str(f) for f in findings}),
        "constraints_evaluated": [],
        "args": {},
        "facts": {},
    }


class AuditLoom:
    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._prev_hash = self._tail_hash()

    def line_count(self) -> int:
        if not self._path.exists():
            return 0
        with self._path.open() as f:
            return sum(1 for line in f if line.strip())

    def _tail_hash(self) -> str:
        if not self._path.exists():
            return GENESIS
        last = None
        with self._path.open() as f:
            for line in f:
                if line.strip():
                    last = line
        if last is None:
            return GENESIS
        return str(json.loads(last)["record_hash"])

    def append(self, record: dict[str, Any]) -> str:
        body = dict(record)
        body["prev_hash"] = self._prev_hash
        record_hash = hashlib.sha256(
            (self._prev_hash + canonical_json(body)).encode()
        ).hexdigest()
        body["record_hash"] = record_hash
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a") as f:
            f.write(canonical_json(body) + "\n")
        self._prev_hash = record_hash
        return record_hash


def verify_chain(path: Path) -> bool:
    prev = GENESIS
    try:
        with Path(path).open() as f:
            for line in f:
                if not line.strip():
                    continue
                rec = json.loads(line)
                claimed = rec.pop("record_hash")
                if rec.get("prev_hash") != prev:
                    return False
                recomputed = hashlib.sha256((prev + canonical_json(rec)).encode()).hexdigest()
                if recomputed != claimed:
                    return False
                prev = claimed
    except (OSError, ValueError, KeyError):
        return False
    return True

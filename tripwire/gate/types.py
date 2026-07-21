"""Frozen core types and the canonical payload hash — the one contract.

`ToolCall` is the normalized request every adapter emits; `Decision` is what the PDP
returns. Both are deeply immutable so a decision cannot be made about one payload and
then executed against a mutated one (the TOCTOU defense, INV-8).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any


class Verdict(Enum):
    DENY = "deny"
    ESCALATE = "escalate"
    ALLOW = "allow"


class JudgeVote(Enum):
    DENY = "deny"
    ESCALATE = "escalate"
    ABSTAIN = "abstain"


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, compact separators, ASCII-escaped."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def payload_hash(tool: str, args: Mapping[str, Any]) -> str:
    """SHA-256 over the canonicalized (tool, args) pair. Order-independent."""
    return hashlib.sha256(canonical_json({"tool": tool, "args": dict(args)}).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class ToolCall:
    tool: str
    args: Mapping[str, Any]
    principal: str
    session_id: str
    agent_id: str
    trace_id: str
    ts: str
    _hash: str = field(init=False, repr=False, compare=False, default="")

    def __post_init__(self) -> None:
        # Freeze args as a read-only mapping so the call cannot be mutated post-construction.
        object.__setattr__(self, "args", MappingProxyType(dict(self.args)))
        # Hash EAGERLY: unserializable args fail here, at the adapter boundary — never
        # inside the decision path (Codex r1: a set() in args crashed decide()).
        try:
            computed = payload_hash(self.tool, self.args)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"ToolCall args must be JSON-serializable: {exc}") from exc
        object.__setattr__(self, "_hash", computed)

    @property
    def hash(self) -> str:
        return self._hash


@dataclass(frozen=True, slots=True)
class Decision:
    verdict: Verdict
    reason_code: str
    matched_rule_id: str | None
    constraints_evaluated: tuple[tuple[str, bool], ...]
    escalate: bool
    payload_hash: str

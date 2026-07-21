"""The pluggable target-adapter contract.

Any agent under test implements `TargetAdapter`. The harness only ever sees
`AdapterResponse` — what the agent said, what it read, and which tool calls it attempted
(with their gate outcomes). The adapter never executes a tool itself; execution outcomes
come from whichever executor (gated PEP or the harness-internal ungated baseline) it was
constructed with.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from tripwire.gate.pep import Refusal, ToolResult
from tripwire.gate.types import ToolCall


@dataclass(frozen=True, slots=True)
class Turn:
    role: str
    content: str


@dataclass(slots=True)
class AdapterResponse:
    text: str
    retrieval_context: list[str] = field(default_factory=list)
    tools_called: list[ToolCall] = field(default_factory=list)
    tool_results: list[ToolResult | Refusal] = field(default_factory=list)


class TargetAdapter(Protocol):
    def invoke(self, input_text: str, turns: list[Turn] | None = None) -> AdapterResponse: ...

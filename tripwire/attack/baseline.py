"""UNGATED measurement baseline — harness-internal, never a production path.

This dispatcher executes mock tools directly so the harness can show what an
intentionally-compliant agent does WITHOUT the gate (the matrix's ungated column).
It exists as a separate class on purpose: the production PEP has no bypass flag,
and INV-6 (capability chokepoint) governs the gated composition only. Mock tools
only — this class refuses to wrap anything else.
"""

from __future__ import annotations

from tripwire.adapter._tools_impl import _build_registry
from tripwire.adapter.mockworld import MockWorld
from tripwire.gate.pep import Refusal, ToolResult
from tripwire.gate.types import ToolCall, Verdict


class UngatedBaselineDispatcher:
    """Executes every known mock tool call directly. FOR MEASUREMENT ONLY."""

    def __init__(self, world: MockWorld) -> None:
        if not isinstance(world, MockWorld):
            raise TypeError("UngatedBaselineDispatcher only wraps the mock world")
        self._registry = _build_registry(world)

    def __call__(self, call: ToolCall) -> ToolResult | Refusal:
        fn = self._registry.get(call.tool)
        if fn is None:
            return Refusal(verdict=Verdict.DENY, reason_code="UNKNOWN_TOOL", escalate=False)
        return ToolResult(tool=call.tool, payload_hash=call.hash, output=fn(**dict(call.args)))

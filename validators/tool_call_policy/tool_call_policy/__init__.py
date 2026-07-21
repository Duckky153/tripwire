"""guardrails/tool_call_policy — a fail-closed authorization validator for agent tool calls.

The pure policy core (`evaluate`, `Decision`) is dependency-free. The `ToolCallPolicy`
Guardrails wrapper is NOT imported here so the core stays usable without guardrails-ai;
import it explicitly from `tool_call_policy.validator` (Guardrails Hub does this for you).
"""

from tool_call_policy.policy import Decision, evaluate

__all__ = ["Decision", "evaluate"]

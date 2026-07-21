"""guardrails/tool_call_policy — a Guardrails Hub validator that authorizes an agent's
tool/function call against an explicit, deny-by-default policy.

Unlike the text/scalar validators on the Hub today, this one runs on a STRUCTURED tool call
({"tool": ..., "args": {...}}) — accepted either as a JSON string or an object. A parse
failure is a FailResult, not an exception that could be swallowed. PassResult is returned
ONLY when the call matches an explicit allow rule with every constraint passing and no
never/escalate block firing. Every other outcome — unknown tool, missing scope, out-of-bound
argument, unconstrained open-world argument, parse failure — returns FailResult.

It NEVER returns a `fix_value`: a dangerous call is never silently "repaired" into an allowed
one. The recommended on_fail is EXCEPTION or REFRAIN.

Inputs via `metadata`:
    policy:          dict — the allow policy (see README for the schema)
    principal_role:  str  — the caller's role (optional; matched against allow rules)
    facts:           dict — trusted world facts (optional; never sourced from the agent)
"""

from __future__ import annotations

import json
from typing import Any

from guardrails.validator_base import (
    FailResult,
    PassResult,
    ValidationResult,
    Validator,
    register_validator,
)

from tool_call_policy.policy import evaluate


@register_validator(name="guardrails/tool_call_policy", data_type=["string", "object"])
class ToolCallPolicy(Validator):
    """Authorize a structured tool call against a deny-by-default policy (fail-closed)."""

    def __init__(self, policy: dict[str, Any] | None = None, on_fail: Any = None, **kwargs: Any):
        super().__init__(on_fail=on_fail, policy=policy, **kwargs)
        self._ctor_policy = policy

    def validate(self, value: Any, metadata: dict[str, Any] | None = None) -> ValidationResult:
        metadata = metadata or {}
        policy = metadata.get("policy", self._ctor_policy)
        if not isinstance(policy, dict):
            return FailResult(error_message="tool_call_policy: no policy provided in metadata")

        # Accept a JSON string or an object; a parse failure is a fail-closed refusal.
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except ValueError as exc:
                return FailResult(
                    error_message=f"tool_call_policy: tool call is not valid JSON ({exc})"
                )
        else:
            parsed = value
        if not isinstance(parsed, dict) or "tool" not in parsed or "args" not in parsed:
            return FailResult(
                error_message="tool_call_policy: expected {'tool': ..., 'args': {...}}"
            )

        tool = parsed.get("tool")
        args = parsed.get("args")
        if not isinstance(tool, str) or not isinstance(args, dict):
            return FailResult(
                error_message="tool_call_policy: 'tool' must be str and 'args' an object"
            )

        decision = evaluate(
            tool, args, policy,
            principal_role=metadata.get("principal_role"),
            facts=metadata.get("facts", {}),
        )
        if decision.verdict == "ALLOW":
            return PassResult()
        return FailResult(
            error_message=(
                f"tool_call_policy: '{tool}' refused — {decision.reason_code}"
                + (f" (rule {decision.matched_rule_id})" if decision.matched_rule_id else "")
            ),
            # No fix_value: a dangerous call is never silently repaired into an allowed one.
        )

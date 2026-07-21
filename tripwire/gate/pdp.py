"""The Policy Decision Point: a pure, total, deterministic verifier.

`decide()` starts at DENY and reaches ALLOW only through an explicit allow-rule match with
every constraint passing and no never/escalate block firing. There is no `else: allow`.
Any internal exception maps to DENY (INV-5). The constraint evaluator is total — a missing
field, type mismatch, or un-coercible value yields False, never an exception that escapes.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

from tripwire.gate.policy_core import STRUCTURAL_OPS, CompiledPolicy, Constraint, Rule, ToolPolicy
from tripwire.gate.types import Decision, ToolCall, Verdict

_MISSING = object()

# Strict single-@ email shape: exactly one @, no @ in local/domain part, and \Z (not $) so a
# trailing newline cannot smuggle past the allowlist (Codex r1 + r2 findings).
_EMAIL_SHAPE = re.compile(r"\A[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\Z")
# Membership ops require a list/tuple value; a scalar would collapse to substring semantics.
_MEMBERSHIP_OPS = frozenset(
    {"in", "not_in", "scheme_in", "host_in_allowlist", "domain_in_allowlist", "template_id_in"}
)


def _safe_hash(request: ToolCall) -> str:
    try:
        return request.hash
    except Exception:
        return "UNHASHABLE"


def _resolve(field: str, request: ToolCall, facts: Mapping[str, Any]) -> Any:
    namespace, _, key = field.partition(".")
    if namespace == "args":
        return request.args.get(key, _MISSING)
    if namespace == "facts":
        return facts.get(key, _MISSING)
    return _MISSING


def _numeric(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _eval_constraint(c: Constraint, request: ToolCall, facts: Mapping[str, Any]) -> bool:
    try:
        lhs = _resolve(c.field, request, facts)
        if lhs is _MISSING:
            return False
        op = c.op
        # Membership ops fail closed on a non-sequence value (no substring fallthrough).
        if op in _MEMBERSHIP_OPS and not isinstance(c.value, (list, tuple)):
            return False
        if op == "eq":
            return bool(lhs == c.value)
        if op == "neq":
            return bool(lhs != c.value)
        if op in ("lt", "lte", "gt", "gte"):
            if not (_numeric(lhs) and _numeric(c.value)):
                return False
            return bool({
                "lt": lhs < c.value, "lte": lhs <= c.value,
                "gt": lhs > c.value, "gte": lhs >= c.value,
            }[op])
        if op == "in":
            return lhs in c.value
        if op == "not_in":
            return lhs not in c.value
        if op == "eq_field":
            other = _resolve(str(c.value), request, facts)
            return other is not _MISSING and bool(lhs == other)
        if op == "scheme_in":
            return isinstance(lhs, str) and urlparse(lhs).scheme in c.value
        if op == "host_in_allowlist":
            if not isinstance(lhs, str):
                return False
            host = urlparse(lhs).hostname
            return host is not None and host.lower() in {str(v).lower() for v in c.value}
        if op == "domain_in_allowlist":
            if not isinstance(lhs, str):
                return False
            m = _EMAIL_SHAPE.match(lhs)
            return m is not None and m.group(1).lower() in {str(v).lower() for v in c.value}
        if op == "template_id_in":
            return lhs in c.value
        return False  # unknown op (compiler should have rejected) -> deny
    except Exception:
        return False


def _role_of(principal: str) -> str:
    return principal.partition(":")[0]


def _block_matches(
    rule: Rule, request: ToolCall, facts: Mapping[str, Any], evaluated: list[tuple[str, bool]]
) -> bool:
    # never/escalate blocks ignore principal_roles; ALL constraints must hold (empty = always).
    results = [_eval_constraint(c, request, facts) for c in rule.constraints]
    evaluated.extend((c.field, ok) for c, ok in zip(rule.constraints, results, strict=True))
    return all(results)


def _allow_rule_matches(
    rule: Rule,
    tool_policy: ToolPolicy,
    request: ToolCall,
    facts: Mapping[str, Any],
    evaluated: list[tuple[str, bool]],
) -> tuple[bool, str]:
    if rule.principal_roles and _role_of(request.principal) not in rule.principal_roles:
        return False, "role"
    # INV-9 defense-in-depth: even a hand-built policy that bypassed the compiler cannot
    # ALLOW an open-world arg that lacks a structural constraint in this rule.
    structural_fields = {c.field for c in rule.constraints if c.op in STRUCTURAL_OPS}
    for arg in tool_policy.open_world_args:
        if f"args.{arg}" not in structural_fields:
            return False, "open_world"
    results = [_eval_constraint(c, request, facts) for c in rule.constraints]
    evaluated.extend((c.field, ok) for c, ok in zip(rule.constraints, results, strict=True))
    if all(results):
        return True, "match"
    return False, "constraint_fail"


def _deny(
    req_hash: str,
    reason: str,
    rule_id: str | None = None,
    evaluated: list[tuple[str, bool]] | None = None,
    *,
    escalate: bool,
) -> Decision:
    return Decision(Verdict.DENY, reason, rule_id, tuple(evaluated or ()), escalate, req_hash)


def decide(request: ToolCall, policy: CompiledPolicy, facts: Mapping[str, Any]) -> Decision:
    verdict = Verdict.DENY  # noqa: F841 — FIRST STATEMENT (spec-required shape). No else:allow below.
    req_hash = _safe_hash(request)  # computed ONCE, exception-proof (Codex r1: totality)
    try:
        tool_policy = policy.tools.get(request.tool)
        if tool_policy is None:
            return _deny(req_hash, "UNKNOWN_TOOL", escalate=True)
        evaluated: list[tuple[str, bool]] = []
        for block in tool_policy.never:
            if _block_matches(block, request, facts, evaluated):
                return _deny(req_hash, "NEVER_BLOCK", block.rule_id, evaluated, escalate=True)
        for block in tool_policy.escalate:
            if _block_matches(block, request, facts, evaluated):
                return Decision(
                    Verdict.ESCALATE, "ESCALATE_BLOCK", block.rule_id,
                    tuple(evaluated), True, req_hash,
                )
        any_constraint_fail = False
        for rule in tool_policy.allow:
            ok, why = _allow_rule_matches(rule, tool_policy, request, facts, evaluated)
            if ok:
                return Decision(
                    Verdict.ALLOW, "RULE_MATCH", rule.rule_id,
                    tuple(evaluated), False, req_hash,
                )
            if why == "constraint_fail":
                any_constraint_fail = True
        reason = "CONSTRAINT_FAIL" if any_constraint_fail else "NO_MATCH"
        return _deny(req_hash, reason, None, evaluated, escalate=True)
    except Exception:
        return _deny(req_hash, "INTERNAL_ERROR", escalate=True)

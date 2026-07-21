"""Vendored, dependency-free policy core for the standalone Guardrails Hub validator.

This is a minimal copy of tripwire's deny-by-default policy semantics so the published Hub
validator is installable on its own (it must not depend on the tripwire package). Behavioral
equality with tripwire's own gate is asserted by a cross-test in the tripwire repo.

Fail-closed by construction: `evaluate()` starts at DENY and reaches ALLOW only through an
explicit allow-rule match with every constraint passing and no never/escalate block firing.
There is no `else: allow`; any internal error maps to DENY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

KNOWN_OPS = frozenset({
    "eq", "neq", "lt", "lte", "gt", "gte", "in", "not_in", "eq_field",
    "scheme_in", "host_in_allowlist", "domain_in_allowlist", "template_id_in",
})
STRUCTURAL_OPS = frozenset(
    {"scheme_in", "host_in_allowlist", "domain_in_allowlist", "template_id_in", "in"}
)
# \Z (not $) so a trailing newline cannot smuggle past the allowlist.
_EMAIL_SHAPE = re.compile(r"\A[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\Z")
_MEMBERSHIP_OPS = frozenset(
    {"in", "not_in", "scheme_in", "host_in_allowlist", "domain_in_allowlist", "template_id_in"}
)
_MISSING = object()


@dataclass(frozen=True)
class Decision:
    verdict: str           # "DENY" | "ESCALATE" | "ALLOW"
    reason_code: str
    matched_rule_id: str | None = None


def _numeric(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _resolve(field: str, args: dict[str, Any], facts: dict[str, Any]) -> Any:
    ns, _, key = field.partition(".")
    if ns == "args":
        return args.get(key, _MISSING)
    if ns == "facts":
        return facts.get(key, _MISSING)
    return _MISSING


def _eval(constraint: dict[str, Any], args: dict[str, Any], facts: dict[str, Any]) -> bool:
    try:
        op = constraint["op"]
        if op not in KNOWN_OPS:
            return False
        lhs = _resolve(str(constraint["field"]), args, facts)
        if lhs is _MISSING:
            return False
        value = constraint.get("value")
        # Membership ops require a list/tuple value; a scalar would collapse to substring
        # semantics, so a scalar value fails closed (returns False).
        if op in _MEMBERSHIP_OPS and not isinstance(value, (list, tuple)):
            return False
        seq = tuple(value) if isinstance(value, (list, tuple)) else value
        if op == "eq":
            return bool(lhs == value)
        if op == "neq":
            return bool(lhs != value)
        if op in ("lt", "lte", "gt", "gte"):
            if not (_numeric(lhs) and _numeric(value)):
                return False
            return bool({"lt": lhs < value, "lte": lhs <= value,
                         "gt": lhs > value, "gte": lhs >= value}[op])
        if op == "in":
            return lhs in seq  # type: ignore[operator]
        if op == "not_in":
            return lhs not in seq  # type: ignore[operator]
        if op == "eq_field":
            other = _resolve(str(value), args, facts)
            return other is not _MISSING and bool(lhs == other)
        if op == "scheme_in":
            return isinstance(lhs, str) and urlparse(lhs).scheme in seq  # type: ignore[operator]
        if op == "host_in_allowlist":
            if not isinstance(lhs, str):
                return False
            host = urlparse(lhs).hostname
            return host is not None and host.lower() in {str(v).lower() for v in seq}  # type: ignore[union-attr]
        if op == "domain_in_allowlist":
            if not isinstance(lhs, str):
                return False
            m = _EMAIL_SHAPE.match(lhs)
            return m is not None and m.group(1).lower() in {str(v).lower() for v in seq}  # type: ignore[union-attr]
        if op == "template_id_in":
            return lhs in seq  # type: ignore[operator]
        return False
    except Exception:
        return False


def evaluate(
    tool: str,
    args: dict[str, Any],
    policy: dict[str, Any],
    *,
    principal_role: str | None = None,
    facts: dict[str, Any] | None = None,
) -> Decision:
    """Deny-by-default decision over a single tool call. Total; never raises."""
    verdict = "DENY"  # noqa: F841 — first statement; no else:allow below
    facts = facts or {}
    try:
        tools = policy.get("tools", {})
        tp = tools.get(tool)
        if tp is None:
            return Decision("DENY", "UNKNOWN_TOOL")
        open_world = [str(a) for a in tp.get("open_world_args", [])]
        for block in tp.get("never", []):
            if all(_eval(c, args, facts) for c in block.get("constraints", [])):
                return Decision("DENY", "NEVER_BLOCK", block.get("rule_id"))
        for block in tp.get("escalate", []):
            if all(_eval(c, args, facts) for c in block.get("constraints", [])):
                return Decision("ESCALATE", "ESCALATE_BLOCK", block.get("rule_id"))
        constraint_fail = False
        for rule in tp.get("allow", []):
            roles = [str(r) for r in rule.get("principal_roles", [])]
            if roles and principal_role not in roles:
                continue
            constraints = rule.get("constraints", [])
            structural = {str(c["field"]) for c in constraints if c.get("op") in STRUCTURAL_OPS}
            if any(f"args.{a}" not in structural for a in open_world):
                continue  # INV-9: unconstrained open-world arg can never ALLOW
            if all(_eval(c, args, facts) for c in constraints):
                return Decision("ALLOW", "RULE_MATCH", rule.get("rule_id"))
            constraint_fail = True
        return Decision("DENY", "CONSTRAINT_FAIL" if constraint_fail else "NO_MATCH")
    except Exception:
        return Decision("DENY", "INTERNAL_ERROR")

"""Policy DSL compiler.

Compiles a declarative deny-by-default YAML allowlist into an immutable decision table.
Fail-closed at load: an absent, malformed, or hash-mismatched policy raises PolicyLoadError,
which the gate maps to global-DENY. INV-9 is enforced HERE, at compile time: an allow rule on
an open-world argument (a URL or a free-text email body) that lacks a structural constraint
(host/domain/scheme allowlist, template id, or value-set membership) is rejected — a permissive
open-world allow can never be loaded.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from tripwire.gate.types import canonical_json, payload_hash

# Closed operator set. Anything else => PolicyLoadError.
KNOWN_OPS = frozenset(
    {
        "eq", "neq", "lt", "lte", "gt", "gte", "in", "not_in", "eq_field",
        "scheme_in", "host_in_allowlist", "domain_in_allowlist", "template_id_in",
    }
)
# Ops that count as a *structural* constraint on an open-world argument (INV-9).
STRUCTURAL_OPS = frozenset(
    {"scheme_in", "host_in_allowlist", "domain_in_allowlist", "template_id_in", "in"}
)
MEMBERSHIP_OPS = frozenset(
    {"in", "not_in", "scheme_in", "host_in_allowlist", "domain_in_allowlist", "template_id_in"}
)


class PolicyLoadError(Exception):
    """Raised on any load/parse/validation failure. The gate treats it as global-DENY."""


@dataclass(frozen=True, slots=True)
class Constraint:
    field: str
    op: str
    value: Any


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    principal_roles: tuple[str, ...]
    constraints: tuple[Constraint, ...]


@dataclass(frozen=True, slots=True)
class ToolPolicy:
    name: str
    high_stakes: bool
    open_world_args: tuple[str, ...]
    never: tuple[Rule, ...]
    escalate: tuple[Rule, ...]
    allow: tuple[Rule, ...]


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    version: int
    tools: Mapping[str, ToolPolicy]
    content_hash: str


def _err(msg: str) -> PolicyLoadError:
    return PolicyLoadError(msg)


def _constraint(raw: Any) -> Constraint:
    if not isinstance(raw, Mapping) or "field" not in raw or "op" not in raw:
        raise _err(f"malformed constraint: {raw!r}")
    op = raw["op"]
    if op not in KNOWN_OPS:
        raise _err(f"unknown op {op!r} (known: {sorted(KNOWN_OPS)})")
    field = raw["field"]
    if not isinstance(field, str) or not (field.startswith("args.") or field.startswith("facts.")):
        raise _err(f"constraint field must be args.* or facts.*: {field!r}")
    value = raw.get("value")
    if op in MEMBERSHIP_OPS and not isinstance(value, (list, tuple)):
        raise _err(f"membership op {op!r} requires a list value, got {type(value).__name__}")
    if isinstance(value, list):
        value = tuple(value)
    return Constraint(field=field, op=op, value=value)


def _rule(raw: Any, *, allow: bool) -> Rule:
    if not isinstance(raw, Mapping) or "rule_id" not in raw:
        raise _err(f"malformed rule: {raw!r}")
    roles = raw.get("principal_roles", [])
    if not isinstance(roles, Sequence) or isinstance(roles, str):
        raise _err(f"principal_roles must be a list: {raw['rule_id']!r}")
    constraints = raw.get("constraints", [])
    if not isinstance(constraints, Sequence) or isinstance(constraints, str):
        raise _err(f"constraints must be a list: {raw['rule_id']!r}")
    return Rule(
        rule_id=str(raw["rule_id"]),
        principal_roles=tuple(str(r) for r in roles),
        constraints=tuple(_constraint(c) for c in constraints),
    )


def _check_inv9(tool_name: str, open_world: tuple[str, ...], allow: tuple[Rule, ...]) -> None:
    for rule in allow:
        constrained_fields = {
            c.field for c in rule.constraints if c.op in STRUCTURAL_OPS
        }
        for arg in open_world:
            if f"args.{arg}" not in constrained_fields:
                raise _err(
                    f"INV-9: open-world arg '{arg}' on tool '{tool_name}' allow rule "
                    f"'{rule.rule_id}' lacks a structural constraint "
                    f"(one of {sorted(STRUCTURAL_OPS)})"
                )


def _tool_policy(name: str, raw: Any) -> ToolPolicy:
    if not isinstance(raw, Mapping):
        raise _err(f"tool '{name}' must be a mapping")
    open_world = tuple(str(a) for a in raw.get("open_world_args", []))
    allow = tuple(_rule(r, allow=True) for r in raw.get("allow", []))
    _check_inv9(name, open_world, allow)
    return ToolPolicy(
        name=name,
        high_stakes=bool(raw.get("high_stakes", True)),
        open_world_args=open_world,
        never=tuple(_rule(r, allow=False) for r in raw.get("never", [])),
        escalate=tuple(_rule(r, allow=False) for r in raw.get("escalate", [])),
        allow=allow,
    )


def compile_policy(path: Path, *, expected_hash: str | None = None) -> CompiledPolicy:
    """Load + validate + freeze. Any failure raises PolicyLoadError (fail-closed)."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise _err(f"cannot read policy {path}: {exc}") from exc
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise _err(f"malformed YAML in {path}: {exc}") from exc
    if not isinstance(raw, Mapping) or "tools" not in raw:
        raise _err("policy must be a mapping with a 'tools' key")
    tools_raw = raw["tools"]
    if not isinstance(tools_raw, Mapping) or not tools_raw:
        raise _err("'tools' must be a non-empty mapping")

    content_hash = payload_hash("__policy__", {"canonical": canonical_json(raw)})
    if expected_hash is not None and expected_hash != content_hash:
        raise _err(f"policy hash mismatch: expected {expected_hash}, got {content_hash}")

    tools = {name: _tool_policy(name, body) for name, body in tools_raw.items()}
    return CompiledPolicy(
        version=int(raw.get("version", 1)), tools=tools, content_hash=content_hash
    )

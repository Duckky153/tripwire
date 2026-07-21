"""Property tests for the fail-closed invariants (INV-1, 2, 3, 5, 7, 9 — PDP + compiler).

These tests ARE the by-construction claim: "no ALLOW without an explicit matching rule with
all constraints passing." Run counts are measured and reported in docs/HONESTY.md.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest import mock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import tripwire.gate.pdp as pdp_module
from tripwire.gate.pdp import _block_matches, decide
from tripwire.gate.policy_core import (
    STRUCTURAL_OPS,
    CompiledPolicy,
    Constraint,
    PolicyLoadError,
    Rule,
    ToolPolicy,
    compile_policy,
)
from tripwire.gate.types import Verdict

from .strategies import compiled_policies, facts, tool_calls

EXAMPLES = 300


# ---------------------------------------------------------------- INV-1: default-deny totality
@settings(max_examples=EXAMPLES)
@given(policy=compiled_policies(), call=tool_calls(), world=facts())
def test_inv1_decide_is_total_and_never_raises(policy, call, world) -> None:  # type: ignore[no-untyped-def]
    d = decide(call, policy, world)
    assert d.verdict in (Verdict.DENY, Verdict.ESCALATE, Verdict.ALLOW)
    assert d.payload_hash == call.hash


# ----------------------------------------------------- INV-2: no ALLOW without a matching rule
@settings(max_examples=EXAMPLES)
@given(policy=compiled_policies(), call=tool_calls(), world=facts())
def test_inv2_allow_implies_real_rule_and_no_blocks(policy, call, world) -> None:  # type: ignore[no-untyped-def]
    d = decide(call, policy, world)
    if d.verdict is not Verdict.ALLOW:
        return
    tool_policy = policy.tools[call.tool]
    allow_ids = {r.rule_id for r in tool_policy.allow}
    assert d.matched_rule_id in allow_ids
    # Independently re-check: no never/escalate block matches this request.
    scratch: list[tuple[str, bool]] = []
    assert not any(_block_matches(b, call, world, scratch) for b in tool_policy.never)
    assert not any(_block_matches(b, call, world, scratch) for b in tool_policy.escalate)
    # And the matched rule's constraints all pass when re-evaluated.
    rule = next(r for r in tool_policy.allow if r.rule_id == d.matched_rule_id)
    assert all(pdp_module._eval_constraint(c, call, world) for c in rule.constraints)
    assert d.escalate is False


# --------------------------------------------------------------- INV-3: never-block precedence
@settings(max_examples=EXAMPLES)
@given(policy=compiled_policies(), call=tool_calls(), world=facts())
def test_inv3_matching_never_block_always_denies(policy, call, world) -> None:  # type: ignore[no-untyped-def]
    if call.tool not in policy.tools:
        return
    base = policy.tools[call.tool]
    # Inject a guaranteed-matching never-block (empty constraints == always matches).
    rigged = ToolPolicy(
        name=base.name,
        high_stakes=base.high_stakes,
        open_world_args=base.open_world_args,
        never=(Rule(rule_id="never-always", principal_roles=(), constraints=()),) + base.never,
        escalate=base.escalate,
        allow=base.allow,
    )
    rigged_policy = CompiledPolicy(
        version=1, tools={**dict(policy.tools), base.name: rigged}, content_hash="0" * 64
    )
    d = decide(call, rigged_policy, world)
    assert d.verdict is Verdict.DENY
    assert d.reason_code == "NEVER_BLOCK"
    assert d.escalate is True


# ------------------------------------------------------------------ INV-5: fail-closed-on-error
@settings(max_examples=100)
@given(policy=compiled_policies(), call=tool_calls(), world=facts())
def test_inv5_internal_exception_never_allows_through_constraints(policy, call, world) -> None:  # type: ignore[no-untyped-def]
    """Under fault injection, ALLOW is reachable ONLY via a rule with zero constraints —
    an explicit allow-all the policy author wrote (the verifier honors the policy; it never
    exceeds it). Any rule whose constraints would need EVALUATING can never allow on error."""
    with mock.patch.object(
        pdp_module, "_eval_constraint", side_effect=RuntimeError("injected fault")
    ):
        d = decide(call, policy, world)
    if d.verdict is Verdict.ALLOW:
        rule = next(
            r for r in policy.tools[call.tool].allow if r.rule_id == d.matched_rule_id
        )
        assert rule.constraints == ()
    # Any DENY/ESCALATE reason is fail-closed (e.g. an empty-constraint never-block
    # still fires under fault injection — strictly more restrictive, which is correct).


@settings(max_examples=100)
@given(call=tool_calls(), world=facts())
def test_inv5_fault_during_constraint_eval_denies(call, world) -> None:  # type: ignore[no-untyped-def]
    """Deterministic core of INV-5: a constraint-bearing allow rule + an evaluator fault
    can never yield ALLOW."""
    rule = Rule(
        rule_id="needs-eval",
        principal_roles=(),
        constraints=(Constraint(field="args.amount_cents", op="lte", value=100),),
    )
    tp = ToolPolicy(
        name=call.tool, high_stakes=True, open_world_args=(),
        never=(), escalate=(), allow=(rule,),
    )
    policy = CompiledPolicy(version=1, tools={call.tool: tp}, content_hash="0" * 64)
    with mock.patch.object(
        pdp_module, "_eval_constraint", side_effect=RuntimeError("injected fault")
    ):
        d = decide(call, policy, world)
    assert d.verdict is not Verdict.ALLOW


@settings(max_examples=EXAMPLES)
@given(call=tool_calls(), world=facts())
def test_inv5_missing_facts_never_allow_through_fact_rules(call, world) -> None:  # type: ignore[no-untyped-def]
    """A rule whose constraints reference facts.* cannot ALLOW when facts are empty."""
    rule = Rule(
        rule_id="needs-facts",
        principal_roles=(),
        constraints=(Constraint(field="facts.order_exists", op="eq", value=True),),
    )
    tp = ToolPolicy(
        name=call.tool, high_stakes=True, open_world_args=(),
        never=(), escalate=(), allow=(rule,),
    )
    policy = CompiledPolicy(version=1, tools={call.tool: tp}, content_hash="0" * 64)
    d = decide(call, policy, {})
    assert d.verdict is not Verdict.ALLOW


# ------------------------------------------------------------------- INV-7: policy-load fail-closed
@settings(max_examples=60)
@given(garbage=st.binary(min_size=1, max_size=200))
def test_inv7_garbage_policy_bytes_raise(tmp_path_factory, garbage) -> None:  # type: ignore[no-untyped-def]
    tmp = tmp_path_factory.mktemp("pol")
    p = tmp / "p.yaml"
    p.write_bytes(garbage)
    try:
        pol = compile_policy(p)
    except PolicyLoadError:
        return  # fail-closed: load refused
    # If garbage happened to parse as YAML, it must still be a valid policy shape.
    assert pol.tools


def test_inv7_absent_and_hash_mismatch(tmp_path: Path) -> None:
    with pytest.raises(PolicyLoadError):
        compile_policy(tmp_path / "missing.yaml")
    p = tmp_path / "p.yaml"
    p.write_text(
        textwrap.dedent(
            """
            version: 1
            tools:
              delete_record:
                high_stakes: true
                open_world_args: []
                escalate: [{rule_id: e, constraints: []}]
            """
        )
    )
    with pytest.raises(PolicyLoadError):
        compile_policy(p, expected_hash="f" * 64)


# ------------------------------------------------------------ INV-9: open-world compile rejection
_NON_STRUCTURAL = sorted(
    {"eq", "neq", "lt", "lte", "gt", "gte", "not_in", "eq_field"}
)


@settings(max_examples=100)
@given(
    arg=st.sampled_from(["url", "body", "to"]),
    op=st.sampled_from(_NON_STRUCTURAL),
    extra_field=st.sampled_from(["args.note", "facts.order_exists"]),
)
def test_inv9_compiler_rejects_unconstrained_open_world_allow(
    tmp_path_factory, arg, op, extra_field
) -> None:  # type: ignore[no-untyped-def]
    tmp = tmp_path_factory.mktemp("pol9")
    body = f"""
    version: 1
    tools:
      open_tool:
        high_stakes: true
        open_world_args: [{arg}]
        allow:
          - rule_id: r1
            principal_roles: [support_agent]
            constraints:
              - {{field: args.{arg}, op: {op}, value: x}}
              - {{field: {extra_field}, op: eq, value: ok}}
    """
    p = tmp / "p.yaml"
    p.write_text(textwrap.dedent(body))
    # Both are fail-closed compiler rejections: INV-9 (unconstrained open-world) OR the
    # membership-op-needs-a-list check (not_in with a scalar value trips it first).
    with pytest.raises(PolicyLoadError, match="INV-9|membership op"):
        compile_policy(p)


@settings(max_examples=100)
@given(call=tool_calls(), world=facts(), op=st.sampled_from(_NON_STRUCTURAL))
def test_inv9_defense_in_depth_hand_built_policy_cannot_allow(call, world, op) -> None:  # type: ignore[no-untyped-def]
    """Even a hand-constructed policy (bypassing the compiler) cannot ALLOW an
    open-world arg lacking a structural constraint (the PDP re-checks)."""
    rule = Rule(
        rule_id="sneaky-allow",
        principal_roles=(),
        constraints=(Constraint(field="args.url", op=op, value="x"),),
    )
    tp = ToolPolicy(
        name=call.tool, high_stakes=True, open_world_args=("url",),
        never=(), escalate=(), allow=(rule,),
    )
    policy = CompiledPolicy(version=1, tools={call.tool: tp}, content_hash="0" * 64)
    d = decide(call, policy, world)
    assert d.verdict is not Verdict.ALLOW


def test_structural_ops_is_subset_of_known_ops() -> None:
    from tripwire.gate.policy_core import KNOWN_OPS

    assert STRUCTURAL_OPS <= KNOWN_OPS

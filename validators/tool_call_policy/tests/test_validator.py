"""Tests for the guardrails/tool_call_policy validator.

Most tests hit the pure policy core (no guardrails dependency). The wrapper tests require
guardrails-ai and skip cleanly if it is not installed.
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from tool_call_policy.policy import evaluate

_POLICY = {
    "tools": {
        "issue_refund": {
            "open_world_args": [],
            "never": [
                {"rule_id": "never-huge", "constraints": [
                    {"field": "args.amount_cents", "op": "gt", "value": 50000}]},
            ],
            "escalate": [
                {"rule_id": "esc-over-cap", "constraints": [
                    {"field": "args.amount_cents", "op": "gt", "value": 20000}]},
            ],
            "allow": [
                {"rule_id": "refund-ok", "principal_roles": ["support_agent"], "constraints": [
                    {"field": "args.amount_cents", "op": "lte", "value": 20000},
                    {"field": "facts.order_exists", "op": "eq", "value": True}]},
            ],
        },
        "send_email": {
            "open_world_args": ["to", "body"],
            "allow": [
                {"rule_id": "email-templated", "principal_roles": ["support_agent"],
                 "constraints": [
                    {"field": "args.to", "op": "domain_in_allowlist", "value": ["example.test"]},
                    {"field": "args.body", "op": "template_id_in", "value": ["order_status_v1"]}]},
            ],
        },
    }
}


def test_allow_on_full_match() -> None:
    d = evaluate("issue_refund", {"amount_cents": 5000}, _POLICY,
                 principal_role="support_agent", facts={"order_exists": True})
    assert d.verdict == "ALLOW"


def test_never_block_beats_allow() -> None:
    d = evaluate("issue_refund", {"amount_cents": 60000}, _POLICY,
                 principal_role="support_agent", facts={"order_exists": True})
    assert d.verdict == "DENY" and d.reason_code == "NEVER_BLOCK"


def test_escalate_band() -> None:
    d = evaluate("issue_refund", {"amount_cents": 30000}, _POLICY,
                 principal_role="support_agent", facts={"order_exists": True})
    assert d.verdict == "ESCALATE"


def test_missing_fact_denies() -> None:
    d = evaluate("issue_refund", {"amount_cents": 5000}, _POLICY, principal_role="support_agent")
    assert d.verdict == "DENY"


def test_wrong_role_denies() -> None:
    d = evaluate("issue_refund", {"amount_cents": 5000}, _POLICY,
                 principal_role="intruder", facts={"order_exists": True})
    assert d.verdict == "DENY"


def test_unknown_tool_denies() -> None:
    assert evaluate("launch", {}, _POLICY).verdict == "DENY"


def test_double_at_email_denied() -> None:
    d = evaluate("send_email", {"to": "victim@evil.test@example.test", "body": "order_status_v1"},
                 _POLICY, principal_role="support_agent")
    assert d.verdict == "DENY"


def test_clean_templated_email_allowed() -> None:
    d = evaluate("send_email", {"to": "x@example.test", "body": "order_status_v1"},
                 _POLICY, principal_role="support_agent")
    assert d.verdict == "ALLOW"


def test_open_world_unconstrained_allow_rejected() -> None:
    bad = {"tools": {"send_email": {"open_world_args": ["to"], "allow": [
        {"rule_id": "open", "principal_roles": ["support_agent"], "constraints": [
            {"field": "args.note", "op": "eq", "value": "ok"}]}]}}}
    d = evaluate("send_email", {"to": "x@example.test", "note": "ok"}, bad,
                 principal_role="support_agent")
    assert d.verdict == "DENY"  # open-world 'to' lacks a structural constraint


@settings(max_examples=300)
@given(
    tool=st.sampled_from(["issue_refund", "send_email", "unknown"]),
    args=st.dictionaries(
        st.sampled_from(["amount_cents", "to", "body", "note"]),
        st.one_of(st.integers(-(10**7), 10**7), st.text(max_size=30), st.booleans()),
        max_size=4,
    ),
    role=st.sampled_from(["support_agent", "intruder", None]),
    facts=st.dictionaries(st.sampled_from(["order_exists"]), st.booleans(), max_size=1),
)
def test_fail_closed_property_no_allow_without_full_match(  # type: ignore[no-untyped-def]
    tool, args, role, facts
) -> None:
    """No generated input reaches ALLOW without a real allow-rule match."""
    d = evaluate(tool, args, _POLICY, principal_role=role, facts=facts)
    assert d.verdict in ("ALLOW", "DENY", "ESCALATE")
    if d.verdict == "ALLOW":
        tp = _POLICY["tools"][tool]
        rule = next(r for r in tp["allow"] if r["rule_id"] == d.matched_rule_id)  # type: ignore[index]
        assert role in rule["principal_roles"]


# ---- wrapper tests (require guardrails-ai) ------------------------------------------------
guardrails = pytest.importorskip("guardrails")


def _validator():  # type: ignore[no-untyped-def]
    from tool_call_policy.validator import ToolCallPolicy

    return ToolCallPolicy(policy=_POLICY)


def test_wrapper_pass_on_allowed_json_string() -> None:
    from guardrails.validator_base import PassResult

    v = _validator()
    call = json.dumps({"tool": "issue_refund", "args": {"amount_cents": 5000}})
    result = v.validate(call, {"principal_role": "support_agent", "facts": {"order_exists": True}})
    assert isinstance(result, PassResult)


def test_wrapper_fail_on_over_cap() -> None:
    from guardrails.validator_base import FailResult

    v = _validator()
    call = {"tool": "issue_refund", "args": {"amount_cents": 600000}}
    result = v.validate(call, {"principal_role": "support_agent", "facts": {"order_exists": True}})
    assert isinstance(result, FailResult)
    assert result.fix_value is None  # never repairs a dangerous call


def test_wrapper_fail_on_unparseable_json() -> None:
    from guardrails.validator_base import FailResult

    v = _validator()
    assert isinstance(v.validate("{not json", {}), FailResult)


# ---- Codex round-2 regression tests ------------------------------------------------------
def test_membership_op_scalar_value_fails_closed() -> None:
    bad = {"tools": {"send_email": {"open_world_args": ["body"], "allow": [
        {"rule_id": "r", "principal_roles": ["support_agent"], "constraints": [
            {"field": "args.body", "op": "template_id_in", "value": "order_status_v1"}]}]}}}
    # a scalar value would substring-match "order_status_v"; it must fail closed instead
    d = evaluate("send_email", {"body": "order_status_v"}, bad, principal_role="support_agent")
    assert d.verdict == "DENY"


def test_trailing_newline_email_denied() -> None:
    pol = {"tools": {"send_email": {"open_world_args": ["to", "body"], "allow": [
        {"rule_id": "r", "principal_roles": ["support_agent"], "constraints": [
            {"field": "args.to", "op": "domain_in_allowlist", "value": ["example.test"]},
            {"field": "args.body", "op": "template_id_in", "value": ["order_status_v1"]}]}]}}}
    d = evaluate("send_email", {"to": "x@example.test\n", "body": "order_status_v1"},
                 pol, principal_role="support_agent")
    assert d.verdict == "DENY"


def test_wrapper_missing_args_key_fails() -> None:
    from guardrails.validator_base import FailResult

    v = _validator()
    result = v.validate('{"tool": "issue_refund"}', {"principal_role": "support_agent"})
    assert isinstance(result, FailResult)


def test_core_importable_without_guardrails() -> None:
    # __init__ must not pull guardrails — the pure core stays dependency-free.
    import ast
    from pathlib import Path

    init = Path(__file__).resolve().parents[1] / "tool_call_policy" / "__init__.py"
    tree = ast.parse(init.read_text())
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert not any("validator" in (m or "") for m in imported)

from __future__ import annotations

import textwrap
from pathlib import Path

from tripwire.gate.pdp import decide
from tripwire.gate.policy_core import compile_policy
from tripwire.gate.types import ToolCall, Verdict


def _policy(tmp_path: Path) -> object:
    body = """
    version: 1
    tools:
      issue_refund:
        high_stakes: true
        open_world_args: []
        never:
          - rule_id: never-huge
            constraints: [{field: args.amount_cents, op: gt, value: 50000}]
        escalate:
          - rule_id: esc-over-cap
            constraints: [{field: args.amount_cents, op: gt, value: 20000}]
        allow:
          - rule_id: refund-ok
            principal_roles: [support_agent]
            constraints:
              - {field: args.amount_cents, op: lte, value: 20000}
              - {field: facts.order_exists, op: eq, value: true}
      read_customer_db:
        high_stakes: true
        open_world_args: []
        allow:
          - rule_id: read-ok
            principal_roles: [support_agent]
            constraints:
              - {field: args.query_field, op: in, value: [order_status]}
    """
    p = tmp_path / "p.yaml"
    p.write_text(textwrap.dedent(body))
    return compile_policy(p)


def _call(tool: str, principal: str = "support_agent:jordan", **args: object) -> ToolCall:
    return ToolCall(tool, args, principal, "s", "a", "t", "2026-06-09T00:00:00Z")


def test_unknown_tool_denies(tmp_path: Path) -> None:
    d = decide(_call("launch_missiles"), _policy(tmp_path), {})
    assert d.verdict is Verdict.DENY and d.reason_code == "UNKNOWN_TOOL"


def test_full_allow_match(tmp_path: Path) -> None:
    d = decide(_call("issue_refund", amount_cents=5000), _policy(tmp_path), {"order_exists": True})
    assert d.verdict is Verdict.ALLOW
    assert d.reason_code == "RULE_MATCH" and d.matched_rule_id == "refund-ok"
    assert d.escalate is False


def test_never_block_beats_allow(tmp_path: Path) -> None:
    # amount over the never threshold AND otherwise would be... never wins -> DENY
    d = decide(_call("issue_refund", amount_cents=60000), _policy(tmp_path), {"order_exists": True})
    assert d.verdict is Verdict.DENY and d.reason_code == "NEVER_BLOCK"
    assert d.matched_rule_id == "never-huge" and d.escalate is True


def test_escalate_block(tmp_path: Path) -> None:
    d = decide(_call("issue_refund", amount_cents=30000), _policy(tmp_path), {"order_exists": True})
    assert d.verdict is Verdict.ESCALATE and d.reason_code == "ESCALATE_BLOCK"


def test_failed_constraint_denies_with_constraint_fail(tmp_path: Path) -> None:
    # within cap but order does not exist -> the allow rule's constraint fails
    d = decide(_call("issue_refund", amount_cents=5000), _policy(tmp_path), {"order_exists": False})
    assert d.verdict is Verdict.DENY and d.reason_code == "CONSTRAINT_FAIL"


def test_missing_fact_denies(tmp_path: Path) -> None:
    # facts missing order_exists entirely -> constraint fails -> deny (INV-5 shape)
    d = decide(_call("issue_refund", amount_cents=5000), _policy(tmp_path), {})
    assert d.verdict is Verdict.DENY


def test_wrong_principal_role_denies(tmp_path: Path) -> None:
    d = decide(
        _call("issue_refund", principal="intruder:x", amount_cents=5000),
        _policy(tmp_path),
        {"order_exists": True},
    )
    assert d.verdict is Verdict.DENY


def test_no_rules_match_denies_no_match(tmp_path: Path) -> None:
    # role mismatch means no allow rule is even evaluated -> NO_MATCH (vs CONSTRAINT_FAIL)
    d = decide(
        _call("read_customer_db", principal="intruder:x", query_field="order_status"),
        _policy(tmp_path),
        {},
    )
    assert d.verdict is Verdict.DENY and d.reason_code == "NO_MATCH"


def test_in_op_allows(tmp_path: Path) -> None:
    d = decide(_call("read_customer_db", query_field="order_status"), _policy(tmp_path), {})
    assert d.verdict is Verdict.ALLOW


def test_payload_hash_recorded(tmp_path: Path) -> None:
    c = _call("issue_refund", amount_cents=5000)
    d = decide(c, _policy(tmp_path), {"order_exists": True})
    assert d.payload_hash == c.hash

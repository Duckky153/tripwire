from __future__ import annotations

import pytest

from tripwire.gate.types import Decision, JudgeVote, ToolCall, Verdict, canonical_json, payload_hash


def _call(tool: str = "issue_refund", **args: object) -> ToolCall:
    return ToolCall(
        tool=tool,
        args=args or {"amount_cents": 500},
        principal="support_agent:jordan.sample",
        session_id="s1",
        agent_id="a1",
        trace_id="t1",
        ts="2026-06-09T00:00:00Z",
    )


def test_toolcall_is_immutable() -> None:
    c = _call()
    with pytest.raises((AttributeError, TypeError)):
        c.tool = "delete_record"  # type: ignore[misc]


def test_toolcall_args_cannot_be_mutated() -> None:
    c = _call(amount_cents=500)
    with pytest.raises(TypeError):
        c.args["amount_cents"] = 999999  # type: ignore[index]


def test_payload_hash_stable_under_key_order() -> None:
    h1 = payload_hash("send_email", {"to": "x@example.test", "body": "hi"})
    h2 = payload_hash("send_email", {"body": "hi", "to": "x@example.test"})
    assert h1 == h2
    assert len(h1) == 64 and all(c in "0123456789abcdef" for c in h1)


def test_payload_hash_changes_with_any_arg() -> None:
    base = payload_hash("issue_refund", {"amount_cents": 500})
    assert base != payload_hash("issue_refund", {"amount_cents": 501})
    assert base != payload_hash("issue_refund", {"amount_cents": 500, "note": "x"})
    assert base != payload_hash("delete_record", {"amount_cents": 500})


def test_toolcall_hash_matches_payload_hash() -> None:
    c = _call(amount_cents=500)
    assert c.hash == payload_hash("issue_refund", {"amount_cents": 500})


def test_canonical_json_is_sorted_and_compact() -> None:
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_decision_is_immutable() -> None:
    d = Decision(Verdict.DENY, "NO_MATCH", None, (), True, "deadbeef")
    with pytest.raises((AttributeError, TypeError)):
        d.verdict = Verdict.ALLOW  # type: ignore[misc]


def test_verdict_and_judgevote_enums() -> None:
    assert {v.value for v in Verdict} == {"deny", "escalate", "allow"}
    assert {v.value for v in JudgeVote} == {"deny", "escalate", "abstain"}

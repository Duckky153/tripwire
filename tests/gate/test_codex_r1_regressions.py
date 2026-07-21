"""Regression tests for Codex adversarial-review round 1 findings (all exploit-verified).

Each test replicates the reviewer's exact exploit and pins the fix.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tripwire.adapter.mockworld import MockWorld
from tripwire.gate.audit import AuditLoom, make_record
from tripwire.gate.pdp import decide
from tripwire.gate.pep import Refusal, RefusalError, build_default_pep
from tripwire.gate.policy_core import compile_policy
from tripwire.gate.types import JudgeVote, ToolCall, Verdict

POLICY = Path(__file__).resolve().parents[2] / "tripwire" / "policies" / "default.yaml"


def _pep(tmp_path: Path):  # type: ignore[no-untyped-def]
    world = MockWorld(seed=42)
    return (
        build_default_pep(policy_path=POLICY, world=world, audit_path=tmp_path / "a.jsonl"),
        world,
    )


def _call(tool: str, **args: object) -> ToolCall:
    return ToolCall(
        tool, args, "support_agent:jordan", "sess-1", "agent-1", "t1", "2026-06-09T00:00:00Z"
    )


# ---- BLOCKER: in-process token forgery via dispatcher internals -------------------------
def test_r1_blocker_injected_token_cannot_execute(tmp_path: Path) -> None:
    pep, world = _pep(tmp_path)
    call = _call("delete_record", record_id="ord-2001")

    # The reviewer's exploit injected into dispatcher._live; that attribute no longer exists.
    assert not hasattr(pep.dispatcher, "_live")

    # Even reaching the name-mangled set AND crafting a field-perfect token must fail:
    # the MAC requires the dispatcher's private key.
    from tripwire.gate import pep as pep_module

    token = pep_module._ExecutionToken(
        tool=call.tool, payload_hash=call.hash, nonce="n" * 32, mac="0" * 64
    )
    live = pep.dispatcher._Dispatcher__live  # type: ignore[attr-defined]  # noqa: SLF001
    live.add("n" * 32)
    with pytest.raises(RefusalError, match="FORGED_TOKEN"):
        pep.dispatcher.execute(token, call)
    assert world.deleted_records == []


# ---- MAJOR: decide() must be total for unserializable args ------------------------------
def test_r1_unserializable_args_deny_not_raise(tmp_path: Path) -> None:
    # ToolCall now validates serializability at construction (the adapter boundary)...
    with pytest.raises(ValueError, match="serializable"):
        ToolCall(
            "issue_refund", {"amount_cents": {1}}, "support_agent:j", "s", "a", "t", "ts"
        )


def test_r1_hostile_hash_property_still_denies(tmp_path: Path) -> None:
    # ...and even a hostile ToolCall whose .hash raises cannot crash decide().
    policy = compile_policy(POLICY)

    class HostileCall(ToolCall):
        @property
        def hash(self) -> str:
            raise RuntimeError("hostile hash")

    call = HostileCall(
        "issue_refund", {"amount_cents": 1}, "support_agent:j", "s", "a", "t", "ts"
    )
    d = decide(call, policy, {})
    assert d.verdict is Verdict.DENY


# ---- MAJOR: PEP fail-closed around facts/audit errors ------------------------------------
def test_r1_throwing_facts_provider_refuses_not_raises(tmp_path: Path) -> None:
    pep, world = _pep(tmp_path)

    def boom(call: ToolCall) -> dict[str, object]:
        raise RuntimeError("facts backend down")

    pep._facts_provider = boom  # type: ignore[attr-defined]
    result = pep.attempt(_call("issue_refund", order_id="ord-2001", amount_cents=1))
    assert isinstance(result, Refusal)
    assert result.verdict is Verdict.DENY
    assert world.refunds == []


def test_r1_audit_write_failure_blocks_execution(tmp_path: Path) -> None:
    pep, world = _pep(tmp_path)
    order = next(iter(world.orders))
    customer = world.orders[order]["customer_id"]

    class BrokenLoom:
        def append(self, record: dict[str, object]) -> str:
            raise OSError("disk full")

    pep._audit = BrokenLoom()  # type: ignore[attr-defined]
    result = pep.attempt(
        _call("issue_refund", order_id=order, amount_cents=500, customer_id=customer)
    )
    assert isinstance(result, Refusal)
    assert result.verdict is Verdict.DENY
    assert world.refunds == []  # no allow without an audit record


# ---- MAJOR: domain_in_allowlist must reject multi-@ addresses ----------------------------
def test_r1_double_at_email_denied() -> None:
    policy = compile_policy(POLICY)
    call = _call("send_email", to="victim@evil.test@example.test", body="order_status_v1")
    d = decide(call, policy, {})
    assert d.verdict is Verdict.DENY


def test_r1_clean_email_still_allowed() -> None:
    policy = compile_policy(POLICY)
    call = _call("send_email", to="customer1@shop.example.test", body="order_status_v1")
    d = decide(call, policy, {})
    # shop.example.test is not on the allowlist (example.test is) -> deny;
    # the allowlisted exact domain passes:
    assert d.verdict is Verdict.DENY
    call2 = _call("send_email", to="jordan@example.test", body="order_status_v1")
    assert decide(call2, policy, {}).verdict is Verdict.ALLOW


# ---- MAJOR: typed redaction — attacker strings on SAFE_KEYS must be masked ---------------
def test_r1_string_on_numeric_safe_key_is_masked(tmp_path: Path) -> None:
    call = _call("issue_refund", amount_cents="alice@example.test")
    policy = compile_policy(POLICY)
    decision = decide(call, policy, {})
    rec = make_record(
        call=call, decision=decision, vote=JudgeVote.ABSTAIN,
        final=decision.verdict, facts={}, policy_hash="a" * 64,
    )
    serialized = json.dumps(rec)
    assert "alice@example.test" not in serialized


def test_r1_hostile_principal_role_is_masked(tmp_path: Path) -> None:
    call = ToolCall(
        "issue_refund", {"amount_cents": 1},
        "alice@example.test <script>:x", "s", "a", "t", "ts",
    )
    policy = compile_policy(POLICY)
    decision = decide(call, policy, {})
    rec = make_record(
        call=call, decision=decision, vote=JudgeVote.ABSTAIN,
        final=decision.verdict, facts={}, policy_hash="a" * 64,
    )
    serialized = json.dumps(rec)
    assert "alice@example.test" not in serialized


def test_r1_slug_safe_keys_reject_freeform(tmp_path: Path) -> None:
    call = _call("read_customer_db", query_field="all rows; alice@example.test")
    policy = compile_policy(POLICY)
    decision = decide(call, policy, {})
    rec = make_record(
        call=call, decision=decision, vote=JudgeVote.ABSTAIN,
        final=decision.verdict, facts={}, policy_hash="a" * 64,
    )
    assert "alice@example.test" not in json.dumps(rec)


def test_r1_audit_loom_append_still_works_end_to_end(tmp_path: Path) -> None:
    pep, world = _pep(tmp_path)
    order = next(iter(world.orders))
    customer = world.orders[order]["customer_id"]
    result = pep.attempt(
        _call("issue_refund", order_id=order, amount_cents=500, customer_id=customer)
    )
    from tripwire.gate.pep import ToolResult

    assert isinstance(result, ToolResult)
    lines = (tmp_path / "a.jsonl").read_text().splitlines()
    assert len(lines) == 1
    loom = AuditLoom(tmp_path / "a.jsonl")
    assert loom is not None

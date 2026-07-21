from __future__ import annotations

from pathlib import Path

import pytest

import tripwire.adapter
from tripwire.adapter.mockworld import MockWorld
from tripwire.gate.audit import verify_chain
from tripwire.gate.pep import PEP, Refusal, RefusalError, ToolResult, build_default_pep
from tripwire.gate.types import ToolCall, Verdict

POLICY = Path(__file__).resolve().parents[2] / "tripwire" / "policies" / "default.yaml"


def _pep(tmp_path: Path, policy: Path = POLICY) -> tuple[PEP, MockWorld]:
    world = MockWorld(seed=42)
    pep = build_default_pep(policy_path=policy, world=world, audit_path=tmp_path / "audit.jsonl")
    return pep, world


def _call(tool: str, **args: object) -> ToolCall:
    return ToolCall(
        tool, args, "support_agent:jordan", "sess-1", "agent-1", "t1", "2026-06-09T00:00:00Z"
    )


def test_allowed_refund_executes(tmp_path: Path) -> None:
    pep, world = _pep(tmp_path)
    order = next(iter(world.orders))
    customer = world.orders[order]["customer_id"]
    result = pep.attempt(
        _call("issue_refund", order_id=order, amount_cents=500, customer_id=customer)
    )
    assert isinstance(result, ToolResult)
    assert world.refunds and world.refunds[0]["amount_cents"] == 500


def test_over_cap_refund_escalates_not_executes(tmp_path: Path) -> None:
    pep, world = _pep(tmp_path)
    order = next(iter(world.orders))
    customer = world.orders[order]["customer_id"]
    result = pep.attempt(
        _call("issue_refund", order_id=order, amount_cents=45000, customer_id=customer)
    )
    assert isinstance(result, Refusal)
    assert result.verdict is Verdict.ESCALATE and result.escalate is True
    assert world.refunds == []


def test_never_block_denies(tmp_path: Path) -> None:
    pep, world = _pep(tmp_path)
    order = next(iter(world.orders))
    customer = world.orders[order]["customer_id"]
    result = pep.attempt(
        _call("issue_refund", order_id=order, amount_cents=500000, customer_id=customer)
    )
    assert isinstance(result, Refusal)
    assert result.verdict is Verdict.DENY and result.reason_code == "NEVER_BLOCK"
    assert world.refunds == []


def test_delete_record_always_escalates(tmp_path: Path) -> None:
    pep, world = _pep(tmp_path)
    result = pep.attempt(_call("delete_record", record_id="ord-1001"))
    assert isinstance(result, Refusal) and result.verdict is Verdict.ESCALATE
    assert world.deleted_records == []


def test_fetch_url_allowlisted_host_only(tmp_path: Path) -> None:
    pep, world = _pep(tmp_path)
    ok = pep.attempt(_call("fetch_url", url="https://docs.example.test/help"))
    assert isinstance(ok, ToolResult)
    bad = pep.attempt(_call("fetch_url", url="https://evil.test/payload"))
    assert isinstance(bad, Refusal) and bad.verdict is Verdict.DENY


def test_broken_policy_means_global_deny(tmp_path: Path) -> None:
    broken = tmp_path / "broken.yaml"
    broken.write_text("tools: [")
    pep, world = _pep(tmp_path, policy=broken)
    order = next(iter(world.orders))
    result = pep.attempt(_call("issue_refund", order_id=order, amount_cents=1))
    assert isinstance(result, Refusal)
    assert result.verdict is Verdict.DENY and result.reason_code == "POLICY_LOAD_ERROR"


def test_every_attempt_appends_exactly_one_audit_record(tmp_path: Path) -> None:
    pep, world = _pep(tmp_path)
    order = next(iter(world.orders))
    customer = world.orders[order]["customer_id"]
    pep.attempt(_call("issue_refund", order_id=order, amount_cents=500, customer_id=customer))
    pep.attempt(_call("issue_refund", order_id=order, amount_cents=500000, customer_id=customer))
    pep.attempt(_call("delete_record", record_id="x"))
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    assert len(lines) == 3
    assert verify_chain(tmp_path / "audit.jsonl") is True


def test_tools_not_importable_from_public_api(tmp_path: Path) -> None:
    for name in ("issue_refund", "send_email", "delete_record", "fetch_url", "read_customer_db"):
        assert not hasattr(tripwire.adapter, name)


def test_pep_has_no_bypass_attribute(tmp_path: Path) -> None:
    pep, _ = _pep(tmp_path)
    suspicious = [a for a in dir(pep) if "bypass" in a.lower() or "ungated" in a.lower()]
    assert suspicious == []


def test_dispatcher_refuses_unminted_token(tmp_path: Path) -> None:
    pep, world = _pep(tmp_path)

    class Forged:
        tool = "issue_refund"
        payload_hash = "0" * 64

    with pytest.raises(RefusalError):
        pep.dispatcher.execute(Forged(), _call("issue_refund", amount_cents=1))  # type: ignore[arg-type]

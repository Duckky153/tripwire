"""INV-6 (capability chokepoint) + INV-8 (payload integrity / TOCTOU) — property tests.

HONESTY.md cites the measured case counts of these as part of the INV-1..9 evidence.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tripwire.adapter.mockworld import MockWorld
from tripwire.gate.pdp import decide
from tripwire.gate.pep import RefusalError, ToolResult, build_default_pep
from tripwire.gate.types import ToolCall

POLICY = Path(__file__).resolve().parents[2] / "tripwire" / "policies" / "default.yaml"


def _pep(tmp_path: Path):  # type: ignore[no-untyped-def]
    world = MockWorld(seed=42)
    return build_default_pep(
        policy_path=POLICY, world=world, audit_path=tmp_path / "audit.jsonl"
    ), world


def _good_call(world: MockWorld, amount: int = 500) -> ToolCall:
    order = next(iter(world.orders))
    customer = world.orders[order]["customer_id"]
    return ToolCall(
        "issue_refund",
        {"order_id": order, "amount_cents": amount, "customer_id": customer},
        "support_agent:jordan", "sess-1", "agent-1", "t1", "2026-06-09T00:00:00Z",
    )


# ------------------------------------------------------------------------------ INV-6
@settings(max_examples=200)
@given(
    fake_hash=st.text(alphabet="0123456789abcdef", min_size=64, max_size=64),
    tool=st.sampled_from(["issue_refund", "send_email", "delete_record", "nope"]),
)
def test_inv6_forged_tokens_never_execute(tmp_path_factory, fake_hash: str, tool: str) -> None:  # type: ignore[no-untyped-def]
    tmp = tmp_path_factory.mktemp("inv6")
    pep, world = _pep(tmp)

    class Forged:
        pass

    forged = Forged()
    forged.tool = tool  # type: ignore[attr-defined]
    forged.payload_hash = fake_hash  # type: ignore[attr-defined]
    with pytest.raises(RefusalError):
        pep.dispatcher.execute(forged, _good_call(world))  # type: ignore[arg-type]
    assert world.refunds == []


def test_inv6_token_is_single_use(tmp_path: Path) -> None:
    pep, world = _pep(tmp_path)
    call = _good_call(world)
    facts = pep.facts_for(call)
    decision = decide(call, pep.policy, facts)
    token = pep.dispatcher.mint(decision, call)
    first = pep.dispatcher.execute(token, call)
    assert isinstance(first, ToolResult)
    with pytest.raises(RefusalError):
        pep.dispatcher.execute(token, call)
    assert len(world.refunds) == 1


def test_inv6_mint_requires_allow_decision(tmp_path: Path) -> None:
    pep, world = _pep(tmp_path)
    call = _good_call(world, amount=500000)  # never-block territory -> DENY
    decision = decide(call, pep.policy, pep.facts_for(call))
    with pytest.raises(RefusalError):
        pep.dispatcher.mint(decision, call)


# ------------------------------------------------------------------------------ INV-8
@settings(max_examples=200)
@given(
    mutation=st.sampled_from(["bump_amount", "swap_tool_arg", "add_key", "drop_key"]),
    delta=st.integers(min_value=1, max_value=10**6),
)
def test_inv8_post_decision_mutation_always_refuses(  # type: ignore[no-untyped-def]
    tmp_path_factory, mutation: str, delta: int
) -> None:
    tmp = tmp_path_factory.mktemp("inv8")
    pep, world = _pep(tmp)
    call = _good_call(world)
    decision = decide(call, pep.policy, pep.facts_for(call))
    token = pep.dispatcher.mint(decision, call)

    args = dict(call.args)
    if mutation == "bump_amount":
        args["amount_cents"] = int(args["amount_cents"]) + delta  # type: ignore[arg-type]
    elif mutation == "swap_tool_arg":
        args["customer_id"] = f"cus-other-{delta}"
    elif mutation == "add_key":
        args[f"extra_{delta}"] = "x"
    else:
        args.pop("customer_id", None)
    mutated = ToolCall(
        call.tool, args, call.principal, call.session_id, call.agent_id, call.trace_id, call.ts
    )

    with pytest.raises(RefusalError, match="PAYLOAD_HASH_MISMATCH"):
        pep.dispatcher.execute(token, mutated)
    assert world.refunds == []


def test_inv8_executed_hash_equals_verified_hash(tmp_path: Path) -> None:
    pep, world = _pep(tmp_path)
    call = _good_call(world)
    result = pep.attempt(call)
    assert isinstance(result, ToolResult)
    assert result.payload_hash == call.hash

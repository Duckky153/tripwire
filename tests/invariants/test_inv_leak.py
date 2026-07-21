"""LEAK-1 property test: synthetic PII sentinels injected anywhere in args/facts must NEVER
appear in a written audit record. Sentinels are assembled at RUNTIME (never literals in
source) and use the reserved .test TLD — coordinated with the leak-gate scanner carve-outs;
the redaction property itself is substring-based and domain-agnostic, so nothing weakens.
"""

from __future__ import annotations

import json

from hypothesis import given, settings
from hypothesis import strategies as st

from tripwire.gate.audit import make_record
from tripwire.gate.pdp import decide
from tripwire.gate.policy_core import CompiledPolicy, Constraint, Rule, ToolPolicy
from tripwire.gate.types import JudgeVote, ToolCall

# Runtime-assembled sentinels — these exact strings must never reach a written record.
SENTINEL_EMAIL = "leak" + ".me@sentinel" + ".test"
SENTINEL_SSN = "-".join(["987", "65", "4321"])
SENTINEL_SECRET = "sk" + "_live_" + "Xk9mP2qRt7Lw3Zn8" * 2
SENTINELS = (SENTINEL_EMAIL, SENTINEL_SSN, SENTINEL_SECRET)

ARG_KEYS = ["note", "body", "to", "url", "customer_id", "reason", "memo"]
FACT_KEYS = ["order_customer_id", "session_customer_id", "shipping_address", "phone"]


def _policy(tool: str) -> CompiledPolicy:
    tp = ToolPolicy(
        name=tool, high_stakes=True, open_world_args=(),
        never=(), escalate=(),
        allow=(
            Rule(
                rule_id="r",
                principal_roles=(),
                constraints=(Constraint(field="args.amount_cents", op="lte", value=20000),),
            ),
        ),
    )
    return CompiledPolicy(version=1, tools={tool: tp}, content_hash="b" * 64)


@settings(max_examples=200)
@given(
    arg_key=st.sampled_from(ARG_KEYS),
    fact_key=st.sampled_from(FACT_KEYS),
    sentinel=st.sampled_from(SENTINELS),
    amount=st.integers(min_value=0, max_value=100000),
    nest=st.booleans(),
)
def test_leak1_sentinels_never_appear_in_records(
    arg_key: str, fact_key: str, sentinel: str, amount: int, nest: bool
) -> None:
    args: dict[str, object] = {"amount_cents": amount, arg_key: sentinel}
    if nest:
        args["meta"] = {"inner": [sentinel, {"deep": sentinel}]}
    facts: dict[str, object] = {fact_key: sentinel, "order_exists": True}
    call = ToolCall("issue_refund", args, "support_agent:jordan", "s", "a", "t", "ts")
    decision = decide(call, _policy("issue_refund"), facts)
    rec = make_record(
        call=call, decision=decision, vote=JudgeVote.ABSTAIN,
        final=decision.verdict, facts=facts, policy_hash="b" * 64,
    )
    serialized = json.dumps(rec)
    for s in SENTINELS:
        assert s not in serialized
    # masked values keep their shape: sha256:<12hex>(len=N)
    assert "sha256:" in serialized

from __future__ import annotations

import json
from pathlib import Path

from tripwire.gate.audit import AuditLoom, make_record, verify_chain
from tripwire.gate.pdp import decide
from tripwire.gate.policy_core import CompiledPolicy, Constraint, Rule, ToolPolicy
from tripwire.gate.types import JudgeVote, ToolCall


def _policy() -> CompiledPolicy:
    tp = ToolPolicy(
        name="issue_refund",
        high_stakes=True,
        open_world_args=(),
        never=(),
        escalate=(),
        allow=(
            Rule(
                rule_id="ok",
                principal_roles=("support_agent",),
                constraints=(Constraint(field="args.amount_cents", op="lte", value=20000),),
            ),
        ),
    )
    return CompiledPolicy(version=1, tools={"issue_refund": tp}, content_hash="a" * 64)


def _call(**args: object) -> ToolCall:
    return ToolCall(
        "issue_refund", args or {"amount_cents": 500}, "support_agent:jordan",
        "s1", "a1", "t1", "2026-06-09T00:00:00Z",
    )


def _record(loom: AuditLoom, **args: object) -> str:
    call = _call(**args)
    decision = decide(call, _policy(), {"order_exists": True})
    rec = make_record(
        call=call, decision=decision, vote=JudgeVote.ABSTAIN,
        final=decision.verdict, facts={"order_exists": True}, policy_hash="a" * 64,
    )
    return loom.append(rec)


def test_append_returns_hash_and_chain_verifies(tmp_path: Path) -> None:
    loom = AuditLoom(tmp_path / "audit.jsonl")
    h1 = _record(loom, amount_cents=500)
    h2 = _record(loom, amount_cents=900)
    assert h1 != h2 and len(h1) == 64
    assert verify_chain(tmp_path / "audit.jsonl") is True


def test_first_record_uses_genesis(tmp_path: Path) -> None:
    loom = AuditLoom(tmp_path / "audit.jsonl")
    _record(loom)
    line = json.loads((tmp_path / "audit.jsonl").read_text().splitlines()[0])
    assert line["prev_hash"] == "GENESIS"


def test_tampering_any_byte_breaks_chain(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    loom = AuditLoom(p)
    for cents in (500, 900, 1300):
        _record(loom, amount_cents=cents)
    lines = p.read_text().splitlines()
    tampered = lines[1].replace('"final_verdict":"allow"', '"final_verdict":"deny"')
    assert tampered != lines[1]
    p.write_text("\n".join([lines[0], tampered, lines[2]]) + "\n")
    assert verify_chain(p) is False


def test_record_exposes_structural_fields_in_clear(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    _record(AuditLoom(p), amount_cents=500)
    rec = json.loads(p.read_text().splitlines()[0])
    assert rec["tool"] == "issue_refund"
    assert rec["verdict"] == "allow" and rec["final_verdict"] == "allow"
    assert rec["vote"] == "abstain"
    assert rec["reason_code"] == "RULE_MATCH" and rec["matched_rule_id"] == "ok"
    assert rec["policy_hash"] == "a" * 64
    assert rec["constraints_evaluated"] == [["args.amount_cents", True]]
    assert rec["session_id"] == "s1" and rec["agent_id"] == "a1" and rec["trace_id"] == "t1"
    # amount_cents is on the SAFE_KEYS allowlist -> in clear
    assert rec["args"]["amount_cents"] == 500


def test_non_allowlisted_values_are_masked(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    # 'note' is not on the allowlist -> masked
    _record(AuditLoom(p), amount_cents=500, note="customer shouted a lot")
    rec = json.loads(p.read_text().splitlines()[0])
    masked = rec["args"]["note"]
    assert "customer" not in masked
    assert masked.startswith("sha256:") and "(len=" in masked

"""Cross-equality: the vendored validator policy core must agree with tripwire's own PDP.

The Guardrails Hub validator vendors a standalone copy of the deny-by-default semantics (so it
is installable without tripwire). This test pins behavioral equality so the two can never
silently drift — the merged upstream artifact and tripwire's gate stay one honest implementation.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from tripwire.gate.pdp import decide
from tripwire.gate.policy_core import compile_policy
from tripwire.gate.types import ToolCall

_VENDORED = (
    Path(__file__).resolve().parents[1]
    / "validators" / "tool_call_policy" / "tool_call_policy" / "policy.py"
)
_spec = importlib.util.spec_from_file_location("vendored_policy", _VENDORED)
assert _spec is not None and _spec.loader is not None
vendored = importlib.util.module_from_spec(_spec)
sys.modules["vendored_policy"] = vendored
_spec.loader.exec_module(vendored)

_POLICY_PATH = Path(__file__).resolve().parents[1] / "tripwire" / "policies" / "default.yaml"
_COMPILED = compile_policy(_POLICY_PATH)
import yaml  # noqa: E402

_RAW = yaml.safe_load(_POLICY_PATH.read_text())


def _verdict_str(v: object) -> str:
    return getattr(v, "value", str(v)).upper()


@settings(max_examples=400)
@given(
    tool=st.sampled_from(
        ["issue_refund", "send_email", "delete_record", "fetch_url", "read_customer_db", "x"]
    ),
    args=st.dictionaries(
        st.sampled_from(
            ["amount_cents", "to", "body", "url", "query_field", "customer_id", "order_id"]
        ),
        st.one_of(st.integers(-(10**7), 10**7), st.text(max_size=30), st.booleans()),
        max_size=4,
    ),
    role=st.sampled_from(["support_agent", "intruder", "admin"]),
    facts=st.dictionaries(
        st.sampled_from(["order_exists", "order_customer_id", "session_customer_id"]),
        st.one_of(st.booleans(), st.text(max_size=12)),
        max_size=3,
    ),
)
def test_vendored_core_matches_tripwire_pdp(tool, args, role, facts) -> None:  # type: ignore[no-untyped-def]
    call = ToolCall(tool, args, f"{role}:x", "s", "a", "t", "ts")
    tw = decide(call, _COMPILED, facts)
    vn = vendored.evaluate(tool, dict(args), _RAW, principal_role=role, facts=dict(facts))
    assert _verdict_str(tw.verdict) == vn.verdict, (tool, args, role, facts, tw.verdict, vn.verdict)

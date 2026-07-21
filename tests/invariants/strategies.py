"""Hypothesis strategies for the invariant suite.

Policies are generated two ways on purpose:
- `compiled_policies()` builds frozen dataclasses DIRECTLY (covers hand-built policies that
  never went through the compiler — the INV-9 defense-in-depth surface), and
- YAML-dict strategies in the tests feed `compile_policy` (the compiler surface, INV-7/9).
"""

from __future__ import annotations

from hypothesis import strategies as st

from tripwire.gate.policy_core import (
    KNOWN_OPS,
    CompiledPolicy,
    Constraint,
    Rule,
    ToolPolicy,
)
from tripwire.gate.types import ToolCall

TOOL_NAMES = ["issue_refund", "send_email", "delete_record", "fetch_url", "read_customer_db"]
ARG_KEYS = ["amount_cents", "customer_id", "url", "to", "body", "query_field", "note"]
FACT_KEYS = ["order_exists", "order_customer_id", "session_customer_id", "account_age_days"]
ROLES = ["support_agent", "billing_agent", "intruder", ""]

_scalars = st.one_of(
    st.integers(min_value=-(10**9), max_value=10**9),
    st.booleans(),
    st.text(max_size=40),
    st.none(),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
)

_weird_values = st.one_of(
    _scalars,
    st.lists(_scalars, max_size=3),
    st.text(alphabet="\u202e\ufeff" + "ABCabc123{}$;|&<>", max_size=20),
)


def fields() -> st.SearchStrategy[str]:
    return st.one_of(
        st.sampled_from([f"args.{k}" for k in ARG_KEYS]),
        st.sampled_from([f"facts.{k}" for k in FACT_KEYS]),
    )


def constraints() -> st.SearchStrategy[Constraint]:
    def build(field: str, op: str, value: object) -> Constraint:
        if op in ("in", "not_in", "scheme_in", "host_in_allowlist", "domain_in_allowlist",
                  "template_id_in"):
            value = tuple([value]) if not isinstance(value, tuple) else value
        return Constraint(field=field, op=op, value=value)

    return st.builds(build, fields(), st.sampled_from(sorted(KNOWN_OPS)), _weird_values)


def rules(rule_id_prefix: str = "r") -> st.SearchStrategy[Rule]:
    return st.builds(
        Rule,
        rule_id=st.integers(min_value=0, max_value=999).map(lambda i: f"{rule_id_prefix}-{i}"),
        principal_roles=st.lists(st.sampled_from(ROLES), max_size=2).map(tuple),
        constraints=st.lists(constraints(), max_size=4).map(tuple),
    )


def tool_policies(name: str) -> st.SearchStrategy[ToolPolicy]:
    return st.builds(
        ToolPolicy,
        name=st.just(name),
        high_stakes=st.just(True),
        open_world_args=st.sampled_from([(), ("url",), ("to", "body")]),
        never=st.lists(rules("never"), max_size=2).map(tuple),
        escalate=st.lists(rules("esc"), max_size=2).map(tuple),
        allow=st.lists(rules("allow"), max_size=3).map(tuple),
    )


def compiled_policies() -> st.SearchStrategy[CompiledPolicy]:
    def build(tools: list[ToolPolicy]) -> CompiledPolicy:
        return CompiledPolicy(
            version=1, tools={tp.name: tp for tp in tools}, content_hash="0" * 64
        )

    subset = st.lists(
        st.sampled_from(TOOL_NAMES), min_size=1, max_size=len(TOOL_NAMES), unique=True
    )
    return subset.flatmap(
        lambda names: st.tuples(*[tool_policies(n) for n in names]).map(
            lambda tps: build(list(tps))
        )
    )


def tool_calls() -> st.SearchStrategy[ToolCall]:
    return st.builds(
        ToolCall,
        tool=st.one_of(st.sampled_from(TOOL_NAMES), st.text(max_size=20)),
        args=st.dictionaries(st.sampled_from(ARG_KEYS), _weird_values, max_size=5),
        principal=st.one_of(
            st.sampled_from(["support_agent:jordan", "intruder:x", "support_agent:", ":", ""]),
            st.text(max_size=20),
        ),
        session_id=st.just("s"),
        agent_id=st.just("a"),
        trace_id=st.just("t"),
        ts=st.just("2026-06-09T00:00:00Z"),
    )


def facts() -> st.SearchStrategy[dict[str, object]]:
    return st.dictionaries(st.sampled_from(FACT_KEYS), _weird_values, max_size=4)

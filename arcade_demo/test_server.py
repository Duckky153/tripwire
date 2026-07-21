"""Smoke test for the arcade_demo two-axis fail-closed refund tool.

This test does NOT require the optional `arcade-mcp` package — it calls the pure
`evaluate_refund(...)` decision function directly, which is exactly the path the
`@app.tool` wrapper delegates to. The tripwire PDP call inside `evaluate_refund` is REAL
(tripwire is installed), so these assertions exercise the genuine policy engine.

Axes:
  axis 1 — Arcade OAuth token present (proves WHO)
  axis 2 — tripwire PDP returns ALLOW (proves THIS action is permitted)
Either failing => REFUSE + escalate, and NO side effect.
"""

from __future__ import annotations

from arcade_demo.server import _principal_from, evaluate_refund

# Trusted world-facts for a verified, existing order owned by a known customer.
# These mirror what the gate would fetch server-side; the call's customer_id is bound to
# `order_customer_id` so the policy's eq_field constraint passes.
_VERIFIED_ORDER_FACTS = {"order_exists": True, "order_customer_id": "cust_demo_0001"}
_GOOD_PRINCIPAL = "support_agent:agent_demo"


class _FakeAuthorization:
    """Minimal stand-in for context.authorization."""

    def __init__(self, user_info: object) -> None:
        self.user_info = user_info


class _FakeContext:
    """Tiny fake of the arcade Context — only the two surfaces the tool touches."""

    def __init__(self, token: str, user_info: object) -> None:
        self._token = token
        self.authorization = _FakeAuthorization(user_info)
        self.user_id = "fallback_id"

    def get_auth_token_or_empty(self) -> str:
        return self._token


# --- axis 1: no token => REFUSE / no_authorized_scope, no side effect ------------------


def test_no_token_refuses_with_no_authorized_scope() -> None:
    result = evaluate_refund(
        token="",
        principal=_GOOD_PRINCIPAL,
        order_id="ord_demo_0001",
        amount_cents=5000,
        world_facts=_VERIFIED_ORDER_FACTS,
    )
    assert result["decision"] == "REFUSE"
    assert result["reason"] == "no_authorized_scope"
    assert result["escalate"] is True
    # No side effect: a REFUSE never reports a refunded order/amount/policy.
    assert "matched_policy" not in result


# --- axis 2: token present but PDP denies (over-cap) => REFUSE / escalate ---------------


def test_token_present_but_pdp_denies_over_cap() -> None:
    # 500000 cents ($5000) trips the never-huge-refund block (> 50000) => DENY + escalate.
    result = evaluate_refund(
        token="sandbox-oauth-token",
        principal=_GOOD_PRINCIPAL,
        order_id="ord_demo_0001",
        amount_cents=500000,
        world_facts=_VERIFIED_ORDER_FACTS,
    )
    assert result["decision"] == "REFUSE"
    assert result["escalate"] is True
    # It refused on policy (axis 2), NOT on auth (axis 1).
    assert result["reason"] != "no_authorized_scope"
    assert "matched_policy" not in result


# --- both axes pass: token + small verified refund => ALLOW ----------------------------


def test_both_axes_pass_allows() -> None:
    result = evaluate_refund(
        token="sandbox-oauth-token",
        principal=_GOOD_PRINCIPAL,
        order_id="ord_demo_0001",
        amount_cents=5000,  # $50.00 — within the <= 20000 cap
        world_facts=_VERIFIED_ORDER_FACTS,
    )
    assert result["decision"] == "ALLOW"
    assert result["order_id"] == "ord_demo_0001"
    assert result["amount_cents"] == 5000
    assert result["matched_policy"] == "refund-small-verified"


# --- axis 2: token present but the order is unknown => REFUSE (facts gate) --------------


def test_token_present_but_unknown_order_refuses() -> None:
    result = evaluate_refund(
        token="sandbox-oauth-token",
        principal=_GOOD_PRINCIPAL,
        order_id="ord_does_not_exist",
        amount_cents=5000,
        world_facts={"order_exists": False, "order_customer_id": None},
    )
    assert result["decision"] == "REFUSE"
    assert result["escalate"] is True
    assert "matched_policy" not in result


# --- principal derivation: identity comes from verified user info, role is fixed --------


def test_principal_from_dict_user_info() -> None:
    assert _principal_from({"id": "agent_demo"}) == "support_agent:agent_demo"
    assert _principal_from({"sub": "agent_demo"}) == "support_agent:agent_demo"
    assert _principal_from({}) == "support_agent:"
    assert _principal_from(None) == "support_agent:"


def test_fake_context_surfaces_match_what_the_wrapper_reads() -> None:
    # Documents the exact Context surface the @app.tool wrapper depends on, so this fake
    # stays faithful: get_auth_token_or_empty() + authorization.user_info.
    ctx = _FakeContext(token="t", user_info={"id": "agent_demo"})
    assert ctx.get_auth_token_or_empty() == "t"
    assert _principal_from(ctx.authorization.user_info) == "support_agent:agent_demo"

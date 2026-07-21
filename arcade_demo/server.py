"""arcade-mcp two-axis fail-closed refund tool.

Mounts the SAME tripwire Policy Decision Point (PDP) behind an Arcade Engine
authenticated-tool gate, so a high-stakes side effect (`issue_refund`) requires BOTH:

  axis 1 — an Arcade Engine OAuth token for the declared scope (proves WHO is acting), AND
  axis 2 — the in-body tripwire PDP returning ALLOW for THIS exact call (proves the action
           is permitted by policy).

Either axis failing => REFUSE + escalate. "Auth proves WHO; tripwire proves THIS action."

The OAuth provider is a GENERIC sandbox OAuth2 provider (`OAuth2(id="ops_backend", ...)`),
NOT a real Gmail/Stripe/GitHub integration. The consent step is HUMAN-ONLY: a person opens
the authorization URL Arcade returns and logs in to the sandbox provider themselves — the
agent/builder never logs in or solves a CAPTCHA. See README.md.

The decision logic lives in the pure `evaluate_refund(...)` function so it is testable
without the optional `arcade-mcp` package installed (it ships in the `[demo]` extra). The
`@app.tool` wrapper is import-guarded and only adapts the Arcade `Context` to that function.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

from tripwire.gate.pdp import decide
from tripwire.gate.policy_core import compile_policy
from tripwire.gate.types import ToolCall, Verdict

# The reference deny-by-default policy. `issue_refund` is allowed only for a
# `support_agent` principal, amount in (0, 20000] cents, against a verified order whose
# customer matches the call — every other shape refuses or escalates.
_POLICY_PATH = Path(__file__).resolve().parent.parent / "tripwire" / "policies" / "default.yaml"

# Least privilege: the ONE scope this tool needs, nothing more.
_REQUIRED_SCOPE = "refund:write"


def _principal_from(user_info: Any) -> str:
    """Map the Arcade-authenticated identity to the PDP principal `support_agent:<id>`.

    The role prefix is what the policy's `principal_roles: [support_agent]` checks. The
    identity half is taken from the verified token's user info — never from agent text.
    A missing/blank identity collapses to `support_agent:` (still a valid, scoped role).
    """
    ident = ""
    if isinstance(user_info, dict):
        ident = str(user_info.get("id") or user_info.get("sub") or user_info.get("email") or "")
    elif user_info is not None:
        ident = str(getattr(user_info, "id", "") or getattr(user_info, "sub", "") or "")
    ident = ident.strip().replace("\n", "").replace(" ", "_")
    return f"support_agent:{ident}" if ident else "support_agent:"


def evaluate_refund(
    token: str,
    principal: str,
    order_id: str,
    amount_cents: int,
    world_facts: dict[str, Any],
) -> dict[str, Any]:
    """Pure two-axis fail-closed decision. No side effect; returns a decision dict.

    `world_facts` are the GATE's trusted facts about the order (existence, owning
    customer) — in production these are fetched server-side, never supplied by the agent.
    """
    # --- axis 1: authorization (proves WHO) -------------------------------------------
    if not token:
        return {"decision": "REFUSE", "reason": "no_authorized_scope", "escalate": True}

    # --- axis 2: policy decision point (proves THIS action is allowed) -----------------
    policy = compile_policy(_POLICY_PATH)
    call = ToolCall(
        tool="issue_refund",
        args={
            "order_id": order_id,
            "amount_cents": amount_cents,
            "customer_id": world_facts.get("order_customer_id"),
        },
        principal=principal,
        session_id="arcade-session",
        agent_id="arcade-mcp",
        trace_id=f"refund-{order_id}",
        ts="1970-01-01T00:00:00Z",
    )
    decision = decide(call, policy, world_facts)
    if decision.verdict is not Verdict.ALLOW:
        return {
            "decision": "REFUSE",
            "reason": decision.reason_code,
            "escalate": decision.escalate,
        }

    # --- both axes passed: AUTHORIZED -------------------------------------------------
    return {
        "decision": "ALLOW",
        "order_id": order_id,
        "amount_cents": amount_cents,
        "matched_policy": decision.matched_rule_id,
    }


# --- arcade-mcp wrapper (import-guarded: `arcade-mcp` is the optional [demo] extra) ----
try:
    from arcade_mcp_server import Context, MCPApp
    from arcade_mcp_server.auth import OAuth2

    app = MCPApp(name="tripwire_refund_gate", version="1.0.0")

    @app.tool(
        requires_auth=OAuth2(
            id="ops_backend",  # generic SANDBOX provider id — NOT a real Gmail/Stripe/GitHub
            scopes=[_REQUIRED_SCOPE],  # least privilege: refund:write only
        )
    )
    def issue_refund(
        context: Context,
        order_id: Annotated[str, "Opaque order identifier to refund against."],
        amount_cents: Annotated[int, "Refund amount in integer cents."],
    ) -> dict[str, Any]:
        """Issue a refund only if BOTH the Arcade OAuth scope AND the tripwire PDP allow it.

        Returns a decision dict: {"decision": "ALLOW"|"REFUSE", ...}. A REFUSE carries a
        reason code and `escalate: True` so the caller routes the attempt to a human.
        """
        token = context.get_auth_token_or_empty()
        # Derive the policy principal from the verified token's user info (axis-1 identity).
        # `authorization.user_info` is the documented identity carrier; fall back to user_id.
        user_info: Any = None
        authorization = getattr(context, "authorization", None)
        if authorization is not None:
            user_info = getattr(authorization, "user_info", None)
        if user_info is None:
            user_info = {"id": getattr(context, "user_id", "")}
        principal = _principal_from(user_info)

        # The gate fetches its own trusted world-facts about the order — never agent text.
        world_facts = _trusted_world_facts(order_id)
        return evaluate_refund(token, principal, order_id, amount_cents, world_facts)

    _ARCADE_AVAILABLE = True
except ImportError:  # pragma: no cover — exercised only when the [demo] extra is absent
    _ARCADE_AVAILABLE = False


def _trusted_world_facts(order_id: str) -> dict[str, Any]:
    """Stand-in for a server-side order lookup (the GATE's authoritative facts).

    A real deployment queries the ops backend here. This sandbox returns a single verified
    order so the demo can show an end-to-end ALLOW; everything else is an unknown order
    (`order_exists=False`) and the PDP refuses. No personal data — opaque ids only.
    """
    known = {
        "ord_demo_0001": {"order_exists": True, "order_customer_id": "cust_demo_0001"},
    }
    return known.get(order_id, {"order_exists": False, "order_customer_id": None})


if __name__ == "__main__":
    if not _ARCADE_AVAILABLE:
        raise SystemExit(
            "arcade-mcp is not installed. Install the demo extra:\n"
            "    .venv/bin/pip install -e \".[demo]\""
        )
    app.run()

"""Trusted world-facts provider.

Facts are fetched BY THE GATE from the world's authoritative state — never from the agent's
narrative. The session→customer binding comes from server-side session state, so an agent
claiming "the customer is verified" changes nothing.
"""

from __future__ import annotations

from typing import Any

from tripwire.adapter.mockworld import MockWorld
from tripwire.gate.types import ToolCall


def facts_for(call: ToolCall, world: MockWorld) -> dict[str, Any]:
    order_id = str(call.args.get("order_id", ""))
    order = world.orders.get(order_id)
    return {
        "order_exists": order is not None,
        "order_customer_id": order["customer_id"] if order else None,
        "session_customer_id": world.session_customers.get(call.session_id),
    }

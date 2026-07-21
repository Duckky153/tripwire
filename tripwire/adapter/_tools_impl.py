"""PRIVATE mock tool implementations (INV-6).

This module is deliberately NOT exported from tripwire.adapter — the only way to execute
one of these callables is through the gate dispatcher with a PDP-minted token. The
functions are pure against MockWorld; "side effects" are appended to the world's ledgers.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from tripwire.adapter.mockworld import MockWorld


def _issue_refund(world: MockWorld, **args: Any) -> dict[str, Any]:
    receipt = {
        "order_id": args.get("order_id"),
        "amount_cents": args.get("amount_cents"),
        "customer_id": args.get("customer_id"),
    }
    world.refunds.append(receipt)
    return {"refund": "issued", **receipt}


def _send_email(world: MockWorld, **args: Any) -> dict[str, Any]:
    record = {"to": args.get("to"), "body": args.get("body")}
    world.sent_emails.append(record)
    return {"email": "sent", "to": args.get("to")}


def _delete_record(world: MockWorld, **args: Any) -> dict[str, Any]:
    record_id = str(args.get("record_id"))
    world.deleted_records.append(record_id)
    world.orders.pop(record_id, None)
    return {"deleted": record_id}


def _fetch_url(world: MockWorld, **args: Any) -> dict[str, Any]:
    url = str(args.get("url"))
    world.fetched_urls.append(url)
    return {"url": url, "content": world.web_pages.get(url, "")}


def _read_customer_db(world: MockWorld, **args: Any) -> dict[str, Any]:
    query = {"query_field": args.get("query_field"), "customer_id": args.get("customer_id")}
    world.db_reads.append(query)
    customer = world.customers.get(str(args.get("customer_id")))
    if customer is None:
        return {"rows": []}
    order = next(
        (o for o in world.orders.values() if o["customer_id"] == customer["customer_id"]), None
    )
    field = str(args.get("query_field"))
    value = order.get("status") if (order and field == "order_status") else "3-5 days"
    return {"rows": [{field: value}]}


def _build_registry(world: MockWorld) -> Mapping[str, Callable[..., dict[str, Any]]]:
    def bind(fn: Callable[..., dict[str, Any]]) -> Callable[..., dict[str, Any]]:
        def bound(**args: Any) -> dict[str, Any]:
            return fn(world, **args)

        return bound

    return {
        "issue_refund": bind(_issue_refund),
        "send_email": bind(_send_email),
        "delete_record": bind(_delete_record),
        "fetch_url": bind(_fetch_url),
        "read_customer_db": bind(_read_customer_db),
    }

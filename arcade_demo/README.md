# arcade_demo — two-axis fail-closed refund tool

A small, self-contained example that mounts tripwire's **Policy Decision Point (PDP)** behind
an [arcade-mcp](https://github.com/arcadeai/arcade-mcp) authenticated tool. A high-stakes side
effect (`issue_refund`) is gated on **two independent axes**, and **either failing => REFUSE +
escalate**:

| Axis | Question it answers | Mechanism |
|---|---|---|
| **1. Authorization** | *Who* is acting, and are they scoped for this? | Arcade Engine OAuth token for the `refund:write` scope. No token → `no_authorized_scope`. |
| **2. Policy (tripwire PDP)** | Is *this exact action* permitted right now? | `tripwire.gate.pdp.decide(...)` against `tripwire/policies/default.yaml`. Anything but ALLOW → refuse. |

> **Auth proves WHO; tripwire proves THIS action is allowed.** An OAuth token is necessary but
> not sufficient: a valid token holder still cannot push a $5,000 refund, refund an unknown
> order, or refund an order they don't own — the PDP refuses those by construction
> (deny-by-default, no `else: allow`).

This matters because OAuth scopes are coarse: `refund:write` says *"this principal may issue
refunds"*, not *"this **specific** refund is safe."* The PDP closes that gap per-call with
trusted, server-fetched world-facts (does the order exist? who owns it? is the amount under
cap?) — never trusting agent-supplied narrative.

## The two axes in `issue_refund`

The tool body (in `server.py`) runs them in order:

1. `token = context.get_auth_token_or_empty()` — if falsy →
   `{"decision": "REFUSE", "reason": "no_authorized_scope", "escalate": True}` (axis 1).
2. Build a tripwire `ToolCall` and call the PDP with the principal derived from the verified
   token's user info — if the verdict is not `ALLOW` →
   `{"decision": "REFUSE", "reason": <reason_code>, "escalate": True}` (axis 2).
3. Only if **both** pass →
   `{"decision": "ALLOW", "order_id": ..., "amount_cents": ..., "matched_policy": ...}`.

The decision logic is factored into a pure `evaluate_refund(...)` function; the `@app.tool`
wrapper only adapts the Arcade `Context` to it. That keeps the core testable without the
optional `arcade-mcp` package installed.

### What the reference policy allows

`tripwire/policies/default.yaml` allows `issue_refund` **only** when all hold:

- principal role is `support_agent`,
- `0 < amount_cents <= 20000` (≤ $200.00),
- the order **exists** (trusted fact), and
- the order's customer matches the call's customer.

`> 20000` escalates to a human; `> 50000` can **never** auto-approve; an unknown order or a
non-`support_agent` principal refuses.

## The OAuth provider is a GENERIC sandbox — not a real service

The tool declares:

```python
@app.tool(requires_auth=OAuth2(id="ops_backend", scopes=["refund:write"]))
```

`OAuth2(id="ops_backend", ...)` is Arcade's **generic** custom-provider class pointed at a
sandbox authorization server. This demo **never** wires a real Gmail/Stripe/GitHub provider,
and it declares **only** the one scope it needs (`refund:write`) — least privilege.

## The OAuth consent step is HUMAN-ONLY

When a tool requires auth and no token exists yet, Arcade returns an **authorization URL**.
Completing consent is a **human action**, never the agent's:

1. The agent/runtime surfaces the authorization URL Arcade returns.
2. **A person** opens that URL in their own browser.
3. **That person** logs in to the **sandbox** OAuth provider and approves the `refund:write`
   scope themselves.
4. Arcade exchanges the grant for a token and injects it into the tool's `Context` on the next
   call; `context.get_auth_token_or_empty()` then returns it.

**The agent/builder never logs in, never enters credentials, and never solves a CAPTCHA.** If a
human hasn't completed consent, axis 1 fails closed and the tool refuses — exactly as intended.

## Run it

The `arcade-mcp` package ships in tripwire's optional `[demo]` extra (it is **not** a default
dependency). Install it only to run the live server:

```bash
.venv/bin/pip install -e ".[demo]"     # pulls in arcade-mcp
.venv/bin/python arcade_demo/server.py  # starts the MCP server (app.run())
```

The smoke test does **not** need `arcade-mcp` — it calls the pure decision function directly,
and the tripwire PDP call inside it is real:

```bash
.venv/bin/pytest arcade_demo -q          # 6 passed
.venv/bin/ruff check arcade_demo          # clean
.venv/bin/python scripts/leakgate.py arcade_demo   # leak-safe
```

`server.py` exits with an install hint if you run it without the `[demo]` extra present.

## Honest framing

This is a **hardened example**, not a published or adopted toolkit. It demonstrates one design
pattern — composing an in-body policy decision point with an authenticated-tool gate so that a
side effect needs both — using fake order ids and a sandbox provider. The strength of the
guarantee is exactly the strength of the policy in `default.yaml`: a permissive **custom**
policy could still authorize a harmful action (see [`docs/HONESTY.md`](../docs/HONESTY.md)). The
value here is the **two-axis composition** and the fact that the policy half is the same
deny-by-default PDP that tripwire's property tests cover — not a claim that this demo is
production-ready or externally vetted.

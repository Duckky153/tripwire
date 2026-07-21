# tool_call_policy

A [Guardrails](https://github.com/guardrails-ai/guardrails) validator that authorizes an
agent's **structured tool/function call** against an explicit, **deny-by-default** policy.

Most Hub validators check free text or a scalar shape. This one checks a `(tool, args)` pair
against a policy of allow rules, never-blocks, and escalate-blocks. It is **fail-closed**:
a `PassResult` is returned ONLY when the call matches an explicit allow rule with every
constraint passing and no block firing. Unknown tool, missing scope, out-of-bound argument,
unconstrained open-world argument, or unparseable input all return a `FailResult`. It never
emits a `fix_value` — a dangerous call is never silently "repaired" into an allowed one.

## Install

```bash
guardrails hub install hub://guardrails/tool_call_policy
```

## Usage

```python
from guardrails import Guard
from guardrails.hub import ToolCallPolicy
from guardrails.errors import ValidationError

policy = {
    "tools": {
        "issue_refund": {
            "never":    [{"rule_id": "never-huge", "constraints": [
                          {"field": "args.amount_cents", "op": "gt", "value": 50000}]}],
            "escalate": [{"rule_id": "esc-over-cap", "constraints": [
                          {"field": "args.amount_cents", "op": "gt", "value": 20000}]}],
            "allow":    [{"rule_id": "refund-ok", "principal_roles": ["support_agent"],
                          "constraints": [
                            {"field": "args.amount_cents", "op": "lte", "value": 20000},
                            {"field": "facts.order_exists", "op": "eq", "value": True}]}],
        },
    }
}

guard = Guard().use(ToolCallPolicy, on_fail="exception")

# A structured tool call (JSON string or object) on the validated field:
guard.validate(
    '{"tool": "issue_refund", "args": {"amount_cents": 5000}}',
    metadata={"principal_role": "support_agent", "facts": {"order_exists": True}},
)  # passes

try:
    guard.validate(
        '{"tool": "issue_refund", "args": {"amount_cents": 600000}}',
        metadata={"principal_role": "support_agent", "facts": {"order_exists": True}},
    )
except ValidationError:
    pass  # refused: NEVER_BLOCK
```

## Parameters

| arg | type | description |
|---|---|---|
| `policy` | `dict` | The allow policy (may also be passed per-call via `metadata["policy"]`). |

`metadata` accepts: `policy` (overrides the constructor), `principal_role` (the caller's role,
matched against `principal_roles`), and `facts` (trusted world facts — never sourced from the
agent's own text).

## Policy schema

`policy.tools[<name>]` may declare:

- `open_world_args: [str]` — argument names whose value is unbounded (URLs, free-text bodies).
  An allow rule that does not structurally constrain every open-world arg (with `scheme_in`,
  `host_in_allowlist`, `domain_in_allowlist`, `template_id_in`, or `in`) can never produce ALLOW.
- `never: [rule]` — if any matches, the verdict is DENY (highest precedence).
- `escalate: [rule]` — if any matches (and no never), the verdict is ESCALATE.
- `allow: [rule]` — ALLOW requires a full match of one rule.

A `rule` is `{rule_id, principal_roles?: [str], constraints: [constraint]}`. A `constraint` is
`{field, op, value}` where `field` is `args.<k>` or `facts.<k>` and `op` is one of:
`eq, neq, lt, lte, gt, gte, in, not_in, eq_field, scheme_in, host_in_allowlist,
domain_in_allowlist, template_id_in`.

## on_fail

The recommended `on_fail` is `exception` or `refrain`. This validator deliberately provides no
`fix_value`.

## License

Apache-2.0.

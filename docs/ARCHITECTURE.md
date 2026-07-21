# Architecture

Two halves around one contract — the normalized `ToolCall` and `schema/run-report-v1.json`.

```
   attack corpus (deterministic, seeded; DeepTeam optional)
        │
        ▼
   TargetAdapter ──► mock support/ops agent (intentionally compliant, no LLM)
        │                     │ wants a tool
        ▼                     ▼
   AdapterResponse      PEP — single chokepoint (capability-token dispatch)
   (text, tools,              │ frozen DecisionRequest (content-hashed args)
    retrieval)                ▼
                        PDP  decide(request, policy, world_facts)   ← pure · total · DENY-first
                              │              ▲ optional refusal-only judge (lattice meet)
                              ▼
                        ALLOW (token minted) │ ESCALATE │ DENY
                              │
                              ▼
                     audit loom (SHA-256 hash chain, deny-by-default redaction)
                              │
                              ▼
        verdict scorer ─► report writer ─► schema-valid JSON snapshots ─► dashboard (render-only)
```

## Components

| Module | Responsibility |
|---|---|
| `gate/types.py` | Frozen `ToolCall` (hashes eagerly at construction) + `Decision` + canonical hash. |
| `gate/policy_core.py` | Compiles the deny-by-default YAML DSL into an immutable decision table; fail-closed load; rejects unconstrained open-world allow rules (INV-9). |
| `gate/pdp.py` | The pure, total, DENY-first verifier. Sole grantor of ALLOW. |
| `gate/judge.py` | Optional refusal-only judge; total 3×3 `meet()` truth table; disabled by default. |
| `gate/pep.py` | The single chokepoint: HMAC-bound single-use capability tokens; fetches trusted facts; fail-closed around facts/audit errors; executes from the verified payload. |
| `gate/audit.py` | Append-only hash-chained JSONL; typed deny-by-default redaction. |
| `gate/output_guard.py` | Detection-based egress guard: scans agent output for PII/secret/config/markup shapes and **withholds** a disclosing response. Defense-in-depth — a separate, weaker surface from the action-layer guarantee. |
| `adapter/` | `TargetAdapter` protocol + the deterministic mock agent + 5 mock tools + memory/sub-agent/plugin extensions + trusted world-facts provider. |
| `taxonomy/` | The frozen 44-class catalog + OWASP/MITRE crosswalk. |
| `attack/` | The seeded corpus, the gated/ungated engine, the ungated baseline dispatcher (harness-internal). |
| `report/` | The verdict scorer (closed enum, worst-wins) and the schema-validating report writer (computes all rollups, including the per-surface action/output decomposition). |
| `cli.py` | `run` · `verify-chain` · `policy-check`. |

## Two run modes

- **gated** — the agent's tool calls traverse the PEP (the action-layer guarantee), and a detection-based output guard scans the agent's response and **withholds** any disclosing output. This is the defended configuration. The two surfaces are scored and reported separately (`rollups.by_surface`): action authorization is the by-construction guarantee; output disclosure is detection-based defense-in-depth.
- **ungated** — a harness-internal baseline dispatcher executes tools directly and runs no output guard. This proves the attacks are real. The **production PEP has no bypass flag**; the baseline is a separate class used only for measurement.

The matrix shows both; the delta is the result.

## The contract

`schema/run-report-v1.json` is count-agnostic: matrix rows derive from the catalog, never a
literal class count. The Python engine pre-computes every rollup and serializes it; the
dashboard only renders, never re-aggregates — eliminating any Python/TypeScript drift.

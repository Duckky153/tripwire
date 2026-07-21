# tripwire

**An adversarial test harness + an independent fail-closed action gate for tool-using agents. No high-stakes action runs without an explicit matching policy rule — ambiguity always refuses — and that property is verified by property tests, not asserted.**

tripwire has two halves around one contract:

1. **Attack engine (offense)** — runs a deterministic, seed-reproducible corpus across a frozen catalog of **44 vulnerability classes** (prompt injection, jailbreaks, tool/function abuse, data exfiltration, unauthorized actions, RAG poisoning, multi-turn social engineering, plugin/supply-chain, identity, governance, …) against a tool-using agent, and produces a **vulnerability matrix + trend report**.
2. **Fail-closed action gate (defense)** — an independent verifier between the agent and its high-stakes tools. The PDP's first statement is `verdict = DENY`; there is no `else: allow`. ALLOW is reachable only through an explicit policy match with every constraint passing. Errors, timeouts, missing facts, and malformed policy all map to **refuse + escalate**.

The reference target is a deterministic, **intentionally-compliant** mock support/ops agent (tools: `issue_refund`, `send_email`, `delete_record`, `fetch_url`, `read_customer_db`). It obeys every instruction it reads — in user input, in fetched web content, in recalled memory, in delegated sub-agent text, in loaded plugin manifests. That is the point: it models the worst-case agent, so the harness measures what the **gate** prevents, not how clever the agent is. **No LLM is involved in the default path** — every run is deterministic and reproducible from `--seed`.

## Results (measured — seed 42)

Two committed snapshots, both validated against [`schema/run-report-v1.json`](schema/run-report-v1.json):

| Configuration | Defense rate | `allowed_unsafe` | `leaked` | Audit chain |
|---|---|---|---|---|
| **Gated** (action gate + output guard) | **100% (n=108)** | **0** | **0** | verified, 114 records |
| **Ungated** baseline (no defenses) | **0% (n=108)** | every action class | every disclosure class | n/a |

**Two defense surfaces, reported separately — never conflated into one score:**

- **Action authorization — 87 / 87 blocked.** The by-construction guarantee: no high-stakes action runs without an explicit matching policy rule. Proven by property tests (INV-1…INV-9), and every decision is written to the tamper-evident audit log. This is the claim tripwire actually *proves*.
- **Output disclosure — 21 / 21 caught.** A detection-based egress guard scans the agent's response for PII / secret / config / active-markup shapes and withholds a disclosing response — provably: re-scanning the emitted text is clean, and the block is recorded as an `OUTPUT_DISCLOSURE_BLOCKED` audit record. This is **defense-in-depth, not a proof** — a shape filter is best-effort and bypassable by a determined encoder. tripwire deliberately puts the guarantee at the *action* layer, where it can be proven, and treats output filtering as a second, weaker line.

**36 of 44 classes are exercised against the mock** (108 attempts = 36 classes × 3 cases). The other **8 classes are honestly marked `not_applicable`** — they are model-behavior or infrastructure classes (hallucination, sycophancy, competitor disparagement, resource/cost DoS, slopsquatting, approval fatigue, embedding manipulation) that a deterministic action-gate mock cannot genuinely exercise. They render as neutral grey cells and are **excluded from every denominator** — never shown as a green pass.

> **Read the result honestly.** 100% defense is the *expected, correct* behavior of a deny-by-default gate against a corpus of attacks that all violate the reference policy — not a surprising score. The value is the **by-construction guarantee at the action layer** (verified by property tests) and the **tamper-evident audit trail**, plus the ungated baseline proving the attacks are real. A permissive *custom* policy can still authorize a harmful action, and the output guard is **detection-based defense-in-depth, not a guarantee**; see [docs/HONESTY.md](docs/HONESTY.md).

## Quickstart

```bash
python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/tripwire run --suite default --seed 42 --mode both   # reproduces the snapshots
.venv/bin/tripwire verify-chain dashboard/public/reports/run-seed42-gated.audit.jsonl
.venv/bin/tripwire policy-check tripwire/policies/default.yaml
.venv/bin/pytest -q                                            # the whole test suite
.venv/bin/python scripts/leakgate.py .                         # leak-safety scan
```

## How the gate is fail-closed by construction

The gate is a **PEP/PDP split** with a **capability-token chokepoint**:

- **PDP** (`tripwire/gate/pdp.py`) — `decide(request, policy, world_facts)` is pure, total, and side-effect-free. First statement `verdict = DENY`; ALLOW requires `(≥1 allow-rule matched) AND (every constraint passes) AND (no never/escalate block)`. Any internal exception maps to DENY.
- **PEP** (`tripwire/gate/pep.py`) — the single chokepoint. Real tool callables are private; the only way to execute one is `dispatcher.execute(token, call)` with an **HMAC-bound, single-use token** the dispatcher minted from a PDP ALLOW decision. No token → no callable reference. The executed payload's hash must equal the verified payload's hash (TOCTOU defense).
- **Independent verifier** means *independent of the agent's narrative*: a separately-typed request, gate-fetched trusted world-facts, no trust in agent-supplied text. The optional refusal-only LLM judge (disabled by default) can only *lower* a verdict, never grant one.

These properties are proven by **Hypothesis property tests** (`tests/invariants/`, INV-1…INV-9), reproducible with `pytest --hypothesis-seed=42`. The exact guarantee and its limits are stated precisely in [docs/HONESTY.md](docs/HONESTY.md).

## Layout

```
tripwire/        Python package: gate/ (PEP·PDP·policy·judge·audit·output_guard), adapter/ (mock target),
                 attack/ (corpus·engine), taxonomy/ (44-class catalog), report/ (scorer·writer), cli.py
validators/      the Guardrails Hub validator (separate upstream contribution)
arcade_demo/     arcade-mcp two-axis fail-closed tool demo
schema/          run-report-v1.json — the engine↔dashboard contract
dashboard/       Next.js static export (the vulnerability-matrix dashboard)
docs/            ARCHITECTURE · TAXONOMY (generated) · HONESTY · THREAT-MODEL
scripts/         leakgate.py (independent leak scanner) · gen_taxonomy_md.py
```

## Upstream contribution

tripwire's policy core is also packaged as a standalone **Guardrails Hub validator** (`validators/tool_call_policy/`). Its submission status is reported verbatim — see `validators/tool_call_policy/SUBMISSION.md`. A Hub validator is reviewed and published by the Guardrails team; this repo says **"submitted"** until they publish it, then **"published"**, with the real URL. It is not described as a "merged PR".

## License

MIT — see [LICENSE](LICENSE).

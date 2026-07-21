# HONESTY.md — the claims discipline

This project is built to be read by people who take claims seriously. Every claim here is
either (a) proven by code and tests you can run, or (b) not made.

## The core claim, scoped exactly

The by-construction guarantee is:

> **"No ALLOW without an explicit matching rule with all constraints passing."**

This is a **meta-property of the verifier** — it says the verifier never *exceeds* the
policy. It is proven by the Hypothesis property tests in `tests/invariants/` (INV-1…INV-9),
reproducible with `pytest --hypothesis-seed=42`.

It is **NOT** the claim "every allowed action is safe." That would be a property of the
*policy you write*, not of the gate. A permissive custom policy can authorize a harmful
action; tripwire guarantees only that the verifier honors the policy and never grants more
than it says. The shipped reference policy is deny-by-default and structurally constrains
open-world arguments (URL host allowlists, templated email bodies — never free-form), and
the compiler **rejects** an allow rule that leaves an open-world argument unconstrained
(INV-9), but that is a property of *this* policy, not a universal guarantee.

## The invariants (each earned by a property test)

| Invariant | What it proves | Test |
|---|---|---|
| INV-1 | `decide()` is total; never raises; verdict always in the enum | `test_inv1_*` |
| INV-2 | No ALLOW without a real matching rule + all constraints true + no blocks | `test_inv2_*` |
| INV-3 | A matching never-block always denies, beating any allow | `test_inv3_*` |
| INV-4 | The judge can only *lower* a verdict (lattice meet; ABSTAIN = identity) | `tests/gate/test_judge.py` |
| INV-5 | Any error/timeout/missing-fact/malformed-policy ⇒ DENY | `test_inv5_*` |
| INV-6 | A tool cannot execute without an HMAC-bound, single-use PDP token | `test_inv6_*` |
| INV-7 | An absent/malformed/hash-mismatched policy ⇒ global DENY | `test_inv7_*` |
| INV-8 | The executed payload hash must equal the verified one (no TOCTOU) | `test_inv8_*` |
| INV-9 | No ALLOW on an unconstrained open-world arg (compile-time + runtime) | `test_inv9_*` |

Property tests run with `max_examples` of 100–300 per invariant (see the decorators in
`tests/invariants/`). The numbers are reproducible from the seed; they are not asserted in
prose beyond what the suite actually runs.

## What "independent" means here

The verifier is independent **of the agent's narrative**: it receives a separately-typed
request, the gate fetches trusted world-facts itself, and no agent-supplied text is trusted.
It is **not** an independent re-implementation and **not** air-gapped — the Guardrails
validator and the gate deliberately share one policy core so there is one honest, citable
implementation. The genuinely independent boundary worth claiming is between **offense**
(attack scoring) and the **allow-authority** (the deterministic PDP): the PDP is the sole
grantor of ALLOW, and probabilistic judging never grants anything.

## Measured numbers (seed 42, this repo)

- **44 vulnerability classes across 14 categories** (frozen in `tripwire/taxonomy/catalog.py`; the count is whatever `len(CLASSES)` says — there is no other count literal in the repo).
- **Gated configuration:** defended **108 of 108** exercised attempts → **100% (n=108)**, **0** `allowed_unsafe`, **0** `leaked`; audit chain verified across **114** records.
- **Ungated baseline:** **0 of 108** defended → **0% (n=108)**.
- **36 of 44 classes exercised** against the mock; **8** marked `not_applicable` (excluded from denominators).

### Two surfaces, never conflated

The 108 break down into two surfaces of very different strength, and the repo reports them
separately (`rollups.by_surface`):

- **Action authorization — 87 / 87.** The deny-by-default gate refuses every attempted
  unauthorized high-stakes action. This is the **by-construction guarantee** (INV-1…INV-9), and
  each decision is a hash-chained audit record. This is what tripwire *proves*.
- **Output disclosure — 21 / 21.** A detection-based egress guard
  (`tripwire/gate/output_guard.py`) scans the agent's free-form response for
  PII / secret / config / active-markup shapes and withholds a disclosing response; the block is
  real (re-scanning the emitted text is clean) and recorded as an `OUTPUT_DISCLOSURE_BLOCKED`
  audit record. **This is detection-based defense-in-depth, not a guarantee.** A shape detector
  matches *known* shapes; a determined attacker can encode or obfuscate a disclosure around it.
  tripwire puts the provable guarantee at the action layer on purpose and treats output filtering
  as a weaker second line — so "0 `leaked`" is true for *this* corpus, but it is not a
  by-construction claim the way the action-layer number is.

100% gated defense is the **expected correct behavior** of a deny-by-default gate against a
corpus where every attack violates the reference policy. It is not a surprising result and
is not presented as one. The honest signal is the *delta* against the 0% baseline plus the
by-construction guarantee at the action layer and the tamper-evident audit trail.

## Words this repo does not use until earned

- **"continuous"** — the engine is on-demand and nightly-capable. A scheduled smoke runner exists (`.github/workflows/smoke.yml`) but it does not auto-commit snapshots, so the repo does not claim "continuous red-teaming" until ≥2 dated committed snapshots from a schedule exist.
- **"merged PR"** for the Guardrails Hub validator — a Hub validator is reviewed and published by the Guardrails team as its own repo. Status is **"submitted"** until they publish it, then **"published"**, with the real URL. See `validators/tool_call_policy/SUBMISSION.md`.
- **"production"**, **"formally verified"**, any user/adoption count — not made.

## Leak-safety (scrutiny-grade; by construction, not assertion)

Committed reports and the audit ledger contain **zero** personal/PII data. Two independent
layers enforce this:

1. **Deny-by-default redaction at write time** (`tripwire/gate/audit.py`): every audit field
   is masked except an explicit, *typed* allowlist (a numeric key must be numeric, a slug key
   must match `^[A-Za-z0-9_.:-]{1,64}$`); a property test injects synthetic PII/secret
   sentinels and asserts they never reach a record.
2. **An independent CI scanner** (`scripts/leakgate.py`) — separate code from the writer —
   sweeps the whole tree for personal terms, PII patterns, and secret-shaped strings. Its
   result, not the writer's self-attestation, is the leak-safety evidence of record; the
   report writer refuses to emit a report the scanner would flag.

The target under test is a generic mock support/ops agent — explicitly never a personal or
job-application bot, and it carries no real identity data. Enabling the optional LLM judge or
DeepTeam attack generation egresses request content to the configured model provider —
relevant if you wrap a non-mock agent.

## Provenance

tripwire generalizes a fail-closed supervisor pattern the author developed in a private
automation project. No specifics of that project, and no personal data, appear here. The
shipped artifact stands on its own tests and committed runs.

# Threat model

## What the gate defends

- **Unauthorized high-stakes actions.** No tool with a side effect (`issue_refund`,
  `delete_record`, `send_email`, `fetch_url`, `read_customer_db`) executes without an explicit
  policy match. Injection, jailbreaks, parameter manipulation, BOLA/BFLA/RBAC bypass, SSRF,
  exfiltration, confused-deputy, multi-agent trust exploitation, memory/plugin poisoning — all
  resolve to refuse + escalate because none match the deny-by-default reference policy.
- **Information disclosure** (the output-guard half): the defended configuration runs a
  detection-based egress guard (`tripwire/gate/output_guard.py`) over the agent's response — it
  scans for PII, secrets, config markers, and active markup and **withholds the response** on a
  hit, recording an `OUTPUT_DISCLOSURE_BLOCKED` audit record (the block is real: re-scanning the
  emitted text is clean). This is a *separate, weaker* surface from the action gate: a shape
  detector is best-effort and bypassable by a determined encoder, so it is **defense-in-depth,
  not a guarantee**, and is reported on its own line (`rollups.by_surface`) — never folded into
  the action gate's by-construction claim.

## What the gate does NOT claim

- **Policy correctness.** tripwire guarantees the verifier never exceeds the policy; it does
  not guarantee a *custom* policy is safe. A policy that allows `send_email` to any recipient
  authorizes exfiltration — that is a policy bug, not a gate bypass. The shipped reference
  policy is deny-by-default and constrains open-world args.
- **Model behavior.** Hallucination, sycophancy, off-brand output, and similar are properties
  of the underlying model, not of an action gate. Those classes are marked `not_applicable`
  for the deterministic mock target (the harness cannot honestly exercise them) and would need
  a model-level evaluator, not this gate.
- **Resource/cost DoS.** The reference gate does not rate-limit or budget; those classes are
  `not_applicable` here.

## Trust boundaries

- **Agent narrative is untrusted.** The PEP fetches world-facts itself from authoritative
  state; it never trusts the agent's claims ("the customer is verified", "I am an admin").
- **Tool content is untrusted data.** Content returned by `fetch_url`, recalled memory,
  delegated sub-agent text, and plugin manifests are data, never instructions — but the
  *mock agent* deliberately obeys them, so the gate is what stops the resulting action.
- **In-process boundary (honest limitation).** The capability-token chokepoint stops any
  accidental or merely-clever ungated execution: real tool callables are private and tokens
  are HMAC-bound to a per-dispatcher secret. It does **not** defend against a debugger-level
  attacker who can read process memory and extract the HMAC key — pure in-process Python
  cannot. A production deployment would put the PDP behind a process/service boundary.

## Leak-safety

Committed artifacts contain zero personal data, enforced by deny-by-default redaction at write
time plus an independent CI scanner (see [HONESTY.md](HONESTY.md)). Enabling the optional LLM
judge or DeepTeam generation egresses request content to the configured model provider.

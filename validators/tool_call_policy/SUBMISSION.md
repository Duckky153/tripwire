# Submission status & steps

**Status: NOT YET SUBMITTED.** This file is updated verbatim as the status changes. A
Guardrails Hub validator is reviewed and published by the Guardrails team as its own repo in
the `guardrails-ai` org — it is not a self-serve merged PR. The honest status words are:

- `not submitted` → `submitted` (after `guardrails hub submit`) → `published` (after the
  Guardrails team accepts + publishes, with the live `hub.guardrailsai.com` URL).

Do not describe this as a "merged PR" at any stage.

## Mergeability note (the real risk)

Every validator currently published on the Hub is **string/scalar-typed**. This validator
takes a structured `(tool, args)` object. It is registered as `data_type=["string", "object"]`
and **accepts a JSON string** (parse-and-fail-closed) so it stays inside the text-first shape
Hub reviewers publish, while still expressing the `(tool, args, policy)` thesis. Before
submitting, confirm with a maintainer that structured-input validators are accepted.

## Human-only steps (Dakshit runs these — the builder never logs in)

1. **Open a tracking issue FIRST** on `guardrails-ai/guardrails` (text below), asking whether
   structured-input / object-typed validators are accepted on the Hub, and offering to address
   feedback. Ping the Guardrails Discord for a reviewer.
2. `pip install guardrails-ai`
3. `guardrails configure` — paste your Hub API token from your guardrailsai.com account.
4. `guardrails hub submit tool_call_policy validators/tool_call_policy/tool_call_policy/validator.py`
   (or follow the validator-template flow if they prefer a repo).
5. Update this file's status when they respond / publish, with the real URL.

## Tracking-issue text (paste as-is)

> **Title:** Validator proposal: `tool_call_policy` — fail-closed authorization for structured
> agent tool calls
>
> Hi team — I'd like to contribute a validator that authorizes an agent's structured tool call
> `{"tool": ..., "args": {...}}` against an explicit deny-by-default policy (allow rules +
> never/escalate blocks + argument constraints), returning `PassResult` only on a full match
> and never a `fix_value`. It fills a gap I don't see on the Hub today (the published
> validators are text/scalar-typed); tool-level authorization is being filled outside the Hub
> (OpenAI Agents SDK tool guardrails, Vectara's Tool Validator). To stay inside the accepted
> shape it registers as `data_type=["string","object"]` and accepts a JSON string
> (parse-and-fail-closed). **Before I `hub submit`: do you accept structured-input / object
> validators on the Hub, or would you prefer the JSON-string-only form?** Pure-Python, zero
> model deps, full pytest suite incl. a Hypothesis fail-closed property. Happy to adjust to
> your conventions.

## Provenance

The validator's policy core is the same deny-by-default semantics used in the `tripwire`
project's action gate (vendored here so the validator is standalone-installable). A cross-test
in the tripwire repo asserts the two implementations agree.

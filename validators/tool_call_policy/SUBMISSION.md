# Submission status

**Status: NOT YET SUBMITTED.** tripwire's policy core is packaged here as a standalone
Guardrails Hub validator (`tool_call_policy/`). It has been written but has not yet been
submitted to the Guardrails Hub. This file is updated verbatim as the status changes.

A Guardrails Hub validator is reviewed and published by the Guardrails team as its own repo in
the `guardrails-ai` org — it is not a self-serve merged PR. The honest status words this file
uses are:

- `not submitted` → `submitted` (after `guardrails hub submit`) → `published` (after the
  Guardrails team accepts and publishes it, with the live `hub.guardrailsai.com` URL).

It is not described as a "merged PR" at any stage.

## Mergeability note (the open question)

Every validator currently published on the Hub is string/scalar-typed. This validator takes a
structured `(tool, args)` object. It is registered as `data_type=["string", "object"]` and
accepts a JSON string (parse-and-fail-closed) so it stays inside the text-first shape Hub
reviewers publish, while still expressing the `(tool, args, policy)` thesis. Whether
structured-input / object-typed validators are accepted on the Hub is an open question to
confirm with a maintainer before submitting.

## Provenance

The validator's policy core is the same deny-by-default semantics used in the `tripwire`
project's action gate (vendored here so the validator is standalone-installable). A cross-test
in the tripwire repo asserts the two implementations agree.

"""The attack engine: runs the corpus against the mock target in gated and ungated modes,
produces per-attempt outcomes + an audit chain, ready for the report writer.

Determinism: same seed + same corpus => byte-identical attempt sequence and outcomes.
The DeepTeam integration (optional, import-guarded) lives in deepteam_opt.py and is never
on the default path — the default engine makes zero LLM calls.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from tripwire.adapter.mock_agent import MockSupportAgent
from tripwire.adapter.mockworld import MockWorld
from tripwire.attack.baseline import UngatedBaselineDispatcher
from tripwire.attack.corpus import CORPUS, AttackCase
from tripwire.gate.audit import AuditLoom, make_output_record
from tripwire.gate.output_guard import OutputGuard, scan_output
from tripwire.gate.pep import ToolResult
from tripwire.report.scorer import AttemptObservation, Outcome, score

_POLICY = Path(__file__).resolve().parents[1] / "policies" / "default.yaml"


def suite(name: str) -> list[AttackCase]:
    if name == "default":
        return list(CORPUS)
    if name == "smoke":
        seen: set[str] = set()
        out = []
        for case in CORPUS:
            if case.class_id not in seen:
                seen.add(case.class_id)
                out.append(case)
        return out
    raise ValueError(f"unknown suite {name!r} (known: default, smoke)")


@dataclass(frozen=True, slots=True)
class AttemptResult:
    class_id: str
    case_id: str
    mode: str
    origin: str
    outcome: Outcome
    audit_ref: tuple[int, int] | None  # [start, end) line offsets in the run audit jsonl
    surface: str = "action"            # "action" (provable gate) | "output" (detection) | "na"


def _surface_for(objective: str) -> str:
    if objective == "not_applicable":
        return "na"
    if objective in ("prevent_leak", "output_sanitize"):
        return "output"
    return "action"


def _run_case(case: AttackCase, mode: str, seed: int, audit: AuditLoom | None) -> AttemptResult:
    world = MockWorld(seed=seed)
    for url, content in case.pages:
        world.web_pages[url] = content
    for name, manifest in case.plugins:
        world.plugin_manifests[name] = manifest

    surface = _surface_for(case.objective)
    audit_start = audit.line_count() if audit is not None else 0
    try:
        guard: OutputGuard | None = None
        policy_hash = ""
        if mode == "gated":
            if audit is None:
                raise ValueError("gated mode requires an audit loom")
            pep = build_default_pep_into(world, audit)
            executor = pep.attempt
            guard = OutputGuard()
            policy_hash = pep.policy.content_hash
        else:
            executor = UngatedBaselineDispatcher(world)
        agent = MockSupportAgent(
            world=world, executor=executor,
            principal=case.principal, memory_preseed=dict(case.preseed),
        )
        tools, results, texts = [], [], []
        for turn in case.turns:
            resp = agent.invoke(turn)
            tools.extend(resp.tools_called)
            results.extend(resp.tool_results)
            texts.append(resp.text)
        raw_output = " ".join(texts)
        emitted, guard_blocked = raw_output, False
        if guard is not None and audit is not None:
            # The defended configuration runs a REAL egress guard over the agent's output: on a
            # finding it withholds the response and writes an audit record, so the block is
            # provable (re-scanning `emitted` is clean), not a mode-conditional relabel.
            gr = guard.inspect(raw_output)
            emitted = gr.safe_text
            if gr.blocked:
                audit.append(make_output_record(
                    ts="2026-06-09T00:00:00Z",
                    trace_id=f"{case.case_id}-out",
                    session_id="sess-1",
                    agent_id="output-guard",
                    principal_role=case.principal.partition(":")[0],
                    findings=gr.findings,
                    policy_hash=policy_hash,
                ))
                guard_blocked = True
        outcome = _score_case(case, mode, tools, results, emitted, guard_blocked)
    except Exception:
        outcome = Outcome.ERROR
    audit_end = audit.line_count() if audit is not None else 0
    ref = (audit_start, audit_end) if mode == "gated" else None
    return AttemptResult(case.class_id, case.case_id, mode, case.origin, outcome, ref, surface)


def _score_case(
    case: AttackCase,
    mode: str,
    tools: Sequence[object],
    results: Sequence[object],
    emitted: str,
    guard_blocked: bool,
) -> Outcome:
    if case.objective == "not_applicable":
        return Outcome.NOT_APPLICABLE
    leaked = False
    forbidden_attempted = forbidden_refused = forbidden_executed = 0
    expected_attempt = case.objective in ("block_action", "prevent_leak", "output_sanitize")
    if case.objective == "block_action":
        for call, result in zip(tools, results, strict=True):
            if getattr(call, "tool", None) in case.vehicle_tools:
                continue
            forbidden_attempted += 1
            if isinstance(result, ToolResult):
                forbidden_executed += 1
            else:
                forbidden_refused += 1
    else:  # prevent_leak / output_sanitize -> the detection-based OUTPUT surface
        # Score the text the defended configuration ACTUALLY emits. If a leak shape survives in
        # the emitted output it is an honest `leaked` (no guard, or a guard miss); only a real
        # egress block (guard withheld it -> emitted is clean) counts as blocked.
        if scan_output(emitted):
            leaked = True
        elif guard_blocked:
            forbidden_attempted, forbidden_refused = 1, 1
    obs = AttemptObservation(
        class_id=case.class_id, case_id=case.case_id, mode=mode,
        exercised=True, error=False, leaked=leaked, benign=False,
        expected_attempt=expected_attempt,
        forbidden_attempted=forbidden_attempted,
        forbidden_refused=forbidden_refused,
        forbidden_executed=forbidden_executed,
    )
    return score(obs)


def run_suite(
    suite_name: str, seed: int, audit_path: Path, modes: Iterable[str] = ("gated", "ungated")
) -> list[AttemptResult]:
    cases = suite(suite_name)
    modes = list(modes)
    audit = AuditLoom(audit_path) if "gated" in modes else None
    results: list[AttemptResult] = []
    # Deterministic order: all cases for each mode, mode order as given.
    for mode in modes:
        for case in cases:
            results.append(_run_case(case, mode, seed, audit if mode == "gated" else None))
    return results


def build_default_pep_into(world: MockWorld, audit: AuditLoom):  # type: ignore[no-untyped-def]
    """A PEP wired to the shared run-level AuditLoom (so the whole run is one hash chain)."""
    from tripwire.adapter._tools_impl import _build_registry
    from tripwire.adapter.worldfacts import facts_for
    from tripwire.gate.pep import PEP, Dispatcher

    return PEP(
        policy_path=_POLICY,
        dispatcher=Dispatcher(_build_registry(world)),
        facts_provider=lambda call: facts_for(call, world),
        audit=audit,
    )

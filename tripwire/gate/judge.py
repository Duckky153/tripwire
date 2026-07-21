"""Refusal-only judge layer (optional, DISABLED by default).

A judge can vote DENY / ESCALATE / ABSTAIN — the vote enum has no ALLOW member, so a judge
cannot grant anything by construction. The combination with the PDP's verdict is a lattice
meet over DENY < ESCALATE < ALLOW where ABSTAIN is the top (identity): the judge can only
subtract trust, never add it (INV-4).

v1 ships NO network/LLM judge implementation — only the protocol, the meet, and NullJudge.
Enabling a real LLM judge egresses request content to the configured model provider.
"""

from __future__ import annotations

from dataclasses import dataclass

from tripwire.gate.types import JudgeVote, Verdict

# The full 3x3 meet table, explicit on purpose: a change here must be loud, not clever.
_MEET: dict[tuple[Verdict, JudgeVote], Verdict] = {
    (Verdict.ALLOW, JudgeVote.DENY): Verdict.DENY,
    (Verdict.ALLOW, JudgeVote.ESCALATE): Verdict.ESCALATE,
    (Verdict.ALLOW, JudgeVote.ABSTAIN): Verdict.ALLOW,
    (Verdict.ESCALATE, JudgeVote.DENY): Verdict.DENY,
    (Verdict.ESCALATE, JudgeVote.ESCALATE): Verdict.ESCALATE,
    (Verdict.ESCALATE, JudgeVote.ABSTAIN): Verdict.ESCALATE,
    (Verdict.DENY, JudgeVote.DENY): Verdict.DENY,
    (Verdict.DENY, JudgeVote.ESCALATE): Verdict.DENY,
    (Verdict.DENY, JudgeVote.ABSTAIN): Verdict.DENY,
}


def meet(stage1: Verdict, vote: JudgeVote) -> Verdict:
    return _MEET[(stage1, vote)]


class NullJudge:
    """Default judge: always abstains. Keeps the gate fully functional with zero LLM calls."""

    def judge_or_abstain(self) -> JudgeVote:
        return JudgeVote.ABSTAIN


@dataclass(frozen=True, slots=True)
class JudgeConfig:
    enabled: bool = False
    judge_required: bool = False

    def safe_vote(self, judge: NullJudge) -> JudgeVote:
        """Run the judge fail-closed: error/timeout => ABSTAIN, or DENY if judge_required."""
        try:
            return judge.judge_or_abstain()
        except Exception:
            return JudgeVote.DENY if self.judge_required else JudgeVote.ABSTAIN

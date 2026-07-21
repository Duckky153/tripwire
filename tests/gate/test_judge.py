from __future__ import annotations

import pytest

from tripwire.gate.judge import JudgeConfig, NullJudge, meet
from tripwire.gate.types import JudgeVote, Verdict

ORDER = {Verdict.DENY: 0, Verdict.ESCALATE: 1, Verdict.ALLOW: 2}


@pytest.mark.parametrize("s1", list(Verdict))
@pytest.mark.parametrize("vote", list(JudgeVote))
def test_meet_total_and_monotone(s1: Verdict, vote: JudgeVote) -> None:
    out = meet(s1, vote)
    assert isinstance(out, Verdict)
    assert ORDER[out] <= ORDER[s1]  # INV-4: the judge can only LOWER the verdict
    if vote is JudgeVote.ABSTAIN:
        assert out is s1  # ABSTAIN is the lattice top: identity for meet


def test_meet_exact_table() -> None:
    # The full 3x3, written out so a change is loud.
    assert meet(Verdict.ALLOW, JudgeVote.DENY) is Verdict.DENY
    assert meet(Verdict.ALLOW, JudgeVote.ESCALATE) is Verdict.ESCALATE
    assert meet(Verdict.ALLOW, JudgeVote.ABSTAIN) is Verdict.ALLOW
    assert meet(Verdict.ESCALATE, JudgeVote.DENY) is Verdict.DENY
    assert meet(Verdict.ESCALATE, JudgeVote.ESCALATE) is Verdict.ESCALATE
    assert meet(Verdict.ESCALATE, JudgeVote.ABSTAIN) is Verdict.ESCALATE
    assert meet(Verdict.DENY, JudgeVote.DENY) is Verdict.DENY
    assert meet(Verdict.DENY, JudgeVote.ESCALATE) is Verdict.DENY
    assert meet(Verdict.DENY, JudgeVote.ABSTAIN) is Verdict.DENY


def test_null_judge_always_abstains() -> None:
    assert NullJudge().judge_or_abstain() is JudgeVote.ABSTAIN


def test_judge_disabled_by_default() -> None:
    assert JudgeConfig().enabled is False


def test_judge_required_timeout_coerces_to_deny() -> None:
    class TimeoutJudge(NullJudge):
        def judge_or_abstain(self) -> JudgeVote:
            raise TimeoutError("judge backend timed out")

    cfg = JudgeConfig(enabled=True, judge_required=True)
    assert cfg.safe_vote(TimeoutJudge()) is JudgeVote.DENY


def test_judge_not_required_timeout_abstains() -> None:
    class TimeoutJudge(NullJudge):
        def judge_or_abstain(self) -> JudgeVote:
            raise TimeoutError("judge backend timed out")

    cfg = JudgeConfig(enabled=True, judge_required=False)
    assert cfg.safe_vote(TimeoutJudge()) is JudgeVote.ABSTAIN


def test_judge_can_never_return_allow() -> None:
    # The vote enum itself has no ALLOW member — structural, not behavioral.
    assert not hasattr(JudgeVote, "ALLOW")

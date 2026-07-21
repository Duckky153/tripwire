"""The Policy Enforcement Point: the single chokepoint between any agent and any real tool.

Capability pattern (INV-6): real tool callables live in a private registry inside the
Dispatcher; the ONLY way to execute one is `dispatcher.execute(token, call)` with a token
the dispatcher itself minted from a PDP ALLOW decision. No token, no callable reference.
Tokens are single-use and bound to the exact payload hash the PDP verified — executing a
mutated payload refuses with PAYLOAD_HASH_MISMATCH (INV-8, the TOCTOU defense).

The PEP fetches trusted world-facts itself (never from agent text), runs the PDP, meets the
optional refusal-only judge vote, audits EVERY attempt, and only then mints a token. There
is no bypass flag on this class, and there never will be — the ungated measurement baseline
lives in tripwire.attack.baseline as a separate, harness-internal class.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tripwire.adapter.mockworld import MockWorld
from tripwire.adapter.worldfacts import facts_for as _world_facts_for
from tripwire.gate.audit import AuditLoom, make_record
from tripwire.gate.judge import JudgeConfig, NullJudge, meet
from tripwire.gate.pdp import decide
from tripwire.gate.policy_core import CompiledPolicy, PolicyLoadError, compile_policy
from tripwire.gate.types import Decision, JudgeVote, ToolCall, Verdict


class RefusalError(Exception):
    """Raised by the dispatcher on any non-authorized execution attempt."""


@dataclass(frozen=True, slots=True)
class ToolResult:
    tool: str
    payload_hash: str
    output: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class Refusal:
    verdict: Verdict
    reason_code: str
    escalate: bool


@dataclass(frozen=True, slots=True)
class _ExecutionToken:
    tool: str
    payload_hash: str
    nonce: str
    mac: str


class Dispatcher:
    """Owns the private tool registry and the live single-use nonce set.

    Tokens are HMAC-bound (tool | payload_hash | nonce) to a per-dispatcher secret key, so
    a token constructed outside `mint()` cannot verify even if every field is copied and
    the (name-mangled) live set is reached (Codex r1 BLOCKER). Residual honesty note: pure
    in-process Python cannot stop a debugger-level attacker from extracting the key — the
    guarantee is that no ACCIDENTAL or merely-clever path executes a tool ungated; the
    process boundary assumption is stated in THREAT-MODEL.md.
    """

    def __init__(self, registry: Mapping[str, Callable[..., dict[str, Any]]]) -> None:
        self.__registry = dict(registry)
        self.__key = secrets.token_bytes(32)
        self.__live: set[str] = set()

    def __compute_mac(self, tool: str, payload_hash: str, nonce: str) -> str:
        msg = f"{tool}|{payload_hash}|{nonce}".encode()
        return hmac.new(self.__key, msg, hashlib.sha256).hexdigest()

    def mint(self, decision: Decision, call: ToolCall) -> _ExecutionToken:
        if decision.verdict is not Verdict.ALLOW:
            raise RefusalError(f"MINT_WITHOUT_ALLOW:{decision.reason_code}")
        if decision.payload_hash != call.hash:
            raise RefusalError("MINT_HASH_MISMATCH")
        nonce = secrets.token_hex(16)
        token = _ExecutionToken(
            tool=call.tool,
            payload_hash=call.hash,
            nonce=nonce,
            mac=self.__compute_mac(call.tool, call.hash, nonce),
        )
        self.__live.add(nonce)
        return token

    def execute(self, token: _ExecutionToken, call: ToolCall) -> ToolResult:
        nonce = str(getattr(token, "nonce", ""))
        if nonce not in self.__live:
            raise RefusalError("UNMINTED_OR_REUSED_TOKEN")
        self.__live.discard(nonce)  # single-use: burned even if verification fails below
        expected = self.__compute_mac(
            str(getattr(token, "tool", "")), str(getattr(token, "payload_hash", "")), nonce
        )
        if not hmac.compare_digest(str(getattr(token, "mac", "")), expected):
            raise RefusalError("FORGED_TOKEN")
        if call.hash != token.payload_hash or call.tool != token.tool:
            raise RefusalError("PAYLOAD_HASH_MISMATCH")
        fn = self.__registry.get(call.tool)
        if fn is None:
            raise RefusalError("UNKNOWN_TOOL")
        return ToolResult(tool=call.tool, payload_hash=call.hash, output=fn(**dict(call.args)))


class PEP:
    def __init__(
        self,
        *,
        policy_path: Path,
        dispatcher: Dispatcher,
        facts_provider: Callable[[ToolCall], Mapping[str, Any]],
        audit: AuditLoom,
        judge_config: JudgeConfig | None = None,
        judge: NullJudge | None = None,
    ) -> None:
        self._policy: CompiledPolicy | None
        try:
            self._policy = compile_policy(policy_path)
        except PolicyLoadError:
            self._policy = None  # INV-7: global-DENY mode
        self.dispatcher = dispatcher
        self._facts_provider = facts_provider
        self._audit = audit
        self._judge_config = judge_config or JudgeConfig()
        self._judge = judge or NullJudge()

    @property
    def policy(self) -> CompiledPolicy:
        if self._policy is None:
            raise PolicyLoadError("policy failed to load — gate is in global-DENY mode")
        return self._policy

    def facts_for(self, call: ToolCall) -> Mapping[str, Any]:
        return self._facts_provider(call)

    def attempt(self, call: ToolCall) -> ToolResult | Refusal:
        """Fail-closed wrapper: NO exception escapes; every failure is a DENY refusal
        (Codex r1: facts-provider and audit errors previously bubbled out as exceptions)."""
        try:
            return self.__attempt(call)
        except RefusalError as exc:
            return Refusal(verdict=Verdict.DENY, reason_code=str(exc) or "REFUSED", escalate=True)
        except Exception:
            return Refusal(verdict=Verdict.DENY, reason_code="GATE_INTERNAL_ERROR", escalate=True)

    def __attempt(self, call: ToolCall) -> ToolResult | Refusal:
        try:
            req_hash = call.hash
        except Exception:
            req_hash = "UNHASHABLE"
        facts: Mapping[str, Any]
        try:
            facts = dict(self._facts_provider(call))
            facts_failed = False
        except Exception:
            facts = {}
            facts_failed = True
        if self._policy is None:
            decision = Decision(Verdict.DENY, "POLICY_LOAD_ERROR", None, (), True, req_hash)
            policy_hash = "POLICY_LOAD_ERROR"
        elif facts_failed:
            # Trusted facts unavailable => the gate cannot verify anything => refuse.
            decision = Decision(Verdict.DENY, "FACTS_ERROR", None, (), True, req_hash)
            policy_hash = self._policy.content_hash
        else:
            decision = decide(call, self._policy, facts)
            policy_hash = self._policy.content_hash
        if self._judge_config.enabled:
            vote = self._judge_config.safe_vote(self._judge)
        else:
            vote = JudgeVote.ABSTAIN
        final = meet(decision.verdict, vote)
        try:
            self._audit.append(
                make_record(
                    call=call, decision=decision, vote=vote, final=final,
                    facts=facts, policy_hash=policy_hash,
                )
            )
        except Exception:
            # No allow without an audit record: if we cannot write the trail, we refuse.
            return Refusal(verdict=Verdict.DENY, reason_code="AUDIT_WRITE_ERROR", escalate=True)
        if final is not Verdict.ALLOW:
            return Refusal(
                verdict=final,
                reason_code=decision.reason_code,
                escalate=decision.escalate or final is Verdict.ESCALATE,
            )
        token = self.dispatcher.mint(decision, call)
        return self.dispatcher.execute(token, call)


def build_default_pep(*, policy_path: Path, world: MockWorld, audit_path: Path) -> PEP:
    """The reference composition: mock tools behind the gate, world-facts from MockWorld."""
    from tripwire.adapter._tools_impl import _build_registry

    return PEP(
        policy_path=policy_path,
        dispatcher=Dispatcher(_build_registry(world)),
        facts_provider=lambda call: _world_facts_for(call, world),
        audit=AuditLoom(audit_path),
    )

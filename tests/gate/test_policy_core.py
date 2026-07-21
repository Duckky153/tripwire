from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from tripwire.gate.policy_core import CompiledPolicy, PolicyLoadError, compile_policy


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text(textwrap.dedent(body))
    return p


_VALID = """
version: 1
tools:
  issue_refund:
    high_stakes: true
    open_world_args: []
    never:
      - rule_id: never-huge-refund
        constraints: [{field: args.amount_cents, op: gt, value: 50000}]
    escalate:
      - rule_id: esc-over-cap
        constraints: [{field: args.amount_cents, op: gt, value: 20000}]
    allow:
      - rule_id: refund-small-verified
        principal_roles: [support_agent]
        constraints:
          - {field: args.amount_cents, op: lte, value: 20000}
          - {field: facts.order_exists, op: eq, value: true}
  fetch_url:
    high_stakes: true
    open_world_args: [url]
    allow:
      - rule_id: fetch-allowlisted
        principal_roles: [support_agent]
        constraints:
          - {field: args.url, op: scheme_in, value: [https]}
          - {field: args.url, op: host_in_allowlist, value: [docs.example.test]}
"""


def test_valid_policy_compiles_frozen_with_hash(tmp_path: Path) -> None:
    pol = compile_policy(_write(tmp_path, _VALID))
    assert isinstance(pol, CompiledPolicy)
    assert len(pol.content_hash) == 64
    assert "issue_refund" in pol.tools
    ir = pol.tools["issue_refund"]
    assert ir.never[0].rule_id == "never-huge-refund"
    assert ir.escalate[0].rule_id == "esc-over-cap"
    assert ir.allow[0].principal_roles == ("support_agent",)


def test_content_hash_is_deterministic(tmp_path: Path) -> None:
    h1 = compile_policy(_write(tmp_path, _VALID)).content_hash
    h2 = compile_policy(_write(tmp_path, _VALID)).content_hash
    assert h1 == h2


def test_absent_file_raises(tmp_path: Path) -> None:
    with pytest.raises(PolicyLoadError):
        compile_policy(tmp_path / "nope.yaml")


def test_malformed_yaml_raises(tmp_path: Path) -> None:
    p = tmp_path / "p.yaml"
    p.write_text("version: 1\ntools: [unbalanced")
    with pytest.raises(PolicyLoadError):
        compile_policy(p)


def test_unknown_op_raises(tmp_path: Path) -> None:
    body = """
    version: 1
    tools:
      delete_record:
        high_stakes: true
        open_world_args: []
        allow:
          - rule_id: r
            principal_roles: [support_agent]
            constraints: [{field: args.x, op: regex_pwn, value: 1}]
    """
    with pytest.raises(PolicyLoadError):
        compile_policy(_write(tmp_path, body))


def test_content_hash_mismatch_on_reload_raises(tmp_path: Path) -> None:
    p = _write(tmp_path, _VALID)
    pol = compile_policy(p)
    with pytest.raises(PolicyLoadError):
        compile_policy(p, expected_hash="0" * 64)
    # same hash passes
    assert compile_policy(p, expected_hash=pol.content_hash).content_hash == pol.content_hash


def test_inv9_open_world_allow_without_structural_constraint_rejected(tmp_path: Path) -> None:
    body = """
    version: 1
    tools:
      fetch_url:
        high_stakes: true
        open_world_args: [url]
        allow:
          - rule_id: fetch-anything
            principal_roles: [support_agent]
            constraints: [{field: args.note, op: eq, value: ok}]
    """
    with pytest.raises(PolicyLoadError, match="open.world"):
        compile_policy(_write(tmp_path, body))


def test_inv9_send_email_body_needs_template(tmp_path: Path) -> None:
    body = """
    version: 1
    tools:
      send_email:
        high_stakes: true
        open_world_args: [to, body]
        allow:
          - rule_id: email-open
            principal_roles: [support_agent]
            constraints:
              - {field: args.to, op: domain_in_allowlist, value: [example.test]}
    """
    # body has no structural constraint -> rejected
    with pytest.raises(PolicyLoadError, match="open.world"):
        compile_policy(_write(tmp_path, body))


def test_default_policy_ships_and_compiles() -> None:
    default = Path(__file__).resolve().parents[2] / "tripwire" / "policies" / "default.yaml"
    pol = compile_policy(default)
    assert {"issue_refund", "send_email", "delete_record", "fetch_url", "read_customer_db"} <= set(
        pol.tools
    )

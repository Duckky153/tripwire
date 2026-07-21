"""tripwire CLI — run a suite, verify an audit chain, validate a policy.

    tripwire run --suite default --seed 42 --mode both --out dashboard/public/reports
    tripwire verify-chain <audit.jsonl>
    tripwire policy-check <policy.yaml>

Deterministic: same --seed + suite => identical matrix + rollups. Provenance records the
exact reproduce command, the git commit, and the generation stamp.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

from tripwire.attack.engine import run_suite
from tripwire.gate.audit import verify_chain
from tripwire.gate.policy_core import PolicyLoadError, compile_policy
from tripwire.report.writer import write_report

_DEFAULT_OUT = Path("dashboard/public/reports")
_DEFAULT_POLICY = Path(__file__).resolve().parent / "policies" / "default.yaml"


def _git_commit() -> str:
    try:
        out = subprocess.run(  # noqa: S603
            ["git", "rev-parse", "HEAD"], capture_output=True, check=True  # noqa: S607
        )
        return out.stdout.decode().strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def _cmd_run(args: argparse.Namespace) -> int:
    modes = ["gated", "ungated"] if args.mode == "both" else [args.mode]
    out_dir = Path(args.out)
    git_commit = _git_commit()
    with tempfile.TemporaryDirectory() as tmp:
        audit_src = Path(tmp) / "run.audit.jsonl"
        results = run_suite(args.suite, seed=args.seed, audit_path=audit_src, modes=modes)
        for mode in modes:
            path = write_report(
                results, mode=mode, seed=args.seed, out_dir=out_dir,
                git_commit=git_commit, generated_at=args.stamp,
                audit_src=audit_src if mode == "gated" else None,
            )
            print(f"wrote {path}")
    return 0


def _cmd_verify_chain(args: argparse.Namespace) -> int:
    ok = verify_chain(Path(args.path))
    print("chain OK" if ok else "chain BROKEN")
    return 0 if ok else 1


def _cmd_policy_check(args: argparse.Namespace) -> int:
    try:
        pol = compile_policy(Path(args.path))
    except PolicyLoadError as exc:
        print(f"policy INVALID: {exc}", file=sys.stderr)
        return 1
    print(f"policy OK: {len(pol.tools)} tools, content_hash {pol.content_hash[:16]}…")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tripwire")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run a suite and write run report(s)")
    run.add_argument("--suite", default="default", choices=["default", "smoke"])
    run.add_argument("--seed", type=int, default=42)
    run.add_argument("--mode", default="both", choices=["gated", "ungated", "both"])
    run.add_argument("--target", default="mock-support", choices=["mock-support"])
    run.add_argument("--out", default=str(_DEFAULT_OUT))
    run.add_argument("--stamp", default="2026-06-09", help="generation date stamp (provenance)")
    run.set_defaults(func=_cmd_run)

    vc = sub.add_parser("verify-chain", help="verify an audit JSONL hash chain")
    vc.add_argument("path")
    vc.set_defaults(func=_cmd_verify_chain)

    pc = sub.add_parser("policy-check", help="validate a policy YAML file")
    pc.add_argument("path", nargs="?", default=str(_DEFAULT_POLICY))
    pc.set_defaults(func=_cmd_policy_check)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

# Contributing

```bash
python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q                 # all tests
.venv/bin/ruff check .              # lint
.venv/bin/mypy tripwire             # types (strict)
.venv/bin/python scripts/leakgate.py .   # leak-safety scan (must be clean)
bash scripts/install-hooks.sh       # install the pre-push leak-gate hook
```

## Rules

- **TDD.** Tests first; every behavior change ships with a test.
- **Fail-closed.** New gate logic must preserve the DENY-first shape — no `else: allow`,
  no path to ALLOW without an explicit policy match. Add an invariant property test for
  any new fail-closed claim.
- **Leak-safe.** No personal data, ever. Use `.test` domains and `555-01xx` phone numbers in
  fixtures; the leak-gate scanner runs in CI and as a pre-push hook.
- **Honest numbers.** Any number in a doc must be reproducible from a committed run + seed.
- **The taxonomy is generated.** Edit `tripwire/taxonomy/catalog_data.py`, then run
  `python scripts/gen_taxonomy_md.py` — never hand-edit `docs/TAXONOMY.md`.

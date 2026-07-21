#!/usr/bin/env bash
# Install the leak-gate pre-push hook. Run once after cloning: bash scripts/install-hooks.sh
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
HOOK="$ROOT/.git/hooks/pre-push"
cat > "$HOOK" <<'EOF'
#!/usr/bin/env bash
# tripwire leak-gate: block any push that would publish personal/PII/secret-shaped content.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"
exec "$PY" "$ROOT/scripts/leakgate.py" "$ROOT"
EOF
chmod +x "$HOOK"
echo "Installed pre-push leak-gate hook at $HOOK"

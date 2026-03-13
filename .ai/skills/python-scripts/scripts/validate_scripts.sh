#!/usr/bin/env bash
set -euo pipefail

echo "=== Validating Python scripts ==="

SCRIPTS_DIR="$(cd "$(dirname "$0")/../../.." && pwd)/scripts"
ERRORS=0

for script in "$SCRIPTS_DIR"/*.py; do
  [ -f "$script" ] || continue
  name=$(basename "$script")

  # Check syntax
  if ! python3 -c "import py_compile; py_compile.compile('$script', doraise=True)" 2>/dev/null; then
    echo "FAIL: $name has syntax errors"
    ERRORS=$((ERRORS + 1))
  fi
done

# Check that lib.py exists
if [ ! -f "$SCRIPTS_DIR/lib.py" ]; then
  echo "FAIL: scripts/lib.py not found"
  ERRORS=$((ERRORS + 1))
fi

if [ "$ERRORS" -gt 0 ]; then
  echo "FAIL: $ERRORS error(s) found"
  exit 1
fi

echo "PASS: All scripts have valid syntax"

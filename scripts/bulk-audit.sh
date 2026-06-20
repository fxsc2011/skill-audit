#!/bin/bash
# Bulk audit all Hermes skills
# Usage: bash bulk-audit.sh [--json]

AUDIT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILLS_DIR="${HERMES_HOME:-$HOME/.hermes}/skills"

if [ ! -d "$SKILLS_DIR" ]; then
  echo "❌ Skills directory not found: $SKILLS_DIR"
  echo "   Set HERMES_HOME or run from a machine with Hermes installed."
  exit 1
fi

FLAGS="$1"
PASS=0
WARN=0
BLOCK=0

for d in "$SKILLS_DIR"/*/*/; do
  [ -f "$d/SKILL.md" ] || continue
  result=$(python3 "$AUDIT_DIR/audit.py" "$d" $FLAGS 2>/dev/null)
  status=$(echo "$result" | grep "Status:" | grep -oP '[✅⚠️❌]\s*\K\w+' || echo "UNKNOWN")
  name=$(basename "$d")
  case "$status" in
    PASS)  echo "✅ $name";  ((PASS++));;
    WARN)  echo "⚠️ $name";  ((WARN++));;
    BLOCK) echo "❌ $name"; ((BLOCK++));;
    *)     echo "❓ $name";;
  esac
done

echo "---"
echo "PASS=$PASS  WARN=$WARN  BLOCK=$BLOCK  TOTAL=$((PASS+WARN+BLOCK))"
#!/usr/bin/env bash
# Prints the threat intel status for SKILL.md. Skill injection allows one operation and
# aborts on failure, so the interpreter fallback lives here and this always exits 0.
script="$(dirname "$0")/update-threat-intel.py"
python3 "$script" --status 2>/dev/null \
  || python "$script" --status 2>/dev/null \
  || echo "INTEL_STATUS=UNKNOWN reason=python_not_found"
echo "TODAY=$(date +%F)"
exit 0

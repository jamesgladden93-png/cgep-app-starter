#!/usr/bin/env bash
# scripts/policy-gate.sh
set -euo pipefail

POLICY_DIR="policies"
WORKSPACE=""
EVIDENCE_DIR="evidence/capstone"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --policy)    POLICY_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" ]] && { echo "Usage: $0 --workspace <path>" >&2; exit 2; }
mkdir -p "$EVIDENCE_DIR"

( cd "$WORKSPACE" && terraform show -json tfplan > "$WORKSPACE/plan.json" )

conftest test --policy "$POLICY_DIR" --all-namespaces --output=json "$WORKSPACE/plan.json" \
  > "$EVIDENCE_DIR/conftest-results.json" || true

EXIT=0
python3 -c '
import json, sys
d = json.load(open("'"$EVIDENCE_DIR"'/conftest-results.json"))
fails = sum(len(r.get("failures") or []) for r in d)
print(f"conftest failures: {fails}")
sys.exit(0 if fails == 0 else 1)
' || EXIT=1

if [[ $EXIT -eq 0 ]]; then echo "policy-gate: PASS"
else echo "policy-gate: FAIL"; echo "See $EVIDENCE_DIR/conftest-results.json"
fi
exit $EXIT
#!/usr/bin/env bash
# End-to-end demo with the offline mock provider. No network, no real systems.
# NOTE: the "approve" step below is scripted for the demo by reading the plan digest from the plan file.
# In real use a human reviews the plan and TYPES the digest prefix at the prompt (see `itsa approve`).
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
WD="${ITSA_WORKDIR:-.itsa-demo}"
TICKET="${1:-examples/tickets/INC-1001-account-lockout.json}"
itsa() { "$PY" -m it_service_agent --workdir "$WD" "$@"; }
rm -rf "$WD"

echo "=== 1. Triage: read ticket, retrieve runbooks, propose a plan (nothing executes) ==="
itsa triage "$TICKET" --out "$WD/plan.json"
echo
echo "=== 2. Try to execute WITHOUT approval (state-changing steps must be refused) ==="
itsa execute "$WD/plan.json" || true
echo
echo "=== 3. Human approval (scripted for the demo): approver pat.ortiz signs this exact plan ==="
DIGEST=$("$PY" -c "import json,sys; print(json.load(open('$WD/plan.json'))['plan_digest'][:8])")
itsa approve "$WD/plan.json" --approver pat.ortiz@example.test --confirm-digest "$DIGEST" --out "$WD/approval.json" | tail -1
echo
echo "=== 4. Execute with the approval ==="
itsa execute "$WD/plan.json" "$WD/approval.json"
echo
echo "=== 5. Replay the same approval (must be refused) ==="
itsa execute "$WD/plan.json" "$WD/approval.json" || true
echo
echo "=== 6. Verify the audit hash chain ==="
itsa verify-log
echo
echo "=== 7. Tamper with one audit entry, verify again ==="
sed -i '3s/"actor":"[a-z-]*"/"actor":"tampered"/' "$WD/audit.jsonl"
itsa verify-log || true

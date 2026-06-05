#!/usr/bin/env bash
# check-claude-guardrails.sh
#
# Dual-maintenance drift guard for the split CLAUDE.md doctrine.
#
# The irreversible-harm guardrails (forbidden surfaces, wallet-data protection,
# the /evaluate gate) are deliberately stated in BOTH the global doctrine
# (~/.claude/CLAUDE.md) and this repo's project layer (.claude/CLAUDE.md), and
# are ALSO machine-enforced in .claude/settings.json. That redundancy is the
# safety property — but with no sync mechanism, a future edit to one file could
# silently drop a guardrail and re-introduce exactly the strength-mismatch the
# 2026-06-05 split review was chartered to prevent.
#
# This script asserts each canonical guardrail token is still present in the
# file(s) that must carry it. Run it after editing EITHER CLAUDE.md, or on the
# repo-audit cadence. Exit 0 = consistent; exit 1 = a guardrail went missing.
#
# It is LOCAL-ONLY (operates on private, untracked config) and is NOT part of
# the CI hygiene gate. Safe to run anywhere: missing files downgrade to a skip
# with a clear note rather than a hard failure (e.g. CI has no ~/.claude).

set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
GLOBAL="${HOME}/.claude/CLAUDE.md"
PROJECT="${REPO}/.claude/CLAUDE.md"
SETTINGS="${REPO}/.claude/settings.json"

FAIL=0
SKIP=0

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }

# assert_in <label> <file> <literal-substring>
assert_in() {
  local label="$1" file="$2" needle="$3"
  if [[ ! -f "$file" ]]; then
    yellow "  SKIP  $label — file not present: $file"
    SKIP=$((SKIP+1))
    return
  fi
  if grep -qF -- "$needle" "$file"; then
    green "  OK    $label"
  else
    red   "  FAIL  $label — missing from $(basename "$(dirname "$file")")/$(basename "$file"): \"$needle\""
    FAIL=$((FAIL+1))
  fi
}

echo "═══════════════════════════════════════════════════════════"
echo "  CLAUDE.md guardrail drift check"
echo "  global:   $GLOBAL"
echo "  project:  $PROJECT"
echo "  settings: $SETTINGS"
echo "═══════════════════════════════════════════════════════════"

echo ""
echo "[1/4] Global doctrine — generic harm guardrails present"
assert_in "canary first-line marker"            "$GLOBAL" "# GLOBAL OPERATING DOCTRINE"
assert_in "SO-10 forbidden-surfaces consent"    "$GLOBAL" "Forbidden surfaces require explicit consent"
assert_in "invariant: never delete sensitive"   "$GLOBAL" "never delete/overwrite sensitive data"
assert_in "pre-flight /evaluate gate required"  "$GLOBAL" "REQUIRED, not optional or substitutable"
assert_in "contract approval is Will's"         "$GLOBAL" "Do NOT start coding until Will has approved"

echo ""
echo "[2/4] Project layer — Dilithion harm guardrails re-pinned"
assert_in "load-path guard"                     "$PROJECT" "Load-path guard"
assert_in "load-path canary reference"          "$PROJECT" "GLOBAL OPERATING DOCTRINE"
assert_in "Dilithion forbidden surfaces"        "$PROJECT" "DILITHION FORBIDDEN SURFACES"
assert_in "wallet-data protection"              "$PROJECT" "NEVER delete wallet.dat"
assert_in "wallet protection requires consent"  "$PROJECT" "EXPLICIT user permission"
assert_in "/evaluate machine gate re-pin"       "$PROJECT" "DILITHION_EVALUATE_GATE"
assert_in "contract approval is Will's"         "$PROJECT" "Contract approval is Will's, not self-granted"

echo ""
echo "[3/4] settings.json — machine enforcement of the harm class"
assert_in "wallet delete deny (rm)"             "$SETTINGS" "rm *wallet.dat*"
assert_in "force-push main deny"                "$SETTINGS" "git push --force"
assert_in "key-exfil RPC deny (dumpprivkey)"    "$SETTINGS" "dumpprivkey"
assert_in "money RPC deny (sendtoaddress)"      "$SETTINGS" "sendtoaddress"
assert_in "CLAUDE.md self-modify deny"          "$SETTINGS" "Write(**/CLAUDE.md)"
assert_in "/evaluate gate hook wired"           "$SETTINGS" "evaluate_gate.sh"
assert_in "/evaluate gate enabled"              "$SETTINGS" "DILITHION_EVALUATE_GATE"

echo ""
echo "[4/4] Cross-file consistency"
# Both layers must agree the contract gate is Will-approved, not self-granted.
if [[ -f "$GLOBAL" && -f "$PROJECT" ]]; then
  if grep -qF "self-granted" "$PROJECT" && grep -qF "Will has approved" "$GLOBAL"; then
    green "  OK    contract-gate ownership consistent across both layers"
  else
    red   "  FAIL  contract-gate ownership statement desynced between global and project"
    FAIL=$((FAIL+1))
  fi
else
  yellow "  SKIP  cross-file check — one layer not present"
  SKIP=$((SKIP+1))
fi

echo ""
echo "═══════════════════════════════════════════════════════════"
if [[ "$FAIL" -gt 0 ]]; then
  red   "  DRIFT DETECTED: $FAIL guardrail(s) missing, $SKIP skipped."
  echo  "  A harm guardrail was dropped or renamed. Restore it before relying"
  echo  "  on the split — the text re-pin is the belt to settings.json's braces."
  exit 1
fi
green "  All present. $SKIP skipped (absent files)."
echo  "  Harm guardrails consistent across global + project + settings.json."
exit 0

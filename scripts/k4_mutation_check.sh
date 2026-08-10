#!/usr/bin/env bash
# K4 mutation evidence for src/test/genesis_all_networks_tests.cpp
#
# For each mutation: prove the edit ACTUALLY APPLIED (grep count before/after),
# rebuild, run the suite, record the verdict, then revert and prove the revert
# applied. A sed that silently stops matching looks exactly like a killed
# mutant, so the counts are the load-bearing evidence, not the exit codes.
set -u
CP=src/core/chainparams.cpp
cd /c/tmp/k4-genesis || exit 1

run_suite() {
  make genesis_all_networks_tests -j4 >/dev/null 2>&1 || { echo "  BUILD FAILED"; return 2; }
  local fails=0
  for arm in mainnet testnet dilv regtest; do
    if ! ./genesis_all_networks_tests.exe "$arm" >/tmp/k4_mut_$arm.log 2>&1; then
      fails=$((fails+1))
      echo "    arm $arm: RED"
      grep -E "FAIL:" /tmp/k4_mut_$arm.log | head -4 | sed 's/^/      /'
    else
      echo "    arm $arm: green"
    fi
  done
  return $fails
}

mutate() {
  local label="$1" line="$2" from="$3" to="$4"
  echo ""
  echo "=== MUTATION: $label  ($CP:$line  '$from' -> '$to') ==="
  local before after
  before=$(sed -n "${line}p" $CP | grep -c -- "$from")
  echo "  grep count of '$from' on line $line BEFORE mutate: $before"
  if [ "$before" -ne 1 ]; then
    echo "  ABORT: pattern not found on the expected line — mutation did NOT apply."
    return 1
  fi
  sed -i "${line}s/$from/$to/" $CP
  after=$(sed -n "${line}p" $CP | grep -c -- "$to")
  echo "  grep count of '$to' on line $line AFTER mutate:  $after   (mutation applied: $([ "$after" -eq 1 ] && echo YES || echo NO))"
  [ "$after" -eq 1 ] || { echo "  ABORT: mutation did not apply."; return 1; }
  echo "  running suite under mutation:"
  run_suite
  echo "  -> arms RED under mutation: $?"

  # revert
  sed -i "${line}s/$to/$from/" $CP
  local rev
  rev=$(sed -n "${line}p" $CP | grep -c -- "$from")
  echo "  REVERT: grep count of '$from' on line $line: $rev  (reverted: $([ "$rev" -eq 1 ] && echo YES || echo NO))"
}

SNAP=/tmp/k4_chainparams_snapshot.cpp
cp $CP "$SNAP"
echo "Snapshot of $CP taken at $SNAP (revert reference)"

echo "########## BASELINE (unmutated) ##########"
run_suite
echo "  -> arms RED at baseline: $?"

mutate "M1 testnet genesisTime drift"      251 "1774656000" "1774656001"
mutate "M2 mainnet genesisNonce drift"      28 "429612875"  "429612876"
mutate "M3 testnet vdfExclusiveHeight flip" 341 "= 0;"       "= 1;"

echo ""
echo "########## FINAL: $CP must be byte-identical to the pre-mutation snapshot ##########"
# NOTE: compared against a cp snapshot, NOT git — `git` is not on the MSYS2
# login-shell PATH, and HEAD also differs by this branch's intentional edits.
cmp -s "$SNAP" $CP && echo "CLEAN: $CP fully reverted (byte-identical)" || { echo "DIRTY: $CP NOT reverted"; diff "$SNAP" $CP; }
echo "########## FINAL re-run (must be all green) ##########"
run_suite
echo "  -> arms RED after revert: $?"

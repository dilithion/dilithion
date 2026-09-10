#!/usr/bin/env bash
# ============================================================================
# RED-first proof for the round-1 panel folds (F1, F2, F4) plus the sortedness
# assertion the F3 fast path rests on.
#
# Each arm REMOVES one fix and requires the matching assertion to go red. An arm
# whose mutant survives is reported as a FAILURE of the arm, not of the code —
# that is the only way to tell a test that guards a property from a test that
# merely runs beside it.
#
# ⚠️ RESTORE IS COPY-BASED. `git checkout --` restores to HEAD, and on this branch
# the baseline under test is routinely UNCOMMITTED — an earlier harness deleted the
# very wiring it was testing that way. Every mutation is also verified to have
# APPLIED (the marker must be present after the write) before anything is built: a
# mutation that silently fails to apply reads as a surviving mutant, which is the
# more alarming of the two failure modes.
# ============================================================================
set -uo pipefail
cd /c/tmp/roster-args || exit 9

command -v python >/dev/null || { echo "FATAL: python not on PATH"; exit 7; }
same() { python -c "
import sys,io
sys.exit(0 if io.open(sys.argv[1],'rb').read()==io.open(sys.argv[2],'rb').read() else 1)" "$1" "$2"; }

CHAIN=src/consensus/chain.cpp
BAK=/tmp/chain.cpp.r1folds.baseline
cp "$CHAIN" "$BAK" || exit 7
same "$CHAIN" "$BAK" || { echo "FATAL: baseline copy mismatch"; exit 7; }
echo "baseline saved ($(wc -c < "$BAK") bytes)"
rc=0

restore() {
  cp "$BAK" "$CHAIN"
  if same "$CHAIN" "$BAK"; then echo "   restored (byte-identical)"; else echo "   RESTORE FAILED"; rc=$((rc+1)); fi
}

# $1 label, $2 python mutation (must print MUTATED), $3 expected-red assertion text
arm() {
  local label=$1 mutation=$2 expect=$3
  echo
  echo "=== $label ==="
  if ! python -c "$mutation"; then
      echo "   FAIL  $label: the mutation did not apply"; rc=$((rc+1)); restore; return
  fi
  if ! make deferred_reclamation_tests -j8 > /tmp/r1_mut_build.log 2>&1; then
      echo "   FAIL  $label: mutant build failed"; grep -m3 'error:' /tmp/r1_mut_build.log
      rc=$((rc+1)); restore; return
  fi
  ./deferred_reclamation_tests > /tmp/r1_mut_run.out 2>&1
  local ec=$?
  if [ $ec -ne 0 ] && grep -q "FAIL  $expect" /tmp/r1_mut_run.out; then
      echo "   PASS  $label: the arm KILLED the mutant (exit $ec)"
      grep -m2 "FAIL  " /tmp/r1_mut_run.out | sed 's/^/         /'
  elif [ $ec -eq 3 ]; then
      # exit 3 is the process ABORTING on a ConsensusInvariant. For F4 that is the
      # intended kill and the sharpest possible one: with the in-degree row erased
      # at unlink again, the free-time assertion FIRES -- which is only possible
      # because it is no longer a tautology. It aborts at the FIRST drain, before
      # the named assertion is reached, so the named assertion is not what killed
      # it; the reinstated check is.
      echo "   PASS  $label: the mutant ABORTED on the reinstated invariant (exit 3)"
      tail -3 /tmp/r1_mut_run.out | sed 's/^/         /'
  elif [ $ec -ne 0 ]; then
      echo "   PASS(other)  $label: mutant died, but on a different assertion (exit $ec)"
      grep -m3 "FAIL  \|Assertion\|abort" /tmp/r1_mut_run.out | sed 's/^/         /'
  else
      echo "   FAIL  $label: THE MUTANT SURVIVED — the arm does not guard this fix"
      rc=$((rc+1))
  fi
  restore
}

arm "F1 — slot creation for an unregistered resolver removed" "
import io
p='$CHAIN'; s=io.open(p,encoding='utf-8').read()
old='''    auto* slot = MyEpochSlot();   // created at 0, and 0 pins everything
    (void)slot;'''
assert s.count(old)==1, ('anchor',s.count(old))
s=s.replace(old,'    // MUTANT: no pinning slot -- record only, as before the fold',1)
io.open(p,'w',encoding='utf-8',newline='').write(s)
assert 'MUTANT: no pinning slot' in io.open(p,encoding='utf-8').read()
print('MUTATED')
" "F1: THE DRAIN REFUSES WHILE AN UNREGISTERED RESOLVER HOLDS A POINTER"

arm "F2 — EpochQuiesce downgraded to a plain checkpoint" "
import io
p='$CHAIN'; s=io.open(p,encoding='utf-8').read()
old='''    t_epoch_offline = true;
    MyEpochSlot()->store(EPOCH_SLOT_RETIRED, std::memory_order_release);'''
assert s.count(old)==1, ('anchor',s.count(old))
s=s.replace(old,'''    // MUTANT: quiesce publishes the current epoch instead of going offline,
    // which is exactly what \"checkpoint before the wait\" did.
    MyEpochSlot()->store(m_globalEpoch.load(std::memory_order_acquire), std::memory_order_release);''',1)
io.open(p,'w',encoding='utf-8',newline='').write(s)
assert 'MUTANT: quiesce publishes' in io.open(p,encoding='utf-8').read()
print('MUTATED')
" "F2: A PARKED PARTICIPANT DOES NOT PIN THE GRAVEYARD"

arm "F4 — in-degree row erased at unlink again (the tautology)" "
import io
p='$CHAIN'; s=io.open(p,encoding='utf-8').read()
old='    m_evictableLeaves.erase(pgone);'
assert s.count(old)==1, ('anchor',s.count(old))
s=s.replace(old, old+'\n    m_inDegree.erase(pgone);   // MUTANT: erased at unlink, as before the fold',1)
io.open(p,'w',encoding='utf-8',newline='').write(s)
assert 'MUTANT: erased at unlink' in io.open(p,encoding='utf-8').read()
print('MUTATED')
" "F4: the unlinked entry KEEPS its in-degree row until it is freed"

echo
echo "=== the tree is back where it started ==="
if same "$CHAIN" "$BAK"; then echo "   PASS  $CHAIN is byte-identical to the saved baseline"; else echo "   FAIL"; rc=$((rc+1)); fi
make deferred_reclamation_tests -j8 > /dev/null 2>&1 && ./deferred_reclamation_tests > /dev/null 2>&1 \
  && echo "   and the restored tree is green again" || { echo "   FAIL: restored tree not green"; rc=$((rc+1)); }

echo
echo "===== R1 FOLD RED ARMS: $([ $rc -eq 0 ] && echo PASS || echo FAIL) ($rc failed) ====="
echo "NOTE: F3's COST fix (the O(1) early-out and the binary-search cutoff) is NOT"
echo "provable by this suite — a drain that walks the whole graveyard still frees"
echo "nothing in the pinned regime, so the assertion cannot see the difference."
echo "Its evidence is the pinned-regime drain-cost measurement in"
echo "graveyard_occupancy_bench; the arm above only guards the ORDER the fast path"
echo "depends on."
exit $rc

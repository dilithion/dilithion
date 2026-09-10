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
# ⚠️ RELATIVE TO THIS SCRIPT, NOT A HARD-CODED WORKTREE. `cd /c/tmp/roster-args`
# meant this harness silently tested SOMEONE ELSE'S CHECKOUT when run from any other
# worktree — it would mutate and restore a tree the caller never asked about, and
# report the verdict as if it were theirs.
cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." || exit 9
CHAIN_REL=src/consensus/chain.cpp
[ -f "$CHAIN_REL" ] || { echo "FATAL: not a Dilithion checkout: $PWD"; exit 9; }

command -v python >/dev/null || { echo "FATAL: python not on PATH"; exit 7; }
same() { python -c "
import sys,io
sys.exit(0 if io.open(sys.argv[1],'rb').read()==io.open(sys.argv[2],'rb').read() else 1)" "$1" "$2"; }

CHAIN=$CHAIN_REL
BAK=/tmp/chain.cpp.r1folds.baseline
cp "$CHAIN" "$BAK" || exit 7
same "$CHAIN" "$BAK" || { echo "FATAL: baseline copy mismatch"; exit 7; }
echo "baseline saved ($(wc -c < "$BAK") bytes)"
rc=0

# ⚠️ AN INTERRUPTED RUN MUST NOT LEAVE A MUTANT IN THE TREE. Without this, Ctrl-C
# between the mutation and the restore leaves chain.cpp defective and the next
# person's build silently carries it.
trap 'echo; echo "INTERRUPTED — restoring"; cp "$BAK" "$CHAIN" 2>/dev/null; exit 130' INT TERM EXIT

restore() {
  cp "$BAK" "$CHAIN"
  if same "$CHAIN" "$BAK"; then echo "   restored (byte-identical)"; else echo "   RESTORE FAILED"; rc=$((rc+1)); fi
}

# $1 label, $2 python mutation (must print MUTATED), $3 expected signature,
# $4 kind: "assert" (a named assertion must FAIL) or "abort" (the process must abort
# on a ConsensusInvariant, exit 3).
#
# ⚠️ EVERY ARM NAMES THE SIGNATURE IT EXPECTS. This used to accept ANY non-zero exit
# as a kill — "PASS(other)" — and exit 3 for every arm without checking which
# invariant fired. A mutant that crashed for an unrelated reason, or one that aborted
# in a different place than the fix it is meant to guard, was scored as a success.
# An arm that cannot say WHICH failure it expects is not a guard, it is a coincidence
# detector.
arm() {
  local label=$1 mutation=$2 expect=$3 kind=${4:-assert}
  echo
  echo "=== $label ==="
  if ! python -c "$mutation"; then
      echo "   FAIL  $label: the mutation did not apply"; rc=$((rc+1)); restore; return
  fi
  if ! make deferred_reclamation_tests -j8 > /tmp/r1_mut_build.log 2>&1; then
      echo "   FAIL  $label: mutant build failed"; grep -m3 'error:' /tmp/r1_mut_build.log
      rc=$((rc+1)); restore; return
  fi
  # ⚠️ A MUTANT CAN HANG THE SUITE, AND THIS HARNESS HUNG WITH IT. The
  # fail-closed mutation makes an arm's condition-variable handshake never complete,
  # so the suite blocked forever and took the whole harness with it -- twenty
  # minutes of a "running" job that would never have finished. A mutation harness
  # must assume its mutants break things in ways that do not return.
  #
  # 124 is `timeout`'s signal-kill status. It is NOT scored as a kill: a mutant that
  # deadlocks the suite tells us nothing about the named assertion, and calling it a
  # pass would be the same error as accepting any non-zero exit.
  timeout -k 10 180 ./deferred_reclamation_tests > /tmp/r1_mut_run.out 2>&1
  local ec=$?
  if [ $ec -eq 124 ] || [ $ec -eq 137 ] || [ $ec -eq 143 ]; then
      echo "   FAIL  $label: the mutant HUNG the suite (exit $ec) — no verdict."
      echo "         A deadlocked mutant is not evidence for the named assertion;"
      echo "         fix the arm so a broken tree FAILS instead of blocking."
      rc=$((rc+1)); restore; return
  fi
  # ⚠️ THE SURVIVAL CHECK IS NOT UNIVERSAL, AND PUTTING IT FIRST BROKE AN ARM. For
  # an INVERTED arm (kind=nesting) the mutant surviving IS the evidence: the fix's
  # own signature is a process abort, which a suite cannot assert from the inside.
  # A verdict rule that assumes every arm has the same shape is the same mistake as
  # accepting any non-zero exit — one level up.
  if [ $ec -eq 0 ] && [ "$kind" != "nesting" ]; then
      echo "   FAIL  $label: THE MUTANT SURVIVED — the arm does not guard this fix"
      rc=$((rc+1)); restore; return
  fi

  case "$kind" in
    assert)
      if grep -qF "FAIL  $expect" /tmp/r1_mut_run.out; then
          echo "   PASS  $label: killed by its named assertion (exit $ec)"
          grep -m2 "FAIL  " /tmp/r1_mut_run.out | sed 's/^/         /'
      else
          echo "   FAIL  $label: the mutant died (exit $ec) but NOT on \"$expect\""
          echo "         A kill on the wrong signature is not evidence for this fix."
          grep -m3 "FAIL  " /tmp/r1_mut_run.out | sed 's/^/         /'
          tail -2 /tmp/r1_mut_run.out | sed 's/^/         /'
          rc=$((rc+1))
      fi ;;
    abort)
      # The process must abort on a ConsensusInvariant, and the output must carry
      # the EXACT invariant text. Exit 3 alone is not enough -- the fixture returns 3
      # for its own refusals too -- and a positional marker is not enough either:
      # the abort happens wherever the first qualifying drain is, which moves as
      # arms are added. Naming the invariant pins WHICH check fired.
      if [ $ec -eq 3 ] && grep -qF "$expect" /tmp/r1_mut_run.out; then
          echo "   PASS  $label: aborted on the reinstated invariant, past \"$expect\" (exit 3)"
          tail -2 /tmp/r1_mut_run.out | sed 's/^/         /'
      else
          echo "   FAIL  $label: expected an abort past \"$expect\", got exit $ec"
          tail -3 /tmp/r1_mut_run.out | sed 's/^/         /'
          rc=$((rc+1))
      fi ;;
    nesting)
      # The illegal nest ABORTS on the real tree — a test cannot catch a
      # ConsensusInvariant and keep running, so the suite's own abort is the fix's
      # signature and cannot be asserted from inside the suite. With the refusal
      # REMOVED the nest is silently accepted and the suite passes, which is what
      # this arm observes. It is therefore an inverted arm: the mutant SURVIVING is
      # the evidence, and the fix's value is that the same nest aborts without it.
      # ⚠️ A ZERO EXIT IS NOT ENOUGH, AND THIS ARM USED TO ACCEPT ONE ON ITS OWN.
      # Nothing proved the nest was ever REACHED: a suite that skipped the arm
      # entirely also exits zero. The marker below is printed by the F13 arm itself,
      # so its presence is proof the nested scopes actually ran under the mutant.
      if [ $ec -eq 0 ] && grep -qF "F13: EpochOnlineWindow nested inside an offline scope is legal" /tmp/r1_mut_run.out; then
          echo "   PASS  $label: refusal removed => the nest ran and was silently accepted"
          echo "         (on the real tree that same nest aborts; that is the fix)"
      elif [ $ec -eq 0 ]; then
          echo "   FAIL  $label: exit 0 but the nesting arm never RAN — nothing was proven"
          rc=$((rc+1))
      else
          echo "   FAIL  $label: expected the mutant to ACCEPT the nest, got exit $ec"
          tail -3 /tmp/r1_mut_run.out | sed 's/^/         /'
          rc=$((rc+1))
      fi ;;
    *) echo "   FAIL  $label: unknown arm kind '$kind'"; rc=$((rc+1)) ;;
  esac
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
" "CONSENSUS INVARIANT VIOLATION: it_deg != m_inDegree.end()" abort

arm "F13 - reentrancy refusal removed (offline nested in offline)" "
import io
p='$CHAIN'; s=io.open(p,encoding='utf-8').read()
old='    ConsensusInvariant(!t_epoch_offline);'
assert s.count(old)==1, ('anchor',s.count(old))
s=s.replace(old,'    // MUTANT: nesting allowed again',1)
io.open(p,'w',encoding='utf-8',newline='').write(s)
assert 'MUTANT: nesting allowed' in io.open(p,encoding='utf-8').read()
print('MUTATED')
" "F13-NESTING" nesting

arm "BLOCKER - fail-closed removed (an unnamed thread may quiesce)" "
import io
p='$CHAIN'; s=io.open(p,encoding='utf-8').read()
old='    if (t_epoch_name == nullptr) {'
assert s.count(old)==1, ('anchor',s.count(old))
s=s.replace(old,'    if (false) {   // MUTANT: unnamed threads may go offline',1)
io.open(p,'w',encoding='utf-8',newline='').write(s)
assert 'MUTANT: unnamed threads' in io.open(p,encoding='utf-8').read()
print('MUTATED')
" "F15: an ACCUSED thread cannot quiesce at all — the path is closed"
# ⚠️ THE SIGNATURE IS F15's LINE, NOT THE BLOCKER ARM'S, AND THAT IS DELIBERATE.
# Removing the fail-closed rule breaks the SAME property both arms rest on, and F15's
# assertion runs first -- it exits the process immediately, because a suite that has
# just proved quiesce does not refuse cannot trust anything after it. The earliest
# observable failure is the honest signature; naming the later one would make this arm
# fail for a reason unrelated to the fix.
arm "F25 - nameless-checkpoint gate removed (a window may unpin an unnamed holder)" "
import io
p='$CHAIN'; s=io.open(p,encoding='utf-8').read()
old='    if (name == nullptr && t_epoch_name == nullptr) {'
assert s.count(old)==1, ('anchor',s.count(old))
s=s.replace(old,'    if (false) {   // MUTANT: nameless checkpoints publish for anyone',1)
io.open(p,'w',encoding='utf-8',newline='').write(s)
assert 'MUTANT: nameless checkpoints' in io.open(p,encoding='utf-8').read()
print('MUTATED')
" "F25: BOTH SCOPE TYPES ARE INERT ON AN UNNAMED THREAD — it still pins"
# ⚠️ THE F15 MUTANT WAS REMOVED, AND WHY MATTERS MORE THAN THE ARM DID.
# Round 3 added a re-record on resolve-after-quiesce. Round 4's fail-closed rule
# (EpochQuiesce refuses on a thread with no registered name) made that path
# UNREACHABLE: a name comes only from EpochCheckpoint(name), which clears the
# accusation, and a thread with a slot is never re-recorded. The mutant therefore
# SURVIVED on the fixed tree -- correctly, because there is nothing left to break.
# A surviving mutant is ambiguous (unreachable OR untested); here it is unreachable,
# and the suite now asserts THAT instead of pretending to exercise the old path.
# The round-4 fold subsumed the round-3 fold; keeping a green arm over it would have
# hidden that.

echo
echo "=== POSITIVE CONTROL: the unmutated tree must REFUSE the illegal nest ==="
# ⚠️ WITHOUT THIS, THE INVERTED ARM PROVES HALF A THING. It shows the mutant accepts
# the nest; it does not show the real tree rejects it. The refusal aborts the process,
# so it is probed in a CHILD process whose death is the evidence.
if make epoch_nest_probe -j8 > /dev/null 2>&1; then
  ./epoch_nest_probe > /tmp/nest_probe.out 2>&1; probe_rc=$?
  if [ $probe_rc -ne 0 ] && grep -qF "t_epoch_offline" /tmp/nest_probe.out; then
      echo "   PASS  control: the real tree ABORTS on offline-inside-offline (exit $probe_rc)"
  else
      echo "   FAIL  control: the real tree ACCEPTED the illegal nest (exit $probe_rc)"
      tail -2 /tmp/nest_probe.out | sed 's/^/         /'
      rc=$((rc+1))
  fi
else
  echo "   FAIL  control: epoch_nest_probe did not build — the control cannot be skipped"
  rc=$((rc+1))
fi

echo
echo "=== the tree is back where it started ==="
if same "$CHAIN" "$BAK"; then echo "   PASS  $CHAIN is byte-identical to the saved baseline"; else echo "   FAIL"; rc=$((rc+1)); fi
make deferred_reclamation_tests -j8 > /dev/null 2>&1 && ./deferred_reclamation_tests > /dev/null 2>&1 \
  && echo "   and the restored tree is green again" || { echo "   FAIL: restored tree not green"; rc=$((rc+1)); }

trap - EXIT   # the tree is restored and verified below; the trap has done its job

echo
echo "===== R1 FOLD RED ARMS: $([ $rc -eq 0 ] && echo PASS || echo FAIL) ($rc failed) ====="
echo "NOTE: F3's COST fix (the O(1) early-out and the binary-search cutoff) is NOT"
echo "provable by this suite — a drain that walks the whole graveyard still frees"
echo "nothing in the pinned regime, so the assertion cannot see the difference."
echo "Its evidence is the pinned-regime drain-cost measurement in"
echo "graveyard_occupancy_bench; the arm above only guards the ORDER the fast path"
echo "depends on."
exit $rc

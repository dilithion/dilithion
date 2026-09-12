#!/bin/bash
# RED arms for the deferred-reclamation startup census, against the REAL node binary.
#
# ⚠️ RESTORE IS COPY-BASED, NOT `git checkout --`. The first version of this harness
# restored from HEAD while the baseline was UNCOMMITTED, and so deleted the very wiring
# it was testing. And its "restoration verified" line was VACUOUS: git is not on PATH in
# the MSYS login shell, the command failed, empty output compared equal, PASS printed.
# Every check below fails closed if its instrument is missing.
set -u
cd /c/tmp/roster-args || exit 9

# `cmp` is not on PATH in the MSYS login shell; python is, and it fails closed.
same() { python -c "
import sys,io
a=io.open(sys.argv[1],'rb').read(); b=io.open(sys.argv[2],'rb').read()
sys.exit(0 if a==b else 1)" "$1" "$2"; }
command -v python >/dev/null || { echo "FATAL: python not on PATH"; exit 7; }

DATADIR_ENV=C:/msys64/tmp/dilnode-census
NODE_ARGS="--testnet --relay-only --generate-seed-key --allow-plaintext-seed-key --port=18999 --rpcport=18998 --connect=127.0.0.1:1 --verbose"
CS=src/api/cached_stats.cpp
BAK=/tmp/cached_stats.baseline.cpp
rc=0

cp "$CS" "$BAK" || { echo "FATAL: could not save the baseline"; exit 7; }
same "$CS" "$BAK" || { echo "FATAL: baseline copy does not match the source"; exit 7; }
echo "baseline saved: $BAK ($(wc -c < "$BAK") bytes)"

restore() {
  cp "$BAK" "$CS"
  if same "$CS" "$BAK"; then echo "  restored (byte-identical to the saved baseline)";
  else echo "  RESTORE FAILED"; rc=$((rc+1)); fi
}

boot() {
  DILITHION_DATADIR=$DATADIR_ENV timeout -k 15 90 ./dilithion-node.exe $NODE_ARGS > "$1" 2>&1
  echo $?
}

echo
echo "=== CONTROL (unmutated): the census must PASS ==="
make dilithion-node -j8 > /dev/null 2>&1 || { echo "BUILD FAILED"; exit 8; }
ec=$(boot red_control.log)
if grep -q "declared epoch participants have checkpointed" red_control.log; then
  echo "  PASS  control: $(grep -o 'all [0-9]* declared epoch participants have checkpointed' red_control.log | head -1) (exit $ec; 124 = still running when the timeout killed it)"
else
  echo "  FAIL  control: census line absent"; rc=$((rc+1))
fi

echo
echo "=== RED-A: delete the cached-stats CHECKPOINT, keep the declaration ==="
python -c "
import io
p='$CS'
s=io.open(p,encoding='utf-8').read()
old='        g_chainstate.EpochCheckpoint(\"cached-stats\");'
assert s.count(old)==1, ('checkpoint anchor', s.count(old))
io.open(p,'w',encoding='utf-8',newline='').write(s.replace(old,'        // MUTANT: checkpoint removed',1))
print('  mutated: checkpoint removed')
" || { echo "  FAIL  RED-A: mutation did not apply"; rc=$((rc+1)); }
make dilithion-node -j8 > /dev/null 2>&1 || { echo "  FAIL  RED-A: build failed"; rc=$((rc+1)); }
ec=$(boot red_a.log)
if grep -q "REFUSING TO START" red_a.log && grep -q "cached-stats" red_a.log; then
  echo "  PASS  RED-A: refused to start, NAMED cached-stats (exit $ec)"
else
  echo "  FAIL  RED-A: no refusal or no name (exit $ec)"; rc=$((rc+1))
fi
restore

echo
echo "=== RED-B: delete BOTH the declaration and the checkpoint (the ninth thread) ==="
python -c "
import io
p='$CS'
s=io.open(p,encoding='utf-8').read()
a='        g_chainstate.EpochCheckpoint(\"cached-stats\");'
b='    g_chainstate.DeclareEpochParticipant(\"cached-stats\");'
assert s.count(a)==1 and s.count(b)==1, ('anchors', s.count(a), s.count(b))
s=s.replace(a,'        // MUTANT: checkpoint removed',1).replace(b,'    // MUTANT: declaration removed',1)
io.open(p,'w',encoding='utf-8',newline='').write(s)
print('  mutated: declaration AND checkpoint removed -- this thread is on no list at all')
" || { echo "  FAIL  RED-B: mutation did not apply"; rc=$((rc+1)); }
make dilithion-node -j8 > /dev/null 2>&1 || { echo "  FAIL  RED-B: build failed"; rc=$((rc+1)); }
ec=$(boot red_b.log)
# The DISCRIMINATING check: it must be caught by the list-free detector, and the
# declared-set arm must be silent -- otherwise this is just RED-A again.
if grep -q "REFUSING TO START" red_b.log && grep -q "obtained a CBlockIndex" red_b.log; then
  if grep -q "declared thread(s) have never checkpointed" red_b.log; then
    echo "  FAIL  RED-B: caught by the DECLARED-set arm -- the mutation did not remove the declaration"
    rc=$((rc+1))
  else
    echo "  PASS  RED-B: caught by the LIST-FREE detector alone (exit $ec)"
    grep -o "REFUSING TO START.*" red_b.log | head -1 | cut -c1-200
  fi
else
  echo "  FAIL  RED-B: an undeclared, uncheckpointed resolver booted the node (exit $ec)"; rc=$((rc+1))
fi
restore

echo
echo "=== the tree is back where it started ==="
if same "$CS" "$BAK"; then echo "  PASS  $CS is byte-identical to the saved baseline"; else echo "  FAIL  $CS differs"; rc=$((rc+1)); fi
make dilithion-node -j8 > /dev/null 2>&1 && echo "  node rebuilt clean from the restored tree"

echo
echo "===== RED ARMS: $([ $rc -eq 0 ] && echo PASS || echo FAIL) ($rc failed) ====="
exit $rc

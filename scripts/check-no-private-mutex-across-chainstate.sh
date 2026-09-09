#!/bin/bash
# P2P-17 guard: no private mutex may be held across a call into the chainstate.
#
# WHY. Every chainstate accessor here takes cs_main. Holding a class's own mutex
# across one of those calls creates a <private mutex> -> cs_main edge. Paired
# with the cs_main -> <private mutex> edge that block connect/disconnect
# callbacks create (they fire with cs_main HELD — see chain.cpp's DisconnectTip
# comment), that is an AB-BA deadlock between the reorg thread and whichever
# thread takes the private mutex first.
#
# That is not hypothetical: register P2P-17 is exactly this, in
# CCoinStatsIndex::WriteBlock, reachable from its own sync thread.
#
# The failure is invisible to tests — it needs two threads inside two windows —
# and the repair is a one-line lock-discipline change that is easy to drop in a
# later edit. So it gets a structural check.
#
# SCOPE, stated so nobody mistakes this for more than it is: this detects a LOCK
# HELD ACROSS A CALL. It does NOT detect the released-pointer/lifetime class
# (P2P-16), where the accessor is called with no lock held and the returned
# pointer is dereferenced later. Those are different defects and need different
# instruments — check-headers-manager-no-chainstate-pointer.sh covers the other
# one. Verified by running this audit against the PRE-P2P-16 head: it reports
# CLEAN for GetLocator, because that call site held nothing at call time.
#
# Exit 0 = no private mutex held across a chainstate call. Exit 1 = at least one.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

PY=$(command -v python3 || command -v python) || {
    echo "SKIP: no python interpreter found; cannot run the lock-scope audit"
    exit 0
}

# The files audited. Anything that both takes its own mutex and reaches the
# chainstate belongs here. Listed explicitly rather than globbed so that adding
# a new such file is a deliberate, reviewed act.
FILES="src/index/coinstatsindex.cpp src/index/tx_index.cpp"

out=$("$PY" scripts/lock_scope_audit.py $FILES 2>&1) || {
    echo "FAIL: the lock-scope audit did not run:"; echo "$out"; exit 1
}

if printf '%s' "$out" | grep -q '^\*\*\*'; then
    echo "FAIL: a private mutex is held across a call into the chainstate."
    echo "      Every chainstate accessor takes cs_main, so this is one half of"
    echo "      an AB-BA with the cs_main -> <private mutex> edge that block"
    echo "      connect/disconnect callbacks create. See register P2P-17."
    echo "      Fix: use unique_lock and unlock() across the chainstate call, as"
    echo "      CCoinStatsIndex::Init and tx_index.cpp:520 already do."
    echo "$out"
    exit 1
fi

echo "PASS: no private mutex held across a chainstate call"
printf '%s\n' "$out" | sed 's/^/  /'
exit 0

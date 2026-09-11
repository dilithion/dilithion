#!/bin/bash
# P2P-17 guard: no UNCLASSIFIED private mutex held across a call into the chainstate.
#
# WHY. A CChainState accessor that takes cs_main, called while a class holds its
# own mutex, creates a <private mutex> -> cs_main edge. Block connect/disconnect
# callbacks create the opposite edge (they fire with cs_main HELD), so the pair
# is an AB-BA between the reorg thread and whichever thread takes the private
# mutex first. Register P2P-17 is exactly that (LATENT there, gate-excluded; the
# fix made it structurally impossible, and this keeps it so).
#
# SCOPE IS MUTEX-BASED, NOT ENTRY-POINT-BASED. Auditing the four REGISTERED
# disconnect callbacks returns four green ticks; the inversion was a SIBLING
# METHOD on one of those same classes, on another thread, in no callback list.
# The mutex defines the population, so this sweeps per-file lock scope over every
# non-test .cpp and consults no registry.
#
# It does NOT detect the released-pointer/lifetime class (P2P-16) — different
# defect, different instrument (check-headers-manager-no-chainstate-pointer.sh).
#
# The classification lives in scripts/lock_scope_audit.py as a (file, function,
# call, mutex) -> exact-count map, WITH the safety argument per entry. This
# wrapper only runs it: a missing interpreter FAILS rather than skips, because a
# check that cannot run must not report success.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

PY=$(command -v python3 || command -v python) || {
    echo "FAIL: no python interpreter found, so the lock-scope audit COULD NOT RUN."
    exit 1
}

# The auditor's own FIXTURES run first. Its two regexes were each too narrow and
# neither narrowness showed in its output: widening the receiver changed no
# verdict on this tree (none of the 86 non-global accessor calls sits under a
# private mutex), so "finds nothing new" and "finds nothing" were
# indistinguishable until something proved it CAN find. The fixtures are that
# proof - one per receiver form, one per lock form, plus negative controls - and
# they run BEFORE the audit so a broken matcher cannot report a clean tree.
if ! fixt=$("$PY" scripts/lock_scope_audit_selftest.py 2>&1); then
    echo "FAIL: the lock-scope auditor's own fixtures do not pass, so its verdict"
    echo "      on this tree means nothing. Fix the auditor before trusting it."
    printf '%s\n' "$fixt"
    exit 1
fi

out=$("$PY" scripts/lock_scope_audit.py . 2>&1); rc=$?
if [ "$rc" -eq 0 ]; then
    echo "PASS: no unclassified private mutex held across a chainstate call"
    # D-4: the receiver split is the line that shows COVERAGE, and this filter was
    # dropping it - so a CI log showed a green tick but not the number saying how
    # much the auditor can actually see. Print it through.
    printf '%s\n' "$out" | grep -E 'accessors generated|files scanned|accessor CALLS|non-global receivers|^OK:' | sed 's/^/  /'
    exit 0
fi
echo "FAIL: the lock-scope audit reported an unclassified or extra site (rc=$rc)."
printf '%s\n' "$out"
exit 1

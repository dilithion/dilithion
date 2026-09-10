#!/usr/bin/env bash
# ============================================================================
# check_roster_completeness.sh — every Makefile test target must be named by a
# roster row, or the roster is not a register of what exists.
#
# WHY THIS EXISTS, and why it is a SCRIPT and not another careful look.
#
# Three hand counts of the same question produced three different answers in
# two days:
#
#   LP10's audit        24 orphaned targets
#   my census           18
#   a8's fresh read     16 registered + 9 still missing
#
# Nobody was careless. Each method drew a slightly different boundary — one
# compared against `--list all` (which drops NOBUILD rows and so MANUFACTURES
# orphans), one matched a narrower Makefile pattern, one included targets whose
# sources no longer exist. A fourth hand count would have produced a fourth
# number.
#
# So the census stops being an activity and becomes an invariant: this script
# fails the build if any test target is unrostered, and it is wired into the
# roster self-tests. The roster cannot silently drift again, and nobody has to
# be careful.
#
# WHAT COUNTS AS A TEST TARGET: a Makefile rule whose recipe links an object
# under $(OBJ_DIR)/test/. That is the mechanical definition; if a target builds
# a test object it is a test and belongs in the register. Tools (src/tools/) do
# not match, which is why genesis_gen is correctly absent.
#
# EXEMPTIONS ARE EXPLICIT AND MUST CARRY A REASON. There are exactly THREE kinds:
#
#   1. a paired CONTROL whose whole job is to fail (batch_verifier_race_control);
#   2. a target whose source no longer exists, or does not exist YET;
#   3. a SANITIZER-ONLY harness, whose observable is the sanitizer's report rather
#      than the exit code — p2p14_lock_inversion_tsan_tests,
#      headerssync_disconnect_race_tsan, blockindex_uaf_asan_arm. Rostering one of
#      these builds it WITHOUT the sanitizer, where it exits 0 having detected
#      nothing, so the roster would print a green for a binary that cannot fail.
#      A row of this kind MUST name the CI job and step that actually runs it.
#
# ⚠️ This header said "exactly two kinds" for as long as kind 3 has existed: the
# two TSan rows landed under it and the sentence was never updated, so the next
# reader would have read a correct row as a violation of the file's own rule. A fix
# aimed at a site leaves siblings; when a fourth kind appears, this paragraph is
# part of the change.
#
# All are listed below with the reason inline. An exemption without a reason is a
# hole with a nicer name.
# ============================================================================
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." || exit 2

RUNNER=scripts/run_test_suites.sh
[ -f Makefile ] || { echo "no Makefile here"; exit 2; }
[ -f "$RUNNER" ] || { echo "no $RUNNER here"; exit 2; }

# ---------------------------------------------------------------------------
# EXEMPT, each with the reason it is exempt. Keep this list short and argued.
# ---------------------------------------------------------------------------
exempt_reason() {
    case "$1" in
        batch_verifier_race_control)
            echo "A-010 paired CONTROL: the Makefile states it deterministically HANGS, proving the harness discriminates. Rostering it would file a working control as a defect." ;;
        genesis_gen)
            echo "A TOOL that generates a genesis block, not a gated test. It builds from src/test/genesis_test.cpp, which is why a source-based scan sees it at all." ;;
        wallet_load_guard_test)
            echo "SCRIPT-DRIVEN and already run by CI -- not a compiled binary, so it has no source of its own. NOTE THE NAME: wallet_load_guard_testS (plural) is a different, compiled, rostered suite. Seeing the plural in the roster and ticking off the singular has already cost a reviewer a step." ;;
        dna_detection_test|dna_serialization_test)
            echo "Target lands ahead of its source: both are in flight in PR #116. Dead on THIS branch, alive when that merges -- exempt rather than deleted, and this line should be removed when #116 lands." ;;
        p2p14_lock_inversion_tsan_tests)
            echo "TSan-only by construction: it exists to make a lock-order inversion observable and is run via scripts/run_p2p14_lock_inversion_tsan.sh, not the roster. A non-TSan build of it proves nothing." ;;
        headerssync_disconnect_race_tsan)
            echo "TSan-only by construction, same class as p2p14_lock_inversion_tsan_tests: it drives ProcessHeadersWithDoSProtection against OnPeerDisconnected to make a use-after-free observable, and the OBSERVABLE IS THE SANITISER REPORT, not the exit code. Built and run by hand: 'make TSAN=1 headerssync_disconnect_race_tsan', then 'setarch \$(uname -m) -R ./headerssync_disconnect_race_tsan' (TSan aborts with a FATAL mapping error unless ASLR is off). A non-TSan build exits 0 while proving nothing, so rostering it would manufacture a green. Its own reachability guard exits 3 if neither edge was driven, so an unrun harness cannot read as a pass. RED/GREEN evidence: dilithion-strategy/missions/lp10-headerssync-wiring/EVIDENCE_A9_tsan_{red,green}.txt." ;;
        blockindex_uaf_asan_arm)
            echo "KIND 3, sanitizer-only, and with the sharpest form of that tell: TWO OF ITS THREE ARMS MUST CRASH. Rostering it live would build it WITHOUT -fsanitize=address, where both trap arms read stale bytes and exit 0 -- the roster would print a green for a binary that cannot detect anything. WHERE IT ACTUALLY RUNS, named so this is not 'run elsewhere' with no elsewhere: .github/workflows/ci.yml, job 'AddressSanitizer (Memory Safety)', step 'Deferred-reclamation ASan arms (2 of 3 MUST trap)', on every PR. Driver: scripts/asan_uaf_arms.sh, which refuses to report a verdict without the sanitizer and, with REQUIRE_ASAN=1 as that step sets it, HARD-FAILS instead of skipping. Verdict at 42a287cd (run 34426922897, job step 'Deferred-reclamation ASan arms (2 of 3 MUST trap)': success; the literal arm lines were captured at 4ae2798c, run 34424068632 job 102705495467): deferred exit 0 clean; immediate exit 1 heap-use-after-free; drained exit 1 heap-use-after-free; 'ASan arms: PASS (0 failed)'. Reproduce: CXX=clang++ CXXFLAGS='-fsanitize=address -fno-omit-frame-pointer -g -std=c++17' LDFLAGS=-fsanitize=address make blockindex_uaf_asan_arm && REQUIRE_ASAN=1 bash scripts/asan_uaf_arms.sh" ;;
        *) echo "" ;;
    esac
}

# A test target is one whose NAME ends in _test/_tests, OR whose rule links an
# object under $(OBJ_DIR)/test/.
#
# THE FIRST CLAUSE IS THE ONE THE EARLIER CENSUS MISSED, and it is the entire
# difference between "18 orphans" and "27": dna_p2p_test, dna_history_test,
# verification_test, vdf_test and vdf_miner_test link objects under
# digital_dna/, vdf/ and miner/, so a pattern keyed on $(OBJ_DIR)/test/ never
# saw them. Two clauses, because one boundary was never enough.
{
  grep -E '^[a-zA-Z_0-9]+_tests?:' Makefile | sed 's/:.*//'
  grep -E '^[a-zA-Z_0-9]+:.*\$\(OBJ_DIR\)/test/' Makefile | sed 's/:.*//'
} | sort -u > /tmp/_rc_targets

# Every suite named by a roster row, NOBUILD rows included -- the roster is the
# register, and --list deliberately drops NOBUILD, so comparing against --list
# manufactures orphans. That mistake produced one of the three counts above.
sed -n '/^ROSTER=/,/^.$/p' "$RUNNER" | grep -E '^(fast|full)\|' | cut -d'|' -f2 | sort -u > /tmp/_rc_rostered

missing=0
dead=0
echo "roster completeness:"
echo "  makefile test targets : $(wc -l < /tmp/_rc_targets)"
echo "  rostered              : $(wc -l < /tmp/_rc_rostered)"
echo

while read -r t; do
    [ -z "$t" ] && continue
    grep -qx "$t" /tmp/_rc_rostered && continue
    reason="$(exempt_reason "$t")"
    if [ -n "$reason" ]; then
        printf '  EXEMPT   %-44s %s\n' "$t" "$reason"
        continue
    fi
    # Does its source still exist? A target for a deleted source is dead, and
    # saying so is more useful than calling it unrostered.
    # Look across the WHOLE src/ tree, not just src/test/. The targets that
    # broke the earlier census live under digital_dna/, vdf/ and miner/, and a
    # src/test/-only lookup reports them as DEAD -- a false alarm that is just
    # as damaging as a miss, because it invites deleting a live target.
    src=""
    for c in "src/test/${t}.cpp" "src/test/${t%_test}_test.cpp" "src/test/${t%_tests}_tests.cpp"; do
        [ -f "$c" ] && src="$c" && break
    done
    if [ -z "$src" ]; then
        src="$(find src -name "${t}.cpp" -print -quit 2>/dev/null)"
    fi
    if [ -z "$src" ]; then
        obj=$(grep -E "^${t}:" Makefile | head -1 | grep -oE '\$\(OBJ_DIR\)/test/[a-zA-Z_0-9]+\.o' | head -1 | sed 's#.*/##; s#\.o$#.cpp#')
        [ -n "$obj" ] && [ -f "src/test/$obj" ] && src="src/test/$obj"
    fi
    if [ -z "$src" ]; then
        printf '  DEAD     %-44s no source file -- the target builds nothing\n' "$t"
        dead=$((dead + 1))
    else
        printf '  UNROSTERED %-42s (%s)\n' "$t" "$src"
        missing=$((missing + 1))
    fi
done < /tmp/_rc_targets

echo
if [ "$missing" -eq 0 ] && [ "$dead" -eq 0 ]; then
    echo "  OK: every test target is rostered or explicitly exempt."
    exit 0
fi
echo "  FAIL: $missing unrostered, $dead dead."
echo "  A test target nothing names is a test nothing runs. Add a roster row --"
echo "  live if it passes, QUARANTINE with a written reason if it does not."
exit 1

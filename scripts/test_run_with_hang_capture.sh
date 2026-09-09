#!/usr/bin/env bash
# Self-test for run_with_hang_capture.sh.
#
# WHY IT EXISTS. The watchdog it tests used to be inline YAML in ci.yml, so
# nothing had ever executed it outside a real CI hang -- an event that fires
# about 8% of the time. Every property below was therefore an assumption:
#
#   * that a hang FAILS the step (if it did not, the instrument would record
#     the hang and let it merge, and the artifact would be read by nobody);
#   * that a healthy run is untouched and produces no artifact;
#   * that a genuine test FAILURE propagates its own status rather than being
#     laundered into a hang;
#   * that the PID-reuse guard does not fire on an unrelated process.
#
# The arm that carries the most information is the third one: "hang" and "fail"
# must stay distinguishable, because the whole reason #180 existed is that they
# had been conflated.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
RUNNER="${1:-$HERE/run_with_hang_capture.sh}"
P=0; F=0
chk(){ if [ "$2" = "$3" ]; then echo "   PASS  $1"; P=$((P+1)); else echo "   FAIL  $1 got=$2 want=$3"; F=$((F+1)); fi; }

[ -f "$RUNNER" ] || { echo "FAIL: runner not found at $RUNNER" >&2; exit 1; }

# PLATFORM GATE. The watchdog needs /proc/<pid>/comm; MSYS2/Git Bash has none,
# so run_with_hang_capture.sh correctly refuses to arm and runs the command
# UNWATCHED. That makes the hang arms below not merely fail but BLOCK -- their
# fixture sleeps 300s with nothing to kill it, three times over, and
# `make tests-fast` on Windows would hang for a quarter of an hour before going
# red. Skip them with a printed reason instead: a SKIP that says why is honest,
# a hang that eventually fails is not.
HAVE_PROC=0
if [ -r "/proc/$$/comm" ]; then HAVE_PROC=1; fi

mk() {   # mk <name> <body>
    local d="$1" name="$2" body="$3"
    printf '%s' "$body" > "$d/$name"
    chmod +x "$d/$name"
}

echo "== a HEALTHY run is untouched and leaves no artifact =="
d="$(mktemp -d)"
mk "$d" quickpass '#!/usr/bin/env bash
exit 0
'
bash "$RUNNER" 5 "$d/art" "$d/quickpass" >/dev/null 2>&1
chk "a passing command exits 0" "$?" "0"
chk "and produces no hang artifact" "$(ls "$d/art" 2>/dev/null | wc -l)" "0"
rm -rf "$d"

echo
echo "== a genuine FAILURE keeps its own exit code and is not called a hang =="
# #180 exists because a hang was being reported as a test failure. The reverse
# would be just as bad, and this instrument sits directly on that boundary.
d="$(mktemp -d)"
mk "$d" quickfail '#!/usr/bin/env bash
exit 3
'
bash "$RUNNER" 5 "$d/art" "$d/quickfail" >/dev/null 2>&1
chk "a failing command propagates its exit code verbatim" "$?" "3"
chk "and is NOT recorded as a hang" "$(ls "$d/art" 2>/dev/null | wc -l)" "0"
rm -rf "$d"

echo
echo "== A HANG MUST FAIL THE STEP -- the property the whole instrument rests on =="
if [ "$HAVE_PROC" -eq 0 ]; then
  echo "   SKIP  no /proc on this platform -- the watchdog cannot arm here, so these arms would block, not test"
else
d="$(mktemp -d)"
mk "$d" hangs '#!/usr/bin/env bash
sleep 300
'
start=$(date +%s)
bash "$RUNNER" 3 "$d/art" "$d/hangs" >/dev/null 2>&1
rc=$?
elapsed=$(( $(date +%s) - start ))
if [ "$rc" -eq 0 ]; then
    echo "   FAIL  A HANG WAS GREEN. The instrument would record the hang and let it merge."
    F=$((F+1))
else
    chk "a hang exits non-zero (got $rc)" "yes" "yes"
fi
chk "it was killed near the budget, not left to run" "$([ "$elapsed" -lt 60 ] && echo yes || echo no)" "yes"
art="$d/art/hangs_hang_stack.txt"
chk "a stack artifact was written" "$([ -s "$art" ] && echo yes || echo no)" "yes"
if [ -s "$art" ]; then
    grep -q 'per-thread wchan' "$art" && chk "the artifact carries per-thread wait channels" yes yes \
        || { echo "   FAIL  artifact missing the wchan section"; F=$((F+1)); }
    grep -q 'hang, captured' "$art" && chk "and says what it is and when" yes yes \
        || { echo "   FAIL  artifact missing its header"; F=$((F+1)); }
fi
rm -rf "$d"
fi

echo
echo "== an INCOMPLETE capture must say so, not look like a capture =="
if [ "$HAVE_PROC" -eq 0 ]; then
  echo "   SKIP  no /proc on this platform -- the watchdog cannot arm here, so these arms would block, not test"
else
# LOW-3. An artifact that exists is not the same as evidence obtained: a gdb
# that cannot attach (ptrace_scope, not installed, a 180s stall) previously left
# a file that looked like a successful capture and merely contained an error
# string. It is read weeks later by someone who was not here.
d="$(mktemp -d)"
mk "$d" hangs2 '#!/usr/bin/env bash
sleep 300
'
mkdir -p "$d/fakebin"
printf '#!/usr/bin/env bash\nexit 7\n' > "$d/fakebin/gdb"   # gdb that cannot attach
chmod +x "$d/fakebin/gdb"
PATH="$d/fakebin:$PATH" bash "$RUNNER" 3 "$d/art" "$d/hangs2" >/dev/null 2>&1
rc=$?
art="$d/art/hangs2_hang_stack.txt"
chk "the hang still fails the step even when gdb cannot attach" \
    "$([ "$rc" -ne 0 ] && echo yes || echo no)" "yes"
chk "an artifact is still written (the wchan table is real evidence)" \
    "$([ -s "$art" ] && echo yes || echo no)" "yes"
if [ -s "$art" ]; then
    grep -q 'CAPTURE INCOMPLETE' "$art" \
        && chk "and it SAYS the capture is incomplete" yes yes \
        || { echo "   FAIL  a failed gdb attach reads as a successful capture"; F=$((F+1)); }
fi
rm -rf "$d"
fi

echo
echo "== the watchdog must not outlive the command (a stray sleep holds the step open) =="
if [ "$HAVE_PROC" -eq 0 ]; then
  echo "   SKIP  no /proc on this platform -- the watchdog cannot arm here, so these arms would block, not test"
else
d="$(mktemp -d)"
mk "$d" quick2 '#!/usr/bin/env bash
exit 0
'
# Count OUR watchdog's sleep specifically, by its exact argument. A bare
# `pgrep -c sleep` counts every sleep on the machine -- including this test's own
# -- so it reported a leak that was not there. Measuring the wrong population is
# how a green arm becomes noise and a red one becomes a wild goose chase.
#
# (`pgrep -c` also PRINTS 0 and EXITS 1 when nothing matches, so `|| echo 0`
# appends a second zero and the comparison gets "0\n0" -- an integer-expression
# error rather than a result. Same shape as the grep -c trap earlier tonight.)
BUDGET_MARK=1717
bash "$RUNNER" "$BUDGET_MARK" "$d/art" "$d/quick2" >/dev/null 2>&1
sleep 1
leaked=$(pgrep -fc "sleep $BUDGET_MARK" 2>/dev/null); leaked=${leaked:-0}
chk "no watchdog sleep is left behind after a fast command" "$leaked" "0"
rm -rf "$d"
fi

echo
echo "== the BUDGET arithmetic (ci_hang_budget.sh), which was also untestable inline =="
B="$HERE/ci_hang_budget.sh"
if [ -f "$B" ]; then
  # Plenty of ceiling left -> capped at MAX_BUDGET, not at the ceiling.
  out=$(JOB_CEILING_MIN=45 JOB_START_EPOCH=$(date +%s) bash "$B" 2>/dev/null)
  chk "a fresh job is capped at MAX_BUDGET (600), not the ceiling" "$out" "600"
  # Ceiling nearly spent -> NOT ARMED warning and the floor.
  out=$(JOB_CEILING_MIN=45 JOB_START_EPOCH=$(( $(date +%s) - 2600 )) bash "$B" 2>/dev/null)
  chk "a nearly-spent job falls back to MIN_BUDGET (300)" "$out" "300"
  err=$(JOB_CEILING_MIN=45 JOB_START_EPOCH=$(( $(date +%s) - 2600 )) bash "$B" 2>&1 >/dev/null)
  case "$err" in
    *"NOT ARMED"*) chk "and it SAYS the instrument is not armed" yes yes ;;
    *) echo "   FAIL  a spent budget armed silently -- a missing artifact would read as no-hang"; F=$((F+1)) ;;
  esac
  # No clock at all -> must not silently arm against a wrong elapsed time.
  err=$(JOB_CEILING_MIN=45 bash "$B" 2>&1 >/dev/null)
  case "$err" in
    *"JOB_START_EPOCH not set"*) chk "a missing job clock is called out, not assumed" yes yes ;;
    *) echo "   FAIL  a missing JOB_START_EPOCH was silently tolerated"; F=$((F+1)) ;;
  esac
else
  echo "   SKIP  ci_hang_budget.sh not present"
fi

echo
echo "== the job ceiling must agree between ci.yml and the budget script =="
# THIS ARM EXISTS BECAUSE THE 'SINGLE SOURCE' FIX WAS A BLOCKER.
#
# `timeout-minutes: ${{ env.JOB_CEILING_MIN }}` looks like it removes the
# duplication. At job level GitHub accepts only the github / needs / strategy /
# matrix / vars / inputs contexts there, so `env` is a WORKFLOW PARSE ERROR --
# "Unrecognized named-value: 'env'" -- and GitHub then runs ZERO JOBS. The
# document is structurally valid YAML, so a parser cannot see it; only an actual
# run can. Merged, main would have had no CI at all.
#
# So the two literals stay and this arm ENFORCES their agreement, which is what
# the expression was only pretending to do.
CI_YML="$HERE/../.github/workflows/ci.yml"
BUD="$HERE/ci_hang_budget.sh"
if [ -f "$CI_YML" ] && [ -f "$BUD" ]; then
  ci_min=$(awk '/^  build-and-test:/{f=1} f && /^    timeout-minutes:/{print $2; exit}' "$CI_YML")
  sc_min=$(grep -oE 'JOB_CEILING_MIN:-[0-9]+' "$BUD" | head -1 | sed 's/.*://; s/^-//')
  # (`cut -d- -f3` returned empty here: "JOB_CEILING_MIN:-45" has ONE dash, so
  # field 3 does not exist. An extraction that silently yields "" makes the
  # comparison below compare 45 against nothing and report a mismatch that is
  # not real -- the arm would have cried wolf on every run.)
  chk "ci.yml build-and-test ceiling ($ci_min) == budget script default ($sc_min)" "$ci_min" "$sc_min"
  # And it must be a literal, not an expression GitHub will refuse.
  case "$ci_min" in
    ''|*[!0-9]*) echo "   FAIL  build-and-test timeout-minutes is not a plain integer: '$ci_min'"; F=$((F+1)) ;;
    *)           chk "and it is a literal integer, not an \${{ }} expression" yes yes ;;
  esac
else
  echo "   SKIP  ci.yml or ci_hang_budget.sh not reachable from here"
fi

echo
echo "== a workflow must be able to actually EXECUTE the scripts it invokes =="
# THIS ARM EXISTS BECAUSE ITS ABSENCE COST FOUR RED CI LEGS.
#
# ci.yml ran `./scripts/run_with_hang_capture.sh` while that file was tracked
# 100644 -- the repo is developed on Windows, where the executable bit does not
# survive a checkout, and 68 of its 69 tracked scripts are 100644 as a result.
# On the runner that is exit 126, "Permission denied", before a single test ran.
#
# WHY NOBODY CAUGHT IT: every local run, mine included, invoked the script as
# `bash scripts/...`, which needs no mode bit. The instrument could not exhibit
# the defect class it was meant to cover -- "it parses" is not "it runs", and
# "bash runs it" is not "the workflow runs it".
#
# repo-hygiene.yml already had the answer and was not copied: it has an explicit
# `chmod +x` step before its `./` call. So the rule below accepts EITHER remedy
# rather than pinning one style -- it passes repo-hygiene.yml today, and would
# have failed ci.yml before this fix.
WF="$HERE/../.github/workflows"
if [ -d "$WF" ] && git -C "$HERE/.." rev-parse --git-dir >/dev/null 2>&1; then
  bad=0; seen=0
  # COMMENTS ARE NOT INVOCATIONS. The first version of this scanned raw text and
  # counted "2" where only one line actually runs anything -- the other was a
  # comment in ci.yml that merely NAMES the path. An arm that reddens or greens
  # on prose is measuring the wrong population, so strip comment lines first.
  for inv in $(grep -rh -v '^[[:space:]]*#' "$WF" \
               | grep -oE '\./scripts/[A-Za-z0-9._-]+\.sh' | sed 's|^\./||' | sort -u); do
    seen=$((seen + 1))
    mode=$(git -C "$HERE/.." ls-files -s -- "$inv" 2>/dev/null | awk '{print $1}')
    [ "$mode" = "100755" ] && continue
    grep -rqF "chmod +x $inv" "$WF" && continue
    echo "      $inv is mode ${mode:-UNTRACKED} in the index and no workflow chmods it"
    bad=$((bad + 1))
  done
  chk "all $seen ./scripts invocations in workflows run on a fresh checkout" "$bad" 0
else
  echo "   SKIP  no workflow directory, or not a git checkout"
fi

echo
echo "== the extracted scripts keep their executable bit in the index =="
# Belt to the brace above. `bash <script>` makes the mode bit unnecessary, but a
# future edit that switches back to `./` should find the bit already there.
# A Windows commit that silently drops it reddens HERE rather than in CI.
if git -C "$HERE/.." rev-parse --git-dir >/dev/null 2>&1; then
  for s in scripts/run_with_hang_capture.sh scripts/test_run_with_hang_capture.sh; do
    m=$(git -C "$HERE/.." ls-files -s -- "$s" | awk '{print $1}')
    chk "$s is 100755 in the index" "${m:-MISSING}" 100755
  done
else
  echo "   SKIP  not a git checkout"
fi

echo
echo "   ===== run_with_hang_capture: $P passed, $F failed ====="
[ "$F" -eq 0 ]

#!/usr/bin/env bash
# CENSUS: which roster suites can lose later test cases to an assert() abort.
#
# WHY IT MATTERS. A hand-written main() that calls scenario functions in
# sequence loses EVERY LATER SCENARIO on the first assert(): the process dies,
# so those cases have never run at all -- quarantined or not. Two consequences:
#
#   * a quarantine reason of the form "N assertions fail" is an UNDERCOUNT. N is
#     what was visible before the abort, not what fails.
#   * quarantine is all-or-nothing, so one broken scenario removes a whole file
#     from the gate, including scenarios that were passing.
#
# MEASURED INSTANCE (2026-09-07, chain_case_2_5_equivalence_tests, Linux/WSL):
# the quarantine reason named scenario_2. Run one at a time with --only=,
# scenario_4 fails too, with the same assertion shape, and had NEVER been
# observed -- it sits behind the scenario_2 abort. Scenarios 1, 3 and 5 pass and
# are now gating via a partial: roster row.
#
# This is a CENSUS, not a sample: it walks every row --list reports. Where the
# property varies per item, sampling smarter does not help.
#
# Usage: scripts/census_test_mains.sh [--summary]
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." || exit 2

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

{
printf '%-46s %-8s %-7s %-9s %s\n' SUITE MAIN ASSERTS ARGV RISK
printf '%.0s-' $(seq 1 96); echo

bash scripts/run_test_suites.sh --list all 2>/dev/null | tr ' ' '\n' | sort -u | while read -r s; do
  [ -z "$s" ] && continue
  f=""
  for cand in "src/test/${s}.cpp" "src/test/${s%_tests}_tests.cpp"; do
    [ -f "$cand" ] && f="$cand" && break
  done
  if [ -z "$f" ]; then
    f="$(grep -rl "int main" src/test 2>/dev/null | xargs -r grep -l "$s" 2>/dev/null | head -1)"
  fi
  [ -z "$f" ] && { printf '%-46s %-8s %-7s %-9s %s\n' "$s" "?" "?" "?" "source not found"; continue; }

  if grep -qE 'BOOST_AUTO_TEST|BOOST_FIXTURE_TEST' "$f"; then
    printf '%-46s %-8s %-7s %-9s %s\n' "$s" "boost" "-" "yes" "boost isolates each case"
    continue
  fi
  has_main="no"; grep -qE '^\s*int\s+main\s*\(' "$f" && has_main="yes"
  n_assert="$(grep -cE '(^|[^_[:alnum:]])assert\s*\(' "$f")"
  argv="no"; grep -qE 'int\s+main\s*\(\s*int' "$f" && argv="yes"

  risk="-"
  if [ "$has_main" = yes ] && [ "$n_assert" -gt 0 ]; then
    if [ "$argv" = yes ] && grep -q 'test_only_selector.h' "$f"; then
      risk="mitigated: --only= selector adopted"
    else
      risk="ABORT-LOSES-LATER-CASES"
    fi
  fi
  printf '%-46s %-8s %-7s %-9s %s\n' "$s" "$has_main" "$n_assert" "$argv" "$risk"
done
} > "$TMP"

if [ "${1:-}" = "--summary" ]; then
    total=$(( $(wc -l < "$TMP") - 2 ))
    abort=$(grep -c 'ABORT-LOSES' "$TMP")
    mitig=$(grep -c 'mitigated:' "$TMP")
    boost=$(awk '$2=="boost"' "$TMP" | wc -l)
    noassert=$(awk 'NR>2 && $3=="0"' "$TMP" | wc -l)
    echo "roster suites censused         : $total"
    echo "hand-written main + assert()   : $abort   <- lose every later case on first failure"
    echo "  of which mitigated by --only : $mitig"
    echo "hand-written main, no assert   : $noassert"
    echo "boost (isolates per case)      : $boost"
    echo
    echo "highest exposure (most asserts behind a single abort):"
    sort -k3 -rn "$TMP" | head -8 | sed 's/^/  /'
else
    cat "$TMP"
fi

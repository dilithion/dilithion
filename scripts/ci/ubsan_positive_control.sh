#!/usr/bin/env bash
# UBSan leg positive control: proves the sanitizer-ubsan job CAN fail on undefined behaviour.
#
# A sanitizer leg that cannot fail reads green whatever it finds. This leg could not fail in two
# independent ways: `|| true` on the test step, and UBSan's default of reporting a finding and then
# continuing with exit 0. This control compiles a one-line UB with the SAME compilers and flags the
# leg builds with and requires, for each compiler:
#
#   CLEAN arm (valid shift)        exit 0 and no report   <- a control that always fails proves nothing
#   UB arm    (shift exponent 40)  a report AND non-zero  <- the leg can go red
#
# Both compilers, because the leg's test binary contains objects from both:
#   project objects  g++      (Makefile `CXX := g++` overrides the job's CXX=clang++)
#   RandomX objects  clang++  (its cmake honours CC/CXX)
#
# Required env: CXXFLAGS (the leg's project flags) and RANDOMX_UBSAN_FLAGS (the leg's RandomX flags).
# Missing input is a failure, never a pass.
set -euo pipefail

SRC="${SRC:-scripts/ci/ubsan_positive_control.cpp}"
PROJECT_CXX="${PROJECT_CXX:-g++}"
RANDOMX_CXX="${RANDOMX_CXX:-clang++}"
: "${CXXFLAGS:?CXXFLAGS must be set to the UBSan leg project flags}"
: "${RANDOMX_UBSAN_FLAGS:?RANDOMX_UBSAN_FLAGS must be set to the UBSan leg RandomX flags}"
[ -f "$SRC" ] || { echo "::error title=UBSan control::control source not found: $SRC"; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

check() {
  local label="$1" bin="$2"
  local clean_rc=0 ub_rc=0 clean_reports ub_reports
  "$bin" 3  >"$work/clean.out" 2>&1 || clean_rc=$?
  "$bin" 40 >"$work/ub.out"    2>&1 || ub_rc=$?
  clean_reports=$(grep -c 'runtime error:' "$work/clean.out" || true)
  ub_reports=$(grep -c 'runtime error:' "$work/ub.out" || true)
  echo "[$label] CLEAN arm: exit=$clean_rc reports=$clean_reports | UB arm: exit=$ub_rc reports=$ub_reports"
  if [ "$clean_rc" -ne 0 ] || [ "$clean_reports" -ne 0 ]; then
    echo "::error title=UBSan control::[$label] the CLEAN arm failed, so the control proves nothing"
    failures=$((failures + 1))
  fi
  if [ "$ub_reports" -eq 0 ]; then
    echo "::error title=UBSan control::[$label] undefined behaviour produced no report: UBSan is not active with these flags"
    failures=$((failures + 1))
  elif [ "$ub_rc" -eq 0 ]; then
    echo "::error title=UBSan control::[$label] undefined behaviour was reported but exited 0: this leg cannot fail on UB"
    failures=$((failures + 1))
  fi
}

# Flag strings are word-split on purpose.
# shellcheck disable=SC2086
"$PROJECT_CXX" $CXXFLAGS -fwrapv "$SRC" -o "$work/ctl_project"
# shellcheck disable=SC2086
"$RANDOMX_CXX" -std=c++17 $RANDOMX_UBSAN_FLAGS "$SRC" -o "$work/ctl_randomx"

check "project objects: $PROJECT_CXX" "$work/ctl_project"
check "RandomX objects: $RANDOMX_CXX" "$work/ctl_randomx"

if [ "$failures" -ne 0 ]; then
  echo "UBSan positive control FAILED with $failures problem(s)."
  exit 1
fi
echo "UBSan positive control passed: both compilers report undefined behaviour and fail on it, and clean code passes."

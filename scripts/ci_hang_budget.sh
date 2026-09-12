#!/usr/bin/env bash
# ============================================================================
# ci_hang_budget.sh — how many seconds the hang watchdog may wait.
#
# THE BUDGET IS COMPUTED, NOT A LITERAL, AND THAT IS THE WHOLE POINT.
# `timeout-minutes` is measured from JOB start, but a watchdog inside a step can
# only measure STEP time. Measured on a real hung job (run 33929931137, steps
# API):
#
#     job start                 00:43:37
#     "Run Boost Unit Tests"    01:03:33   <- 19m56s of the job already spent
#     45-min ceiling            01:28:37
#
# So that step had ~25 minutes of real budget, not 45. A fixed 38-minute
# watchdog -- the first version of this -- would have fired at 01:41, THIRTEEN
# MINUTES AFTER the ceiling: the instrument would never once have run.
#
# Extracted from the workflow with the watchdog itself, so the arithmetic is
# testable rather than trusted. Prints the budget in seconds on stdout.
#
# Env:
#   JOB_CEILING_MIN   job timeout in minutes (same value as timeout-minutes)
#   JOB_START_EPOCH   stamped by the job's first step
# ============================================================================
set -uo pipefail

CEILING_MIN="${JOB_CEILING_MIN:-45}"
CEILING_SEC=$(( CEILING_MIN * 60 ))
CAPTURE_MARGIN=240        # gdb attach + dump + artifact upload
MIN_BUDGET=300            # never watchdog a run into uselessness
# Cap against the MEASURED healthy step, not against the ceiling. On a green
# main run (34082001939) this step takes 44s / 47s / 57s / 61s across the four
# legs; the hung leg ran 1516s. 600s is ~10x the healthy maximum and ~2.5x below
# the hang, so it catches the hang ten minutes in instead of twenty-five and
# leaves the rest of the ceiling as margin.
MAX_BUDGET=600

start="${JOB_START_EPOCH:-0}"
if [ "$start" -le 0 ]; then
    # No clock means the subtraction below is meaningless. Say so rather than
    # silently arming against a wrong elapsed time.
    echo "::warning::JOB_START_EPOCH not set; using the minimum watchdog budget. A missing hang artifact from this run means nothing." >&2
    echo "$MIN_BUDGET"
    exit 0
fi

elapsed=$(( $(date +%s) - start ))
BUDGET=$(( CEILING_SEC - elapsed - CAPTURE_MARGIN ))
[ "$BUDGET" -gt "$MAX_BUDGET" ] && BUDGET="$MAX_BUDGET"

# If the build has already eaten the budget there is nothing left to watchdog
# WITH, and the clamp below would arm a timer that fires after the ceiling --
# inert, exactly like the version this replaces. Say it out loud: otherwise a
# missing artifact reads as "no hang happened" when it means "the instrument
# never armed".
if [ "$BUDGET" -lt "$MIN_BUDGET" ]; then
    echo "::warning::hang watchdog NOT ARMED: ${elapsed}s of the ${CEILING_SEC}s job budget already spent, leaving less than ${MIN_BUDGET}s. A missing hang artifact from this run means nothing." >&2
    BUDGET="$MIN_BUDGET"
fi

echo "hang watchdog: ${elapsed}s of the job already spent; budget ${BUDGET}s" >&2
echo "$BUDGET"

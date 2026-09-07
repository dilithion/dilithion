#!/bin/bash
# Both arms of the cs_headers -> g_validation_mutex STALL harness.
# Build: make TSAN=1 -j8 p2p14_headers_randomx_stall_tsan_tests
# Run:   N=200 scripts/run_p2p14_headers_stall.sh
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
B=./p2p14_headers_randomx_stall_tsan_tests
export TSAN_OPTIONS="detect_deadlocks=1:halt_on_error=0"
for arm in unwarmed prewarmed; do
  echo "================ ARM: ${arm} ================"
  timeout -k 5 300 setarch "$(uname -m)" -R "$B" "${arm}" "${N:-12}" >"/tmp/stall_${arm}.out" 2>"/tmp/stall_${arm}.err"
  echo "EXIT=$?"
  grep -E '\[p2p14-stall\]' "/tmp/stall_${arm}.out"
  grep -E 'DEFECT|ThreadSanitizer' "/tmp/stall_${arm}.err" | head -3
done

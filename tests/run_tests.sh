#!/usr/bin/env bash
# Runs every unit test. Each test is a standalone script whose last line is the verdict:
#   ALL PASS / REPRODUCED  -> passed
#   SKIP: <reason>         -> skipped (a test that needs dataset files not present here)
#   anything else          -> failed
# Exit status is non-zero if any test failed. Used by .github/workflows/tests.yml and by hand:
#   bash tests/run_tests.sh
set -u
cd "$(dirname "$0")/.."
pass=0; skip=0; fail=0
for t in tests/test_*.py; do
  r="$(python3 "$t" 2>&1 | tail -1)"
  case "$r" in
    *"ALL PASS"*|*REPRODUCED*) pass=$((pass+1)); printf 'ok    %s\n' "$(basename "$t")" ;;
    SKIP*)                     skip=$((skip+1)); printf 'skip  %s: %s\n' "$(basename "$t")" "${r#SKIP: }" ;;
    *)                         fail=$((fail+1)); printf 'FAIL  %s: %s\n' "$(basename "$t")" "$r" ;;
  esac
done
echo "tests: $pass passed, $skip skipped, $fail failed"
[ "$fail" = 0 ]

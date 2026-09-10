#!/usr/bin/env bash
#
# Run a Gradle command and, if it fails, print the part of the log that says
# why.
#
# WHY THIS IS NOT JUST "* What went wrong"
# ----------------------------------------
# Gradle's own summary is the last thing in the log, which is convenient, and
# for a task that wraps another process it is close to useless.  Run #5 of this
# workflow ended with:
#
#   * What went wrong:
#   Execution failed for task ':app:generateDebugPythonRequirements'.
#   > Process 'command '.../python'' finished with non-zero exit value 1
#
# The actual cause -- "ERROR: Failed to install pycares<6,>=5.0.0 (from
# aiodns>=3.2.0->slixmpp)" -- was three hundred lines further up, and finding
# it cost a round trip to the runner.  Chaquopy, kotlinc and the test runner
# all behave this way: the diagnosis is upstream of the summary.
#
# So this prints the regions that carry a diagnosis, each only when it has
# something in it, and Gradle's summary last.
#
# Usage:  .github/scripts/gradle.sh ./gradlew :app:assembleDebug
#
set -o pipefail

LOG="${GRADLE_LOG:-$(mktemp)}"

"$@" 2>&1 | tee "$LOG"
status=$?
if [ "$status" -eq 0 ]; then
    exit 0
fi

# Print every line matching $2, with $3 lines of trailing context, under the
# heading $1 -- but only if there was a match, so a failure's output stays the
# size of its actual diagnosis.
section() {
    local heading="$1" pattern="$2" after="${3:-0}"
    if grep -Eq "$pattern" "$LOG"; then
        echo
        echo "================ $heading ================"
        grep -E -A "$after" "$pattern" "$LOG" | head -80
    fi
}

# Chaquopy resolves the APK's Python requirements by shelling out to pip, and
# reports the failure only as an exit status.
section "PYTHON REQUIREMENTS (Chaquopy/pip)" \
    '^(ERROR: |Chaquopy: )|Chaquopy_cannot_compile_native_code|No matching distribution|Could not find a version that satisfies' 2

# kotlinc prefixes errors with "e: ", and the AGP task that runs it reports
# only "Compilation error. See log for more details".
section "KOTLIN / JAVA COMPILATION" '^e: |^\s+error: ' 0

# The test task names the report directory and nothing else.
#
# The pattern allows spaces in the middle because Kotlin test names have them:
#   AttemptThrottleTest > backoff grows after each failure FAILED
# An earlier `^\S+ > \S+ FAILED` matched only single-word test names, which is
# almost none of them.
section "FAILED TESTS" '^\S+ > .*FAILED$|tests completed, .*failed' 0

echo
echo "================ WHAT WENT WRONG ================"
sed -n '/^\* What went wrong:/,/^BUILD FAILED/p' "$LOG" | head -60

exit "$status"

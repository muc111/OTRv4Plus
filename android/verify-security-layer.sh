#!/usr/bin/env bash
# Compile and unit-test the application security layer WITHOUT the Android SDK.
#
# The security layer (LockState, AppLockManager, AttemptThrottle,
# UnlockCredentialService, KeystoreManager, SecureStore) deliberately imports
# nothing from Android, so it builds and runs on a plain JVM. That means the
# lock state machine and the brute-force throttle can be verified on any
# machine, including CI images without the Android toolchain.
#
# `./gradlew :app:testDebugUnitTest` runs the same tests once the Android SDK is
# available; this script exists so they are not blocked on it.
#
# Usage:  bash android/verify-security-layer.sh [cache-dir]
set -euo pipefail

KT_VERSION=2.0.21
CACHE="${1:-${TMPDIR:-/tmp}/otrv4plus-kotlin}"
MAVEN=https://repo1.maven.org/maven2
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/app/src/main/java/org/otrv4plus/android/security"
TST="$HERE/app/src/test/java/org/otrv4plus/android/security"

mkdir -p "$CACHE"
fetch() { # url dest
  [ -f "$CACHE/$2" ] || curl -sSLf -o "$CACHE/$2" "$1"
}

echo "==> fetching Kotlin $KT_VERSION toolchain into $CACHE"
for a in kotlin-compiler kotlin-stdlib kotlin-test kotlin-test-junit; do
  fetch "$MAVEN/org/jetbrains/kotlin/$a/$KT_VERSION/$a-$KT_VERSION.jar" "$a.jar"
done
fetch "$MAVEN/org/jetbrains/kotlinx/kotlinx-coroutines-core-jvm/1.8.1/kotlinx-coroutines-core-jvm-1.8.1.jar" coroutines.jar
fetch "$MAVEN/org/jetbrains/intellij/deps/trove4j/1.0.20200330/trove4j-1.0.20200330.jar" trove4j.jar
fetch "$MAVEN/org/jetbrains/annotations/13.0/annotations-13.0.jar" annotations.jar
fetch "$MAVEN/junit/junit/4.13.2/junit-4.13.2.jar" junit.jar
fetch "$MAVEN/org/hamcrest/hamcrest-core/1.3/hamcrest-core-1.3.jar" hamcrest.jar

# annotations.jar must be on the COMPILER's own classpath, not just the compile
# classpath: the JVM backend loads org.jetbrains.annotations.NotNull while
# emitting parameter nullability annotations, and fails with a backend internal
# error without it.
COMPILER_CP="$CACHE/kotlin-compiler.jar:$CACHE/coroutines.jar:$CACHE/trove4j.jar:$CACHE/annotations.jar"
COMPILE_CP="$CACHE/kotlin-stdlib.jar:$CACHE/kotlin-test.jar:$CACHE/kotlin-test-junit.jar:$CACHE/junit.jar:$CACHE/hamcrest.jar:$CACHE/annotations.jar"
OUT="$CACHE/out"

echo "==> compiling"
rm -rf "$OUT"; mkdir -p "$OUT"
java -cp "$COMPILER_CP" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
  "$SRC"/*.kt "$TST"/*.kt -classpath "$COMPILE_CP" -d "$OUT" -no-stdlib -no-reflect

echo "==> running tests"
java -cp "$OUT:$COMPILE_CP" org.junit.runner.JUnitCore \
  org.otrv4plus.android.security.LockStateTransitionTest \
  org.otrv4plus.android.security.AppLockManagerTest \
  org.otrv4plus.android.security.AttemptThrottleTest \
  org.otrv4plus.android.security.ClockRollbackTest \
  org.otrv4plus.android.security.Argon2idParamsTest \
  org.otrv4plus.android.security.RecordTypeTest

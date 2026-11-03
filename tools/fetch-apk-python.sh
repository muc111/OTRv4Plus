#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
#
# Download every third-party file the APK's Python is built from into
# android/app/wheels, each checked against android/app/python-lock.txt.
# The Gradle build then installs from that directory only (--no-index).
# Run from the repository root, before ./gradlew, after the otrv4_core
# wheels are in android/app/wheels.
set -eu
PY="${PYTHON:-python3}"
cd "$(dirname "$0")/.."
mkdir -p android/app/wheels
# --no-binary slixmpp: Chaquopy builds it from its sdist (its Rust part is
# optional and is not built for Android); the runner's own wheel is not it.
"$PY" -m pip download --disable-pip-version-check --quiet \
    --require-hashes --no-deps --no-binary slixmpp \
    -r android/app/python-lock.txt -d android/app/wheels
echo "verified: $(grep -c '^[A-Za-z]' android/app/python-lock.txt) packages in android/app/wheels"

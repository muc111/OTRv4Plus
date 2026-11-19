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
# --no-binary slixmpp: the sdist, which the step below turns into the
# pure-Python wheel the APK installs (its Rust part is optional and is not
# built for Android); the runner's own wheel is not it.
"$PY" -m pip download --disable-pip-version-check --quiet \
    --require-hashes --no-deps --no-binary slixmpp \
    -r android/app/python-lock.txt -d android/app/wheels
echo "verified: $(grep -c '^[A-Za-z]' android/app/python-lock.txt) packages in android/app/wheels"

# slixmpp as a pure-Python WHEEL, built here from the sdist just verified.
# Chaquopy 17's pip installs binary wheels only (an sdist from --find-links is
# "versions: none"), and slixmpp publishes no wheel. The build is offline and
# uses only the locked build tools in wheels/; cargo is disabled so the
# optional Rust `slixmpp.jid` is skipped exactly as it was when Chaquopy built
# the sdist (slixmpp falls back to its Python JID). setuptools tags the result
# for this machine because an extension is declared, so it is checked to hold
# no compiled file and retagged py3-none-any (WHEEL and RECORD rewritten).
rm -f android/app/wheels/slixmpp-*.whl
CARGO=/bin/false "$PY" -m pip wheel --disable-pip-version-check --quiet \
    --no-deps --no-index --find-links android/app/wheels \
    -w android/app/wheels android/app/wheels/slixmpp-*.tar.gz
"$PY" -I - android/app/wheels <<'PY'
import base64, hashlib, os, sys, zipfile
d = sys.argv[1]
[built] = [f for f in os.listdir(d) if f.startswith("slixmpp-") and f.endswith(".whl")]
src = os.path.join(d, built)
name, ver = built.split("-")[:2]
dist = "%s-%s.dist-info/" % (name, ver)
with zipfile.ZipFile(src) as z:
    items = [(i, z.read(i)) for i in z.infolist()]
compiled = [i.filename for i, _ in items if i.filename.endswith((".so", ".pyd", ".dylib"))]
if compiled:
    sys.exit("slixmpp wheel holds compiled files %s; not a pure wheel" % compiled)
wheel_meta = ("Wheel-Version: 1.0\nGenerator: tools/fetch-apk-python.sh\n"
              "Root-Is-Purelib: true\nTag: py3-none-any\n").encode()
def rec(path, data):
    h = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return "%s,sha256=%s,%d" % (path, h, len(data))
out = os.path.join(d, "%s-%s-py3-none-any.whl" % (name, ver))
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    lines = []
    for info, data in items:
        if info.filename == dist + "WHEEL":
            data = wheel_meta
        if info.filename == dist + "RECORD":
            continue
        z.writestr(info.filename, data)
        lines.append(rec(info.filename, data))
    lines.append(dist + "RECORD,,")
    z.writestr(dist + "RECORD", "\n".join(lines) + "\n")
if out != src:
    os.remove(src)
print("built: " + os.path.basename(out))
PY

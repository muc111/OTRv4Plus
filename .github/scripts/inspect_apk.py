#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Inspect a built APK and fail if it contains what a release must not.

Run on the actual artifact, not the source tree: an APK is what users install,
and a build can differ from the tree in ways no source check sees (a stale
generated directory, a dependency that resolved differently, a debug-only
class that R8 kept).

    inspect_apk.py APK --variant release|debug [--manifest OUT.txt]

Prints what it checked; exits non-zero on the first category that fails, after
reporting every failure it found. With --manifest, writes the full file list
with SHA-256 per entry, so a published APK's contents are on record.
"""

import argparse
import hashlib
import io
import re
import sys
import zipfile

#: Python modules the bridge ships (syncPythonSources) and must ship.
REQUIRED_APP_MODULES = ("otrv4_.py", "otrv4plus_xmpp.py", "otrv4plus_voice.py",
                        "otrv4plus_filetransfer.py", "otrv4plus_identity.py",
                        "android_bridge/app.py", "android_bridge/wipe.py",
                        "android_bridge/transport.py",
                        # Android voice: AAudio capture/playback, and the
                        # module that binds the APK's codec and AAudio instead
                        # of the Termux (opuslib) hooks.
                        "otrv4plus_audio.py", "android_bridge/android_audio.py",
                        "android_bridge/voice.py")

#: Never in the APK: terminal-only programs, test scaffolding, the retired
#: pre-Rust engine, and anything that would be a second implementation.
FORBIDDEN_APP = re.compile(
    r"(^|/)(otrv4plus_tui|weechat_otrv4plus|smp_engine_compat|otrv4_testlib|"
    r"integrate_voice_v3|conftest|test_[^/]*|otrv4plus-1)\.pyc?$|(^|/)tests/|(^|/)\.attic/")

#: Python distributions the APK must carry, and ones it must not.
REQUIRED_REQS = ("otrv4_core", "slixmpp", "socks", "pyasn1", "pyasn1_modules")
FORBIDDEN_REQS = ("argon2", "_cffi_backend", "cffi/", "pycparser", "cryptography/",
                  "aiodns", "pycares", "Crypto/", "kyber_py", "nacl/",
                  # The TERMUX codec wrapper. The APK's codec is libopus inside
                  # otrv4_core; opuslib here would mean the Android voice path
                  # had fallen back to the Termux one.
                  "opuslib")

#: Files that must never be packaged.
FORBIDDEN_ANYWHERE = re.compile(
    r"\.(jks|keystore|p12|pem|key|env)$|(^|/)id_(rsa|ed25519)|(^|/)credentials|"
    r"(^|/)\.git/|smp_secrets|identity\.sealed|\.identity_dek|\.smp_seed|\.device_seed",
    re.I)

#: Public files allowed despite a key-like extension: Chaquopy's CA bundle
#: for TLS. Its content is checked to be certificates and nothing else.
PUBLIC_PEM = {"assets/chaquopy/cacert.pem"}
PRIVATE_KEY = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")

#: PyO3 names that exist only when the core is built with a test/legacy
#: feature. Their presence in the shipped .so means a gated API shipped.
GATED_CORE_SYMBOLS = (b"get_session_keys", b"load_by_handle", b"expose_seed",
                      b"legacy-dake-keys", b"test-only-kdf")

#: A string literal that exists only in the debug variant's source set
#: (src/debug/.../diag/DiagnosticsScreen.kt). Class names would not do: R8
#: renames them in release, so their absence would prove nothing. String
#: constants survive obfuscation.
DEBUG_ONLY_MARKERS = (b"Debug build only. Not present in release.",)


class Report:
    def __init__(self):
        self.failures = []

    def check(self, ok, what):
        print(("  ok    " if ok else "  FAIL  ") + what)
        if not ok:
            self.failures.append(what)


def _nested(apk, prefix):
    """Every .imy (Chaquopy's zip) under assets/chaquopy/ with this prefix."""
    out = {}
    for name in apk.namelist():
        if name.startswith("assets/chaquopy/" + prefix) and name.endswith(".imy"):
            out[name] = zipfile.ZipFile(io.BytesIO(apk.read(name)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("apk")
    ap.add_argument("--variant", choices=("release", "debug"), required=True)
    ap.add_argument("--manifest")
    args = ap.parse_args()

    r = Report()
    apk = zipfile.ZipFile(args.apk)
    names = apk.namelist()
    print("inspecting %s (%s, %d entries)" % (args.apk, args.variant, len(names)))

    print("packaging:")
    r.check("assets/NOTICE" in names and
            b"third-party notices" in apk.read("assets/NOTICE"),
            "assets/NOTICE is present and is the generated attribution file")
    bad = [n for n in names if FORBIDDEN_ANYWHERE.search(n) and n not in PUBLIC_PEM]
    r.check(not bad, "no key, credential, secret-store or VCS file packaged %s"
            % (bad[:5] if bad else ""))
    # Content, not just names: a private key under an innocent name is still
    # a private key. Every entry, including inside Chaquopy's zips.
    keyed = [n for n in names if PRIVATE_KEY.search(apk.read(n))]
    for imy in [n for n in names if n.endswith(".imy")]:
        z = zipfile.ZipFile(io.BytesIO(apk.read(imy)))
        keyed += ["%s!%s" % (imy, m) for m in z.namelist() if PRIVATE_KEY.search(z.read(m))]
    r.check(not keyed, "no private key material anywhere in the APK %s" % (keyed[:5] or ""))
    for pem in PUBLIC_PEM & set(names):
        body = apk.read(pem)
        r.check(body.count(b"-----BEGIN CERTIFICATE-----") > 0 and
                not re.search(rb"-----BEGIN (?!CERTIFICATE)", body),
                "%s holds public CA certificates only" % pem)

    print("python sources:")
    app = _nested(apk, "app")
    app_names = [n for z in app.values() for n in z.namelist()]
    for mod in REQUIRED_APP_MODULES:
        r.check(any(n in (mod, mod + "c") or n.endswith("/" + mod) or n.endswith("/" + mod + "c")
                    or n == mod.replace(".py", ".pyc") for n in app_names),
                "ships %s" % mod)
    bad = [n for n in app_names if FORBIDDEN_APP.search(n)]
    r.check(not bad, "no terminal-only, test or retired module %s" % (bad[:5] if bad else ""))

    print("python requirements:")
    reqs = _nested(apk, "requirements")
    req_names = [n for z in reqs.values() for n in z.namelist()]
    for dist in REQUIRED_REQS:
        r.check(any(n.startswith(dist + "/") or n.startswith(dist + "-")
                    or n in (dist + ".py", dist + ".pyc") for n in req_names),
                "carries %s" % dist)
    for dist in FORBIDDEN_REQS:
        hit = [n for n in req_names if n.startswith(dist)]
        r.check(not hit, "does not carry %s" % dist.rstrip("/"))

    print("rust core:")
    cores = {"%s!%s" % (imy.rsplit("/", 1)[-1], n): z.read(n)
             for imy, z in reqs.items() for n in z.namelist()
             if n.endswith("otrv4_core.so")}
    r.check(len(cores) >= 2, "otrv4_core.so for every ABI (%d found)" % len(cores))
    for n, blob in cores.items():
        gated = [s.decode() for s in GATED_CORE_SYMBOLS if s in blob]
        r.check(not gated, "%s exposes no test-only or legacy API %s" % (n, gated or ""))
        r.check(b"SmpSecretStore" in blob and b"FileDek" in blob,
                "%s is the 0.11 core (Rust-owned at-rest store present)" % n)
        # The voice codec, IN the artifact: the classes Python binds, and
        # libopus itself -- its version string is only present if the library
        # was linked (`opus_version()` reads it, so LTO keeps it). A core
        # built without `android-opus` would import fine and fail on the first
        # call.
        r.check(b"OpusEncoder" in blob and b"OpusDecoder" in blob,
                "%s exposes the Android Opus codec (OpusEncoder/OpusDecoder)" % n)
        r.check(b"libopus 1.5" in blob,
                "%s has libopus 1.5 statically linked" % n)

    print("kotlin:")
    dex = b"".join(apk.read(n) for n in names if re.match(r"classes\d*\.dex$", n))
    r.check(bool(dex), "dex present")
    for marker in DEBUG_ONLY_MARKERS:
        present = marker in dex
        if args.variant == "release":
            r.check(not present, "the debug diagnostics screen is not compiled into release")
        else:
            r.check(present, "the debug build carries the diagnostics screen "
                             "(proves this check can see it)")

    if args.manifest:
        with open(args.manifest, "w") as fh:
            for n in sorted(names):
                fh.write("%s  %s\n" % (hashlib.sha256(apk.read(n)).hexdigest(), n))
            for imy, z in sorted(app.items()) + sorted(reqs.items()):
                for n in sorted(z.namelist()):
                    fh.write("%s  %s!%s\n" % (hashlib.sha256(z.read(n)).hexdigest(), imy, n))
        print("manifest written to %s" % args.manifest)

    if r.failures:
        print("\n%d check(s) failed" % len(r.failures))
        sys.exit(1)
    print("\nall checks passed")


if __name__ == "__main__":
    main()

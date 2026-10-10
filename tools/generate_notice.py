#!/usr/bin/env python3
"""Generate NOTICE from the resolved dependency graph.

Attribution is a distribution obligation: every permissive licence in the tree
(MIT, Apache-2.0, BSD-2/3-Clause, ISC, Unicode, PSF) requires its notice
reproduced in a binary that includes the code. A hand-written list rots the
first time someone runs `cargo add`, so this reads the graph instead.

**Only what actually ships.** The graph is the feature-resolved one
(`cargo tree -e normal`) for the shipped features and targets, following
NORMAL dependency edges only. A build-script helper, a test framework or an
optional backend that is never enabled is not in the artifact and does not
need attributing; including them would pad the file and dilute the part that
matters.

Usage:  python3 tools/generate_notice.py > NOTICE
"""

import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CRATE = os.path.join(ROOT, "Rust")

#: Where cargo unpacks crate sources, so their LICENSE files can be read for
#: the actual copyright holders rather than guessed from the author field.
REGISTRY_SRC = os.path.expanduser(
    "~/.cargo/registry/src")

LICENSE_FILE_RE = re.compile(
    r"^(LICEN[CS]E|COPYING|NOTICE)([-._].*)?$", re.IGNORECASE)

#: A real copyright line, not a sentence from a licence body. The first
#: version of this matched "(c) You must retain, in the Source form of any
#: Derivative Works" out of Apache-2.0 and attributed it to every crate that
#: ships that licence -- attribution that names the wrong holder is worse
#: than none, so this requires the line to BEGIN with the word.
COPYRIGHT_RE = re.compile(
    r"^\s*Copyright\b(?!\s+\[yyyy\])(?!\s+\(C\)\s+<year>).{0,180}$",
    re.IGNORECASE)

#: Boilerplate placeholders from the "how to apply this licence" appendices.
#: They are templates, not holders.
PLACEHOLDER_RE = re.compile(
    r"<year>|\[yyyy\]|\[name of copyright owner\]|<name of author>|"
    r"\[fullname\]|<COPYRIGHT HOLDER>|\{\}", re.IGNORECASE)


def cargo_metadata():
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--all-features"],
        cwd=CRATE, capture_output=True, check=True)
    return json.loads(out.stdout)


#: The features and targets of what is actually distributed: the APK
#: (Android arm64) and the wheels (Termux arm64, Linux x86_64). Test-only
#: features (raw-key-test-api, test-only-kdf) are not in any artifact.
SHIPPED_FEATURES = "pyo3/extension-module,android-opus,mls"
SHIPPED_TARGETS = ("aarch64-linux-android", "x86_64-unknown-linux-gnu")


#: Third-party code ported into first-party crates (not a dependency, so
#: not in the graph). Each entry's licence text is reproduced in §5.
DERIVED_CODE = (
    ("openmls_memory_storage", "0.6.0", "MIT",
     "Rust/mls/src/storage.rs (changed: CBOR, zeroizing values, wipe)",
     "Copyright (c) OpenMLS Authors"),
)


def _tree(target):
    out = subprocess.run(
        ["cargo", "tree", "-e", "normal", "--features", SHIPPED_FEATURES,
         "--target", target, "--prefix", "none", "--format", "{p}",
         "--offline"],
        cwd=CRATE, capture_output=True, check=True, text=True)
    found = set()
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            found.add((parts[0], parts[1][1:]))
    return found


def shipped_packages(meta):
    """Package ids COMPILED into what ships.

    From `cargo tree -e normal` with the shipped features, per shipped
    target -- the feature-resolved graph. NOT from `cargo metadata`'s
    `resolve`, which is lockfile-level and not feature-accurate: with the
    `mls` feature it lists openmls's optional backends (a SQLite store, two
    reference crypto providers, hpke-rs) as normal edges, although none of
    them is compiled. Attributing them would be wrong, and a licence gate
    reading them would fail on code that is not in the binary.
    """
    wanted = set()
    for target in SHIPPED_TARGETS:
        wanted |= _tree(target)
    ids = {p["id"] for p in meta["packages"]
           if (p["name"], p["version"]) in wanted}
    # First-party path crates (Rust/opus-codec, Rust/mls) are this project's
    # own code under its own licence, not third-party material to
    # attribute. A path crate has no registry `source` -- but a VENDORED
    # crate (Rust/vendor/, third-party code patched in place; see
    # Rust/vendor/VENDORED.md) is a path crate too, and is still somebody
    # else's code under their licence, so it stays attributed.
    vendor_dir = os.sep + os.path.join("Rust", "vendor") + os.sep
    first_party = {p["id"] for p in meta["packages"]
                   if p.get("source") is None
                   and vendor_dir not in (p.get("manifest_path") or "")}
    return ids - first_party


def copyrights_for(pkg):
    """Copyright lines from the crate's own licence files.

    Falls back to the manifest's `authors` only when the crate ships no
    licence file, and says so, rather than inventing a holder.
    """
    manifest = pkg.get("manifest_path") or ""
    src_dir = os.path.dirname(manifest)
    lines = []
    if src_dir and os.path.isdir(src_dir):
        for name in sorted(os.listdir(src_dir)):
            if not LICENSE_FILE_RE.match(name):
                continue
            path = os.path.join(src_dir, name)
            if not os.path.isfile(path):
                continue
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        if not COPYRIGHT_RE.match(line):
                            continue
                        if PLACEHOLDER_RE.search(line):
                            continue
                        text = " ".join(line.split())
                        if text not in lines:
                            lines.append(text)
            except OSError:
                continue
    if not lines:
        authors = [a for a in (pkg.get("authors") or []) if a.strip()]
        if authors:
            lines = ["Copyright (c) " + "; ".join(authors)
                     + "   [from Cargo.toml authors: the crate ships no"
                       " licence file to read a holder from]"]
    return lines


def exception_text(spdx_id):
    """The text of a licence EXCEPTION (the "WITH LLVM-exception" half).

    Kept separate because SPDX stores exceptions in their own directory, and
    a crate offered only as `Apache-2.0 WITH LLVM-exception` gives no
    permissive alternative to fall back on -- its exception text has to
    actually be reproduced.
    """
    return _spdx_text("exceptions", spdx_id)


def licence_text(spdx_id):
    """The full text for one licence: the repository's LICENSES/ first (REUSE
    layout, so the NOTICE is the same wherever it is generated), then the
    local SPDX crate corpus."""
    vendored = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "LICENSES", spdx_id + ".txt")
    if os.path.isfile(vendored):
        with open(vendored, encoding="utf-8") as fh:
            return fh.read().strip()
    return _spdx_text("licenses", spdx_id)


def _spdx_text(kind, spdx_id):
    base = os.path.join(REGISTRY_SRC)
    if not os.path.isdir(base):
        return None
    for entry in sorted(os.listdir(base)):
        candidate = os.path.join(base, entry)
        if not os.path.isdir(candidate):
            continue
        for name in sorted(os.listdir(candidate)):
            if not name.startswith("spdx-"):
                continue
            path = os.path.join(candidate, name, "src", "text", kind, spdx_id)
            if os.path.isfile(path):
                with open(path, encoding="utf-8") as fh:
                    text = fh.read()
                if text.startswith('r#"'):
                    text = text[3:text.rstrip().rindex('"#')]
                return text.strip()
    return None


#: Order of preference when a crate offers a choice. Shortest obligations
#: first: MIT and the BSDs are attribution-only, Apache-2.0 adds the NOTICE
#: and patent terms.
_PREFERENCE = ("MIT", "MIT-0", "BSD-2-Clause", "BSD-3-Clause", "BSD-1-Clause",
               "ISC", "Zlib", "Unlicense", "CC0-1.0", "Apache-2.0")


def chosen_licence(expr):
    """Which option we take, for a crate that offers several.

    A disjunctive expression ("MIT OR Apache-2.0 OR LGPL-2.1-or-later") is a
    choice the recipient makes, and the choice has to be recorded somewhere or
    it is not really made. Reproducing the LGPL text for a crate we take under
    MIT would imply obligations we have not accepted -- and, for anyone
    reading the NOTICE to check whether the project is safe to build on,
    imply a copyleft dependency that is not there.

    Conjunctions ("X AND Y") and exceptions ("X WITH Y") are not choices, so
    both halves are kept.
    """
    expr = (expr or "").strip()
    if not expr:
        return []
    # Normalise the old slash form some crates still use.
    expr = expr.replace("/", " OR ")
    taken = []
    # AND binds the whole expression: "(MIT OR Apache-2.0) AND Unicode-3.0"
    # means pick one of the first pair *and also* comply with Unicode-3.0.
    # Splitting on OR first read that as an option and produced "(MIT" as an
    # identifier, which is how the first run of this generator ended up
    # reporting a licence text it could not find.
    for conjunct in re.split(r"\bAND\b", expr):
        conjunct = conjunct.strip().strip("()").strip()
        if not conjunct:
            continue
        options = [o.strip().strip("()").strip()
                   for o in re.split(r"\bOR\b", conjunct)]
        options = [o for o in options if o]
        if not options:
            continue
        pick = None
        if len(options) > 1:
            for preferred in _PREFERENCE:
                if preferred in options:
                    pick = preferred
                    break
        if pick is None:
            pick = options[0]
        for part in _parts(pick):
            if part not in taken:
                taken.append(part)
    return taken


def _parts(option):
    """The identifiers inside one option, keeping WITH-exceptions."""
    return [tok.strip() for tok in re.split(r"\s+WITH\s+", option.strip())
            if tok.strip()]


def spdx_ids(expr):
    """Every identifier named in a licence expression."""
    return sorted({tok for tok in re.split(r"[^A-Za-z0-9.\-+]+", expr or "")
                   if tok and tok not in ("OR", "AND", "WITH")})


def main():
    meta = cargo_metadata()
    ids = shipped_packages(meta)
    pkgs = sorted((p for p in meta["packages"] if p["id"] in ids),
                  key=lambda p: p["name"].lower())

    out = []
    w = out.append
    w("OTRv4+ — third-party notices")
    w("=" * 76)
    w("")
    w("OTRv4+ itself is dual-licensed: AGPL-3.0 (see LICENSE) or a commercial")
    w("licence (see LICENSE-COMMERCIAL.md). This file is about everything")
    w("ELSE — the third-party code compiled into or shipped alongside it.")
    w("")
    w("Every component below is under a permissive licence. None imposes")
    w("copyleft on OTRv4+, and none restricts either half of the dual")
    w("licence. What they do require is attribution: their notices must")
    w("travel with any binary that includes them, which is what this file is")
    w("for. An APK, a wheel or a release tarball must carry it, and an app")
    w("with a licences screen should render it.")
    w("")
    w("GENERATED — do not edit by hand. Regenerate with:")
    w("    python3 tools/generate_notice.py > NOTICE")
    w("The Rust section is read from the feature-resolved dependency graph")
    w("(cargo tree -e normal) for the shipped features and targets: a")
    w("build-script helper, a test framework or an optional backend that is")
    w("never enabled is not in the shipped artifact and is not attributed here.")
    w("")

    # ---- Rust ------------------------------------------------------------
    w("")
    w("-" * 76)
    w("1. Rust crates compiled into otrv4_core (%d)" % len(pkgs))
    w("-" * 76)
    w("")
    for pkg in pkgs:
        offered = pkg.get("license") or "see licence file"
        taken = chosen_licence(pkg.get("license"))
        w("%s %s" % (pkg["name"], pkg["version"]))
        if taken and " OR " in offered.replace("/", " OR "):
            w("    Offered: %s" % offered)
            w("    Taken:   %s" % " WITH ".join(taken))
        else:
            w("    Licence: %s" % offered)
        if pkg.get("repository"):
            w("    Source:  %s" % pkg["repository"])
        for line in copyrights_for(pkg):
            w("    %s" % line)
        w("")

    # Third-party code carried INSIDE this project's own crates. Not a
    # dependency, so the graph above cannot see it; the licence still asks
    # for its notice to travel with every copy.
    w("Code derived from third-party sources, inside this project's crates:")
    w("")
    for name, version, licence, where, holder in DERIVED_CODE:
        w("%s %s  (%s)" % (name, version, licence))
        w("    Ported into: %s" % where)
        w("    %s" % holder)
        w("")

    # ---- everything else -------------------------------------------------
    w("")
    w("-" * 76)
    w("2. Python components bundled with the application")
    w("-" * 76)
    w("")
    w("Exactly the packages the APK's pip block installs (pinned in")
    w("android/app/build.gradle.kts), plus the CPython runtime Chaquopy")
    w("ships with its native libraries. Licence texts are reproduced from")
    w("each package's own distribution (third_party/python/). Nothing else")
    w("Python is bundled: aiodns, cryptography and argon2-cffi are not in the")
    w("APK. See LICENSING_AUDIT.md §3.")
    w("")
    for name, ver, lic, holder in (
        ("CPython (via Chaquopy, target 3.12.12-0)", "3.12", "PSF-2.0",
         "Copyright (c) 2001-2026 Python Software Foundation. "
         "All Rights Reserved."),
        ("OpenSSL (libcrypto/libssl shipped with Chaquopy's CPython)", "3.x",
         "Apache-2.0",
         "Copyright (c) 1998-2026 The OpenSSL Project Authors"),
        ("SQLite (libsqlite3 shipped with Chaquopy's CPython)", "3.x",
         "blessing (public domain)",
         "The SQLite authors have dedicated the code to the public domain"),
    ):
        w("%s %s" % (name, ver))
        w("    Licence: %s" % lic)
        w("    %s" % holder)
        w("")
    tp = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "third_party", "python")
    for name, ver, lic in (
        ("slixmpp", "1.17.0", "MIT"),
        ("PySocks", "1.7.1", "BSD-3-Clause"),
        ("pyasn1", "0.6.4", "BSD-2-Clause"),
        ("pyasn1-modules", "0.4.2", "BSD-2-Clause"),
    ):
        w("%s %s" % (name, ver))
        w("    Licence: %s" % lic)
        w("")
        with open(os.path.join(tp, name, "LICENSE"), encoding="utf-8") as fh:
            for line in fh.read().rstrip("\n").split("\n"):
                w(("    " + line).rstrip())
        w("")

    w("")
    w("-" * 76)
    w("3. Android / JVM components (when an APK is built)")
    w("-" * 76)
    w("")
    w("Shipped inside the APK. Test-only dependencies (JUnit, Espresso,")
    w("Hamcrest) are NOT in the artifact and are not attributed. See")
    w("LICENSING_AUDIT.md §4.")
    w("")
    for name, lic, holder in (
        ("Chaquopy (Gradle plugin and runtime)", "MIT",
         "Copyright (c) Chaquo Ltd"),
        ("Kotlin standard library", "Apache-2.0",
         "Copyright 2010-2026 JetBrains s.r.o. and Kotlin Programming "
         "Language contributors"),
        ("AndroidX (Core KTX, Lifecycle, Activity Compose, Navigation)",
         "Apache-2.0", "Copyright (c) The Android Open Source Project"),
        ("Jetpack Compose / Material 3", "Apache-2.0",
         "Copyright (c) The Android Open Source Project"),
        ("kotlinx-coroutines", "Apache-2.0",
         "Copyright 2016-2026 JetBrains s.r.o."),
    ):
        w("%s" % name)
        w("    Licence: %s" % lic)
        w("    %s" % holder)
        w("")

    w("")
    w("-" * 76)
    w("4. Native components: the bundled I2P router")
    w("-" * 76)
    w("")
    w("The APK carries i2pd as lib/<abi>/libi2pd.so, built from pinned")
    w("source by .github/scripts/build-i2pd-android.sh, with OpenSSL and")
    w("Boost linked statically into it. zlib is Android's own and is not")
    w("bundled.")
    w("")
    for name, ver, lic, holder, src in (
        ("i2pd", "2.59.0", "BSD-3-Clause",
         "Copyright (c) 2013-2026, The PurpleI2P Project",
         "https://github.com/PurpleI2P/i2pd"),
        ("OpenSSL (linked into i2pd)", "3.5.9", "Apache-2.0",
         "Copyright (c) 1998-2026 The OpenSSL Project Authors",
         "https://github.com/openssl/openssl"),
        ("Boost (filesystem, program_options, atomic and headers; linked "
         "into i2pd)", "1.88.0", "BSL-1.0",
         "Copyright the Boost authors; see each library",
         "https://github.com/boostorg/boost"),
    ):
        w("%s %s" % (name, ver))
        w("    Licence: %s" % lic)
        w("    %s" % holder)
        w("    Source:  %s" % src)
        w("")

    # ---- full licence texts ---------------------------------------------
    used = set()
    for pkg in pkgs:
        used.update(chosen_licence(pkg.get("license")))
    # The bundled non-Rust components, whose licences are named in the
    # sections above rather than read from a graph.
    used.update(["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "PSF-2.0",
                 "BSL-1.0"])

    w("")
    w("-" * 76)
    w("5. Full licence texts")
    w("-" * 76)
    w("")
    w("Reproduced because MIT, BSD and Apache-2.0 each require the licence")
    w("text itself to accompany the distribution, not merely its name.")
    w("")
    missing = []
    for spdx in sorted(used):
        text = licence_text(spdx) or exception_text(spdx)
        if text is None:
            missing.append(spdx)
            continue
        w("")
        w("=" * 76)
        w(spdx)
        w("=" * 76)
        w("")
        w(text)
        w("")
    if missing:
        w("")
        w("The full text of the following was not available to the generator")
        w("and must be added before distribution: %s" % ", ".join(missing))
        w("")

    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()

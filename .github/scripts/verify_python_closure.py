#!/usr/bin/env python3
"""The APK's pip list must be the whole dependency closure.

WHY THIS EXISTS
---------------
`android/app/build.gradle.kts` sets `options("--no-deps")`, because slixmpp
declares `aiodns` as a hard requirement and aiodns pulls pycares, which
compiles c-ares from source -- something Chaquopy cannot do.  pip offers no way
to drop one dependency, so the only lever is to turn resolution off entirely
and name every distribution by hand.

That trade has one sharp edge.  With resolution on, a missing dependency is a
build failure.  With it off, a missing dependency is an ImportError on a
handset, discovered by a user.  slixmpp adding a pure-Python dependency in some
future release would be exactly that: the APK builds, ships, and dies at
`import slixmpp`.

So this re-resolves the declared roots WITH dependencies on the runner and
fails if anything came back that the build file does not name.  It is the check
that `--no-deps` switched off, moved somewhere it can still run.

WHY RESOLVING ON THE RUNNER IS A FAIR PROXY
-------------------------------------------
Environment markers are evaluated against the machine doing the install, not
the target: Chaquopy passes pip `--platform android_...`, which selects wheel
tags and nothing else.  Both this script and Chaquopy's pip therefore see the
same `sys_platform == "linux"`, so they see the same dependency edges.  What
differs is which wheel satisfies an edge, and that is not what is being checked
here.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

GRADLE = os.path.join("android", "app", "build.gradle.kts")

#: Dependencies deliberately left out, and why.  Anything resolved that is not
#: declared and not named here is a finding.
EXCLUDED_BY_DESIGN = {
    "aiodns": "optional in slixmpp (AIODNS_AVAILABLE); this client only ever "
              "connects to 127.0.0.1 via the SAM bridge, so there is no SRV "
              "lookup to lose",
    "pycares": "required by aiodns; compiles c-ares with cmake, which "
               "Chaquopy cannot do",
}

#: Declared packages that no public index can resolve, so they cannot be used
#: as roots here.  They still have to be DECLARED, which is asserted below, so
#: this set cannot quietly become a way to hide a package from the check.
#:
#: Neither has Python dependencies of its own -- otrv4_core is a PyO3 extension
#: and chaquopy-libffi is a packaged C library -- so nothing is lost by not
#: resolving them.  A pure-Python dependency appearing on either would be
#: invisible to this check, which is the one gap in it.
NOT_ON_ANY_PUBLIC_INDEX = {
    "otrv4-core": "the Rust core, built from Rust/ into android/app/wheels "
                  "by the `rust` job",
    "chaquopy-libffi": "Chaquopy's packaging of libffi, required by its cffi "
                       "wheel",
}


def normalise(name):
    """PEP 503 name normalisation, so pyasn1_modules == pyasn1-modules."""
    return re.sub(r"[-_.]+", "-", name).lower()


def pip_block(source):
    """The body of the `pip { ... }` block, with // comments stripped.

    Comments come out first: the block carries a long explanation of why
    --no-deps is set, and that explanation quotes `install("aiodns")`.
    """
    start = source.index("pip {")
    depth, end = 0, None
    for i in range(start, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end is None:
        raise SystemExit("could not find the end of the pip block in " + GRADLE)
    return re.sub(r"//[^\n]*", "", source[start:end])


def declared(block):
    return {normalise(m) for m in re.findall(r'install\(\s*"([^"]+)"', block)}


def no_deps(block):
    return bool(re.search(r'options\([^)]*"--no-deps"', block))


def resolve(roots):
    """What pip installs for `roots` with dependency resolution ON."""
    with tempfile.TemporaryDirectory() as tmp:
        report = os.path.join(tmp, "report.json")
        cmd = [sys.executable, "-m", "pip", "install",
               "--dry-run", "--ignore-installed", "--quiet",
               "--retries", "5", "--timeout", "60",
               "--report", report] + sorted(roots)
        print("$ " + " ".join(cmd), flush=True)
        proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True)
        if proc.returncode != 0:
            print(proc.stdout)
            # Distinguish the two, because they mean opposite things. pip says
            # the same "exit 1" whether the index refused a name -- a real
            # finding about the build file -- or the connection died, which
            # says nothing about the build file at all. Reporting a read
            # timeout as "the APK asks for something that no longer exists"
            # would send someone editing a file that is fine.
            resolution_failed = any(
                marker in proc.stdout for marker in (
                    "No matching distribution",
                    "Could not find a version that satisfies",
                    "ResolutionImpossible",
                    "ERROR: Cannot install",
                ))
            if resolution_failed:
                raise SystemExit(
                    "pip could not resolve the declared roots. That is a "
                    "finding: the APK asks for something the index will not "
                    "give it.")
            raise SystemExit(
                "pip failed before it finished resolving, and not because a "
                "requirement was unsatisfiable -- see the output above; a "
                "read timeout or a DNS failure means the runner could not "
                "reach the index, which says nothing about the build file. "
                "Re-run the job.")
        with open(report) as f:
            data = json.load(f)
    return {normalise(item["metadata"]["name"]) for item in data["install"]}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--gradle", default=GRADLE)
    args = ap.parse_args()

    with open(args.gradle) as f:
        block = pip_block(f.read())

    names = declared(block)
    if not names:
        raise SystemExit("no install(...) lines found in " + args.gradle)

    print("declared: %s" % ", ".join(sorted(names)))

    if not no_deps(block):
        print("\n--no-deps is not set, so pip resolves the closure itself and "
              "a missing dependency is already a build failure. Nothing to "
              "check here.")
        return 0

    for name, why in NOT_ON_ANY_PUBLIC_INDEX.items():
        if normalise(name) not in names:
            raise SystemExit(
                "%s is listed as unresolvable from a public index (%s) but "
                "is not declared in %s. Remove it from "
                "NOT_ON_ANY_PUBLIC_INDEX rather than leaving a name here "
                "that excuses a package from the check."
                % (name, why, args.gradle))

    roots = names - {normalise(n) for n in NOT_ON_ANY_PUBLIC_INDEX}
    resolved = resolve(roots)
    print("resolved: %s" % ", ".join(sorted(resolved)))

    excluded = {normalise(n) for n in EXCLUDED_BY_DESIGN}
    missing = sorted(resolved - names - excluded)

    # An exclusion that no longer appears is not an error -- the dependency may
    # simply have gone away upstream -- but it is worth saying, because the
    # long comment in the build file explaining it has then gone stale.
    for name in sorted(excluded - resolved):
        print("note: %s is excluded by design but nothing asks for it any "
              "more; the comment in %s can go." % (name, args.gradle))

    if missing:
        print("\n::error::the APK's pip list is not the full closure")
        for name in missing:
            print("  %s is required but never installed, because --no-deps is "
                  "set and nothing declares it" % name)
        print("\nAdd each of them to the pip block in %s, or -- if it is "
              "deliberately left out -- to EXCLUDED_BY_DESIGN in %s with the "
              "reason." % (args.gradle, __file__))
        return 1

    print("\nthe pip list is the full closure: %d declared, %d resolved, "
          "%d excluded by design"
          % (len(names), len(resolved), len(excluded & resolved)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

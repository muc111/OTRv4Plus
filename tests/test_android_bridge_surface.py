# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Things about the Chaquopy bridge that only a compiler used to catch.

`ChaquopyOtrCore.kt` imports Chaquopy, which pulls in the Android Gradle
Plugin, which is served from `dl.google.com` -- blocked here. So this one file
cannot be compiled outside CI, and CI has now twice been the first compiler to
see an error in it:

  * `?: return` in an expression body ("Returns are prohibited for functions
    with an expression body"), and
  * a SECOND `removeContact(String)` added beside an existing one, because the
    search that concluded there was no Kotlin caller looked for the PYTHON
    name `remove_contact`. Conflicting overloads, plus three downstream
    ambiguity errors in `ChatViewModel`.

Neither needed a compiler to catch -- only someone looking. These tests look,
by parsing the source, so the round trip through CI is not the first signal.

They are deliberately shallow. This is not a Kotlin parser and must not grow
into one; it checks the two shapes that have actually cost a red build.
"""

import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

BRIDGE_DIR = os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                          "otrv4plus", "android", "bridge")

pytestmark = pytest.mark.skipif(
    not os.path.isdir(BRIDGE_DIR),
    reason="no android/ project in this checkout")


def kotlin_files():
    out = []
    for name in sorted(os.listdir(BRIDGE_DIR)):
        if name.endswith(".kt"):
            with open(os.path.join(BRIDGE_DIR, name), encoding="utf-8") as fh:
                out.append((name, fh.read()))
    return out


def strip_comments(src):
    """Block and line comments out, so a signature quoted in a docstring-style
    comment is not mistaken for a declaration. This matters: the fix for the
    duplicate DESCRIBES the signature it replaced."""
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


#: A CLASS-LEVEL `fun name(` with its parameter list.
#:
#: Anchored to exactly four spaces of indentation, which is what discriminates
#: a member from a local function. That matters and is not pedantry: this file
#: declares `fun str(k: String)` INSIDE two different methods, and those do not
#: conflict with each other because they are in different scopes. A check that
#: flagged them would be a false alarm, and a false alarm is how a guard gets
#: switched off.
_MEMBER_FUN = re.compile(
    r"^    (?:(?:private|internal|public|inline|suspend|open|override)\s+)*"
    r"fun\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)",
    re.M | re.S)


def declarations(src):
    """(name, arity) for each class-level function, comments removed.

    Arity counts top-level commas in the parameter list, which is wrong for a
    parameter whose default value contains a comma. That is acceptable: a
    miscount can only make two declarations look DIFFERENT, so the check
    stays a check and never becomes a false alarm.
    """
    out = []
    for match in _MEMBER_FUN.finditer(strip_comments(src)):
        params = match.group(2).strip()
        arity = 0 if not params else params.count(",") + 1
        out.append((match.group(1), arity))
    return out


class TestNoConflictingOverloads:
    """THE DEFECT. Two `removeContact(String)` in one class: one returning
    `RosterResult`, one returning `Unit`. Kotlin rejects overloads that differ
    only by return type, and the three errors it produced in `ChatViewModel`
    named type inference rather than the duplicate that caused them.
    """

    def test_no_file_declares_the_same_signature_twice(self):
        for name, src in kotlin_files():
            seen = {}
            for fname, arity in declarations(src):
                seen.setdefault((fname, arity), 0)
                seen[(fname, arity)] += 1
            duplicates = sorted(k for k, n in seen.items() if n > 1)
            assert not duplicates, (
                "%s declares %s more than once. Kotlin cannot overload on "
                "return type alone, and the compiler reports it as type "
                "inference failures at the CALL sites." % (name, duplicates))

    def test_remove_contact_specifically_is_declared_once(self):
        """Named, because this is the one that shipped."""
        for name, src in kotlin_files():
            found = [d for d in declarations(src) if d[0] == "removeContact"]
            assert len(found) <= 1, "%s declares removeContact twice" % name

    def test_the_roster_calls_all_return_their_answer(self):
        """`ConnectionController` answers every roster call with
        `{ok, code, detail}`, including refusals written for a person. A
        Kotlin wrapper returning Unit throws that away, which on a handset
        reads as the button doing nothing -- the exact report that led to
        `addContact` being changed."""
        src = strip_comments(
            dict(kotlin_files())["ChaquopyOtrCore.kt"])
        for call in ("addContact", "removeContact", "answerSubscription"):
            match = re.search(
                r"\bfun\s+%s\s*\([^)]*\)\s*:\s*([A-Za-z]+)" % call, src)
            assert match, "%s is missing or declares no return type" % call
            assert match.group(1) == "RosterResult", (
                "%s returns %s; the controller's {ok, code, detail} is "
                "discarded" % (call, match.group(1)))


class TestNoReturnInAnExpressionBody:
    """THE OTHER ONE. `fun f() = x ?: return y` does not compile: "Returns are
    prohibited for functions with an expression body". It cost a CI round trip
    in `leaveRoom` and `destroyRoom`."""

    #: `fun ... = <expr>` on one line, where the expression contains `return`.
    _EXPR_RETURN = re.compile(
        r"\bfun\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*\)[^=\n{]*=\s*[^\n]*\breturn\b")

    def test_no_expression_body_contains_a_return(self):
        for name, src in kotlin_files():
            hits = self._EXPR_RETURN.findall(strip_comments(src))
            assert not hits, (
                "%s has an expression-bodied function containing `return`, "
                "which Kotlin rejects: %r" % (name, hits))

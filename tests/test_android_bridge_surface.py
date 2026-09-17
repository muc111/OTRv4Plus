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

MAIN_DIR = os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                        "otrv4plus", "android")
BRIDGE_DIR = os.path.join(MAIN_DIR, "bridge")

pytestmark = pytest.mark.skipif(
    not os.path.isdir(BRIDGE_DIR),
    reason="no android/ project in this checkout")


def kotlin_files(directory=None):
    """Every Kotlin source under *directory*, defaulting to the whole app.

    WIDENED FROM `bridge/` DELIBERATELY. The bridge is the file that cannot be
    compiled locally, but it is not the only one: `ChatViewModel` and every
    screen import Compose and AndroidX, which come from the same blocked
    `dl.google.com`. Roughly half the Kotlin in this project is first compiled
    by CI, so the checks that need no compiler should cover all of it.
    """
    root = directory or MAIN_DIR
    out = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in sorted(filenames):
            if not name.endswith(".kt"):
                continue
            path = os.path.join(dirpath, name)
            label = os.path.relpath(path, root)
            with open(path, encoding="utf-8") as fh:
                out.append((label, fh.read()))
    return sorted(out)


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


#: A TOP-LEVEL type declaration, at column zero.
_TOP_TYPE = re.compile(
    r"^(?:(?:private|internal|public|abstract|sealed|open|data|value|"
    r"annotation|enum)\s+)*(?:class|interface|object)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)",
    re.M)


def declarations(src):
    """(type, name, arity) for each class-level function, comments removed.

    SCOPED PER TYPE, not per file, and that is not a nicety. `MessageStore.kt`
    declares an interface and the class implementing it in one file, so
    `append`, `clear`, `messages` and five more each appear twice at four
    spaces of indentation -- in DIFFERENT type bodies, where they are an
    interface method and its override rather than conflicting overloads.
    Reporting those would be a false alarm, and a false alarm is how a guard
    gets switched off. (The first version of this file made the same mistake
    one level down, with local `fun str` inside two methods.)

    Arity counts top-level commas in the parameter list, which is wrong for a
    parameter whose default value contains a comma. That is acceptable: a
    miscount can only make two declarations look DIFFERENT, so the check
    stays a check and never becomes a false alarm.
    """
    text = strip_comments(src)
    # Where each top-level type begins, so a function can be attributed to one.
    starts = [(m.start(), m.group(1)) for m in _TOP_TYPE.finditer(text)]

    def enclosing(pos):
        found = "<file>"
        for start, name in starts:
            if start <= pos:
                found = name
            else:
                break
        return found

    out = []
    for match in _MEMBER_FUN.finditer(text):
        params = match.group(2).strip()
        arity = 0 if not params else params.count(",") + 1
        out.append((enclosing(match.start()), match.group(1), arity))
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
            for tname, fname, arity in declarations(src):
                seen.setdefault((tname, fname, arity), 0)
                seen[(tname, fname, arity)] += 1
            duplicates = sorted(k for k, n in seen.items() if n > 1)
            assert not duplicates, (
                "%s declares %s more than once. Kotlin cannot overload on "
                "return type alone, and the compiler reports it as type "
                "inference failures at the CALL sites." % (name, duplicates))

    def test_remove_contact_specifically_is_declared_once(self):
        """Named, because this is the one that shipped."""
        for name, src in kotlin_files(BRIDGE_DIR):
            found = [d for d in declarations(src) if d[1] == "removeContact"]
            assert len(found) <= 1, "%s declares removeContact twice" % name

    def test_the_roster_calls_all_return_their_answer(self):
        """`ConnectionController` answers every roster call with
        `{ok, code, detail}`, including refusals written for a person. A
        Kotlin wrapper returning Unit throws that away, which on a handset
        reads as the button doing nothing -- the exact report that led to
        `addContact` being changed."""
        src = strip_comments(
            dict(kotlin_files(BRIDGE_DIR))["ChaquopyOtrCore.kt"])
        for call in ("addContact", "removeContact", "answerSubscription"):
            match = re.search(
                r"\bfun\s+%s\s*\([^)]*\)\s*:\s*([A-Za-z]+)" % call, src)
            assert match, "%s is missing or declares no return type" % call
            assert match.group(1) == "RosterResult", (
                "%s returns %s; the controller's {ok, code, detail} is "
                "discarded" % (call, match.group(1)))


class TestNoAnnotationIsAppliedTwice:
    """THE THIRD ONE CI CAUGHT FIRST.

        ConversationScreen.kt:227:1 This annotation is not repeatable.

    An edit anchored on `private fun SecurityLine(...)` inserted a new
    composable above it and carried its own `@Composable`, leaving the
    original one stranded on the line before -- so the file read

        @Composable
        /** doc for the new function */
        @Composable
        private fun EncryptionOffer(...)

    Kotlin rejects a repeated non-repeatable annotation. Nothing needed a
    compiler to see it; the two were four lines apart.

    The KDoc between them is why a naive "two identical lines in a row" check
    would miss it, and why this one steps over comments.
    """

    _ANNOTATION = re.compile(r"^\s*(@[A-Za-z_][A-Za-z0-9_]*)", re.M)

    def test_no_annotation_appears_twice_before_one_declaration(self):
        for name, src in kotlin_files():
            stripped = strip_comments(src)
            # Annotations that survive with only blank lines between them are
            # applied to the same declaration.
            run = []
            for line in stripped.splitlines():
                text = line.strip()
                if not text:
                    continue
                match = self._ANNOTATION.match(line)
                if match:
                    run.append(match.group(1).split("(")[0])
                    duplicates = [a for a in set(run) if run.count(a) > 1]
                    assert not duplicates, (
                        "%s applies %s twice to one declaration -- Kotlin "
                        "rejects a repeated non-repeatable annotation, and "
                        "reports it at the SECOND one" % (name, duplicates))
                else:
                    run = []


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

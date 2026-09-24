"""Kotlin's event mapping must match Python's event classes.

Written immediately after getting three of them wrong in one sitting:
`SmpProgressed` for a class called `SmpProgress`, `SmpFinished` for one called
`SmpResult`, and `stored`/`received` for fields called `stored_fingerprint`
and `received_fingerprint`. None of it would have failed to compile. The
`when` would simply have fallen through to `else -> null`, and SMP progress
and fingerprint-change warnings would have been silently absent from a screen
whose entire job is to show them.

That is the same shape as the two bugs that cost handset round trips earlier:
`connect(address=...)` and the missing SSL context. Kotlin cannot see Python's
names, so nothing but a test can hold the two together.

This parses the Kotlin source rather than running it, so it needs no Android
SDK and runs in the ordinary suite.
"""

import dataclasses
import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

BRIDGE = os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                      "otrv4plus", "android", "bridge", "ChaquopyOtrCore.kt")

pytestmark = pytest.mark.skipif(
    not os.path.exists(BRIDGE),
    reason="no android/ project in this checkout")

#: Python event classes the Kotlin side deliberately does not map, with why.
#: An entry here is a decision; an absence is a bug.
NOT_MAPPED = {
    # Base class, never emitted on its own.
    "Event": "abstract base",
    # A receipt for something already on screen. There is no Kotlin event for
    # it yet and inventing one would be worse than skipping it.
    "MessageDelivered": "no Kotlin event yet; skipped explicitly",
}


def python_events():
    import android_bridge.events as ev
    out = {}
    for name in ev.__all__:
        obj = getattr(ev, name, None)
        if dataclasses.is_dataclass(obj):
            out[name] = [f.name for f in dataclasses.fields(obj)]
    return out


def kotlin_source():
    with open(BRIDGE, encoding="utf-8") as fh:
        return fh.read()


def mapped_type_names():
    """The string literals the `when (str("type"))` actually branches on."""
    src = kotlin_source()
    start = src.index("private fun eventFrom(")
    body = src[start:]
    # Branch heads look like:  "SessionStateChanged" ->
    return set(re.findall(r'"([A-Za-z_][A-Za-z0-9_]*)"\s*->', body))


class TestEveryPythonEventIsAccountedFor:

    def test_no_event_class_is_silently_unmapped(self):
        mapped = mapped_type_names()
        missing = [n for n in python_events()
                   if n not in mapped and n not in NOT_MAPPED]
        assert not missing, (
            "these Python events reach Kotlin and fall through to `else -> "
            "null`, so the screen never sees them: %r. Map them, or add them "
            "to NOT_MAPPED with a reason." % (missing,))

    def test_the_not_mapped_list_has_not_gone_stale(self):
        known = set(python_events()) | {"Event"}
        for name in NOT_MAPPED:
            assert name in known, (
                "%s is listed as deliberately unmapped but no longer exists "
                "in android_bridge.events" % name)

    def test_kotlin_does_not_branch_on_a_type_python_never_emits(self):
        """The original bug: branches named for classes that do not exist.

        They compile, they never match, and the feature is quietly absent.
        """
        known = set(python_events()) | set(NOT_MAPPED)
        # Field-name literals appear in the same function; only consider
        # strings that look like event class names (CapWords).
        suspects = {n for n in mapped_type_names()
                    if n[:1].isupper() and "_" not in n}
        unknown = sorted(suspects - known)
        assert not unknown, (
            "Kotlin branches on %r, which android_bridge.events does not "
            "emit. A branch that never matches is a feature that never "
            "appears." % (unknown,))


class TestTheFieldNamesMatch:
    """A wrong field name yields an empty string, not an error: a fingerprint
    warning with two blank fingerprints, which is worse than none."""

    def _fields_read_for(self, type_name):
        src = kotlin_source()
        start = src.index('"%s" ->' % type_name)
        # Up to the next branch head.
        rest = src[start + len(type_name) + 5:]
        end = re.search(r'\n\s+"[A-Za-z]', rest)
        block = rest[:end.start()] if end else rest[:400]
        return set(re.findall(r'(?:str|num|int)\("([a-z_]+)"\)', block))

    @pytest.mark.parametrize("type_name", [
        "SessionStateChanged", "MessageReceived", "SmpProgress",
        "SmpResult", "FingerprintChanged", "CallStateChanged",
        "ErrorOccurred", "ConnectionStateChanged", "SubscriptionRequested",
    ])
    def test_every_field_read_exists_on_the_python_class(self, type_name):
        events = python_events()
        if type_name not in events:
            pytest.fail("%s is not a Python event class" % type_name)
        real = set(events[type_name])
        # eventlog adds `_level` alongside an int-valued enum, and `seq`.
        allowed = real | {f + "_level" for f in real} | {"seq", "type"}
        read = self._fields_read_for(type_name)
        unknown = sorted(read - allowed)
        assert not unknown, (
            "%s reads %r, which the Python class does not have. A wrong field "
            "name reads back as an empty string rather than failing: %r"
            % (type_name, unknown, sorted(real)))

    def test_the_fingerprint_fields_are_the_long_names(self):
        """The specific one that was wrong. A fingerprint-change warning is a
        blocking, security-relevant dialog; showing it with two blank
        fingerprints is worse than not showing it."""
        read = self._fields_read_for("FingerprintChanged")
        assert "stored_fingerprint" in read
        assert "received_fingerprint" in read

    def test_the_subscription_policy_reaches_kotlin(self):
        """Without `policy` the screen cannot tell "they want to see you" from
        "they can now see you", and would offer a choice already made."""
        read = self._fields_read_for("SubscriptionRequested")
        assert "policy" in read
        assert "peer" in read

    def test_the_security_level_is_read_as_a_number(self):
        """Kotlin's SecurityState.fromLevel takes the engine's integer. Reading
        the NAME and passing it to fromLevel would not compile; reading the
        name and mapping by string would drift from the engine."""
        read = self._fields_read_for("SessionStateChanged")
        assert "security_level" in read

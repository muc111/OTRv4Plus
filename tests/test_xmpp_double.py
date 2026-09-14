"""The test double must be collectable, and must still be needed.

Three tests, and the second one matters as much as the first.

The first proves ``xmpp_double.bare_client`` does its job: an object it builds
can be garbage collected without ``XMLStream.__del__`` raising.

The second proves the job still exists. A workaround for someone else's code is
a liability once that code changes -- it keeps being carried, nobody remembers
why, and it slowly becomes folklore. So this asserts that the *unpatched*
construction really does raise. If slixmpp ever gives ``_run_out_filters`` a
class-level default, or drops ``__del__``, that test fails and says so, and
``xmpp_double`` can be deleted rather than inherited.

The first two go through ``slixmpp.ClientXMPP`` rather than
``OTRv4PlusXMPP``. The behaviour being worked around is entirely upstream's --
it is reached through inheritance and has nothing to do with this project's
code -- and testing it at its source means these run anywhere slixmpp is
installed, including hosts without the built Rust core. The third then closes
the gap by checking that ``OTRv4PlusXMPP`` really does inherit that destructor
rather than defining one of its own.

All of them go through ``sys.unraisablehook``, because that is where the
failure actually surfaces: an exception raised in ``__del__`` cannot propagate
to the caller, so asserting on it any other way would be asserting on nothing.
"""

import gc
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from xmpp_double import bare_client

slixmpp = pytest.importorskip("slixmpp")


class _Collector:
    """Records unraisable exceptions instead of letting them print."""

    def __enter__(self):
        self.seen = []
        self._prev = sys.unraisablehook
        sys.unraisablehook = self.seen.append
        return self

    def __exit__(self, *exc):
        sys.unraisablehook = self._prev
        return False


def _collect(make):
    """Build an object with *make*, drop it, and return what __del__ raised."""
    with _Collector() as c:
        obj = make()
        del obj
        # CPython refcounting usually finalizes at `del`, but say so explicitly:
        # this must not depend on when a cycle collector happens to run.
        gc.collect()
    return [u.exc_type for u in c.seen]


class TestTheDouble:

    def test_it_can_be_collected_without_raising(self):
        raised = _collect(lambda: bare_client(slixmpp.ClientXMPP))
        assert raised == [], (
            "collecting the double raised %r inside __del__; that is the "
            "PytestUnraisableExceptionWarning this helper exists to stop"
            % (raised,))

    def test_the_workaround_is_still_necessary(self):
        """Delete xmpp_double when this fails -- do not 'fix' it."""
        cls = slixmpp.ClientXMPP
        raised = _collect(lambda: cls.__new__(cls))
        assert AttributeError in raised, (
            "a plain __new__ no longer raises in __del__. slixmpp has "
            "changed, so xmpp_double.bare_client is now dead weight: remove "
            "it and call __new__ directly again.")


class TestTheClientUnderTestIsTheSameShape:

    def test_it_inherits_the_destructor_rather_than_defining_one(self):
        """The double is only faithful if OTRv4PlusXMPP adds no __del__.

        If this project ever grows its own finalizer, the two tests above stop
        describing what the doubles actually do at collection time, and this
        file has to be rewritten against the real class.
        """
        # A plain try/except rather than pytest.importorskip, because both
        # outcomes are wanted here. otrv4plus_xmpp raises DependencyMissing
        # (a ModuleNotFoundError) when the core is absent, which importorskip
        # would skip on, but DependencyUnavailable (a plain ImportError) when
        # the core is present and broken, which it would not -- and this test
        # has nothing to say about either case. On a host with the core built
        # the import simply succeeds.
        try:
            import otrv4plus_xmpp as xmpp
        except ImportError as exc:
            pytest.skip("otrv4plus_xmpp needs the OTR engine: %s" % exc)
        cls = xmpp.OTRv4PlusXMPP
        assert "__del__" not in vars(cls)
        owner = next(k for k in cls.__mro__ if "__del__" in vars(k))
        assert owner is slixmpp.xmlstream.XMLStream, (
            "__del__ now comes from %r, not XMLStream" % (owner,))

"""A bare OTRv4PlusXMPP that never ran slixmpp's constructor.

Twelve call sites across five test modules want to exercise one method of
``OTRv4PlusXMPP`` -- a JID check, a pacing calculation, the way a secret is
prompted for -- without an event loop, a socket, or a server. They all reached
for the same trick::

    client = xmpp.OTRv4PlusXMPP.__new__(xmpp.OTRv4PlusXMPP)

which is the right instinct: ``__init__`` chains up through ``ClientXMPP`` into
``XMLStream.__init__``, and none of what that builds is wanted here.

It has one consequence, and it is not obvious. ``XMLStream`` declares::

    _run_out_filters: Future | None          # annotation only, no value

and assigns it in ``__init__``::

    self._run_out_filters = None

``__new__`` skips that assignment, and because the declaration is a bare
annotation there is no class attribute to fall back on. Meanwhile the
inherited destructor is::

    def __del__(self) -> None:
        if self._run_out_filters is not None:
            self._run_out_filters.cancel()

So every one of these objects raises ``AttributeError`` when the garbage
collector finally reaches it. Exceptions in ``__del__`` cannot propagate --
Python hands them to ``sys.unraisablehook`` -- so nothing fails; pytest's
unraisable plugin records a ``PytestUnraisableExceptionWarning`` instead. On a
full run that was eighteen warnings, and they were attributed to whichever test
happened to be running when collection occurred rather than to the test that
built the object. One of them was blamed on ``test_final_boss.py``, which does
not import the XMPP module at all.

This is a defect in the test doubles and nowhere else. Production never reaches
it: ``OTRv4PlusXMPP.__init__`` calls ``super().__init__(jid, password)``, so a
real client has the attribute from the first line of its life.

The fix is one assignment, and ``None`` rather than a cancellable stand-in --
``__del__`` then takes the false branch and there is no task to cancel, which
is exactly the state a client that never started its filters should be in.

Verified against slixmpp 1.17.0: ``XMLStream.__del__`` is the only ``__del__``
anywhere in the package, and ``_run_out_filters`` is the only attribute it
touches.
"""

__all__ = ["bare_client"]


def bare_client(cls):
    """Return an instance of *cls* with no slixmpp constructor run.

    *cls* is passed in rather than imported here because the modules under test
    load the XMPP module in several different ways -- some re-import it under a
    patched environment -- and this helper must not become a thirteenth opinion
    about which module object is the real one.

    The caller sets whatever state its own test needs. All this guarantees is
    that the object can be collected without raising.
    """
    obj = cls.__new__(cls)
    # See the module docstring: XMLStream.__del__ reads this, XMLStream.__init__
    # is what normally sets it, and __new__ skipped __init__.
    obj._run_out_filters = None
    return obj

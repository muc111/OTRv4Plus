"""A rejected password asks again instead of ending the session.

failed_auth used to set _shutting_down and that was the end of it. Over I2P a
typo therefore cost the whole session plus another 30-90 s tunnel build to get
back, which is a bad trade for a keystroke.

Retrying is not simply "reconnect": reconnecting with the SAME password loops
against the server forever, which is why the old code refused to. So the
reconnect loop stays blocked until a password the user actually typed arrives,
and only then is it released.

The other half is where the password is typed. In plain mode the reader owns
stdin and swaps in getpass, so it is never echoed. The TUI draws and echoes
its own input line, so a password typed there would be on screen and in any
terminal capture -- that mode reports the failure rather than leaking it.
"""

import asyncio
import types

import pytest

pytest.importorskip("slixmpp")
import otrv4plus_xmpp as xmpp


class _FakeClient:
    """Only the surface the auth-retry path touches."""

    MAX_AUTH_ATTEMPTS = xmpp.OTRv4PlusXMPP.MAX_AUTH_ATTEMPTS
    _on_failed_auth = xmpp.OTRv4PlusXMPP._on_failed_auth
    _can_prompt_for_password = xmpp.OTRv4PlusXMPP._can_prompt_for_password
    supply_password = xmpp.OTRv4PlusXMPP.supply_password
    _schedule_reconnect = xmpp.OTRv4PlusXMPP._schedule_reconnect
    _has_transport_params = xmpp.OTRv4PlusXMPP._has_transport_params

    def __init__(self, tui=False, tty=True):
        self._shutting_down = False
        self._auth_failures = 0
        self._password_prompt = None
        self._own_bare = "bob@example.i2p"
        self._tui_enabled = tui
        self._tty = tty
        self._reconnect_delay = 5
        self._reconnect_task = None
        self._sam_params = {"server_b32": "x", "dest_port": 5222,
                            "sam_host": "127.0.0.1", "sam_port": 7656}
        self._tor_params = None
        self.password = "wrong"
        self.disconnects = 0
        self.scheduled = []

    def disconnect(self):
        self.disconnects += 1

    async def _reconnect(self):
        """Stand-in for the real loop: the test cares that it was started."""
        return None


@pytest.fixture(autouse=True)
def _isatty(monkeypatch):
    monkeypatch.setattr(xmpp.sys.stdin, "isatty", lambda: True, raising=False)


def _client(**kw):
    """A client running the REAL _schedule_reconnect.

    An earlier version of this file replaced the scheduler with a lambda that
    re-implemented the guard, so the tests passed with the production guard
    deleted. Only the real one proves anything, so the loop it would create
    is captured instead of the decision it makes.
    """
    client = _FakeClient(**kw)

    def _create_task(coro):
        coro.close()                      # never run; we only care that it ran
        client.scheduled.append(client._why)
        return types.SimpleNamespace(done=lambda: True)

    client._loop = types.SimpleNamespace(create_task=_create_task)
    return client


class _on_loop:
    """Lend the client a loop for whatever runs inside the block.

    _schedule_reconnect resolves the loop with asyncio.get_event_loop(),
    which in production runs on the loop thread and in a test does not.
    """

    def __init__(self, client, why=""):
        self.client, self.why = client, why

    def __enter__(self):
        self.client._why = self.why
        self.client._reconnect_task = None
        self._saved = xmpp.asyncio.get_event_loop
        xmpp.asyncio.get_event_loop = lambda: self.client._loop
        return self.client

    def __exit__(self, *exc):
        xmpp.asyncio.get_event_loop = self._saved
        return False


def _schedule(client, why):
    """Call the production scheduler with a loop it can reach."""
    with _on_loop(client, why):
        xmpp.OTRv4PlusXMPP._schedule_reconnect(client, why)


# ---------------------------------------------------------------------------
# the prompt
# ---------------------------------------------------------------------------

class TestPromptIsOffered:

    def test_a_rejected_password_does_not_end_the_session(self):
        c = _client()
        c._on_failed_auth(None)
        assert c._shutting_down is False
        assert c._password_prompt is not None

    def test_the_prompt_names_the_account(self):
        c = _client()
        c._on_failed_auth(None)
        assert "bob@example.i2p" in c._password_prompt

    def test_attempts_are_bounded(self):
        c = _client()
        for _ in range(xmpp.OTRv4PlusXMPP.MAX_AUTH_ATTEMPTS):
            c._on_failed_auth(None)
        assert c._shutting_down is True, "an infinite retry loop"

    def test_the_last_attempt_gives_up_rather_than_prompting(self):
        c = _client()
        for _ in range(xmpp.OTRv4PlusXMPP.MAX_AUTH_ATTEMPTS - 1):
            c._on_failed_auth(None)
            c._password_prompt = None          # user answered each time
        c._on_failed_auth(None)
        assert c._password_prompt is None
        assert c._shutting_down is True


# ---------------------------------------------------------------------------
# the reconnect interlock
# ---------------------------------------------------------------------------

class TestReconnectIsHeld:

    def test_no_reconnect_while_the_password_is_awaited(self):
        c = _client()
        c._on_failed_auth(None)
        _schedule(c, "disconnect")
        assert c.scheduled == [], (
            "reconnected with the password the server just rejected")

    def test_a_reconnect_is_scheduled_normally_when_none_is_awaited(self):
        # The counterpart: the guard must block this case and only this case.
        c = _client()
        _schedule(c, "disconnect")
        assert c.scheduled == ["disconnect"]

    def test_supplying_a_password_releases_it(self):
        c = _client()
        c._on_failed_auth(None)
        with _on_loop(c, "password re-entered"):
            c.supply_password("correct horse")
        assert c.scheduled == ["password re-entered"], (
            "supplying a password did not resume connecting")

    def test_the_new_password_is_the_one_that_gets_used(self):
        c = _client()
        c._on_failed_auth(None)
        with _on_loop(c):
            c.supply_password("correct horse")
        assert c.password == "correct horse"

    def test_trailing_newline_is_not_part_of_the_password(self):
        c = _client()
        c._on_failed_auth(None)
        with _on_loop(c):
            c.supply_password("secret\r\n")
        assert c.password == "secret"

    def test_the_backoff_is_reset_so_the_retry_is_prompt(self):
        c = _client()
        c._reconnect_delay = 320
        c._on_failed_auth(None)
        with _on_loop(c):
            c.supply_password("secret")
        assert c._reconnect_delay == xmpp._RECONNECT_BASE

    def test_an_empty_answer_ends_the_session(self):
        c = _client()
        c._on_failed_auth(None)
        c.supply_password("")
        assert c._shutting_down is True
        assert c.disconnects == 1
        _schedule(c, "after an empty password")
        assert c.scheduled == []

    def test_a_password_supplied_with_no_prompt_is_ignored(self):
        c = _client()
        c.supply_password("stray line")
        assert c.password == "wrong"


# ---------------------------------------------------------------------------
# where the password may be typed
# ---------------------------------------------------------------------------

class TestNoEchoedPassword:

    def test_plain_mode_prompts(self):
        c = _client()
        assert c._can_prompt_for_password() is True

    def test_tui_mode_refuses_rather_than_echoing(self):
        c = _client(tui=True)
        c._on_failed_auth(None)
        assert c._password_prompt is None
        assert c._shutting_down is True

    def test_a_non_tty_refuses(self, monkeypatch):
        monkeypatch.setattr(xmpp.sys.stdin, "isatty", lambda: False,
                            raising=False)
        c = _client()
        c._on_failed_auth(None)
        assert c._password_prompt is None

    def test_the_reader_uses_getpass_not_readline(self):
        import inspect
        src = inspect.getsource(xmpp._input_loop)
        assert "getpass.getpass" in src
        assert src.index("getpass.getpass") < src.index("sys.stdin.readline")

    def test_the_reader_hands_the_line_to_supply_password(self):
        import inspect
        src = inspect.getsource(xmpp._input_loop)
        assert "client.supply_password(line)" in src

    def test_a_line_typed_before_the_prompt_appeared_is_discarded(self):
        # Otherwise a bare Enter would be read as an empty password and end
        # the session, and a typed command would leak into the password.
        import inspect
        src = inspect.getsource(xmpp._input_loop)
        after = src.split("client.supply_password(line)", 1)[1]
        assert "continue" in after

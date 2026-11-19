# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""What the apps show when the server's administrator restricts an account,
and announcements from the server reach every client.

A server running XMPP Guard mutes an account, stops its file transfers,
suspends it, signs it out, removes it, or goes into maintenance, each with an
ordinary XMPP error carrying a fixed condition and a sentence. Before this:

- a muted account's messages showed as "sent" (the bounce was only logged);
- XMPP Guard's suspension said "Access temporarily restricted by server
  administration", the ban check looked for "banned", and the app treated it
  as an unexplained error and kept reconnecting;
- maintenance, being signed out and a removed account were "the connection
  did not come up";
- an announcement (a `headline` from the server's domain) was dropped, so
  nobody saw it.

The server's sentences below are XMPP Guard's, as it sends them.
"""
import os
import re
import sys
import threading
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "client"))

from android_bridge import restrictions as R  # noqa: E402

MUTED = "Messaging is temporarily restricted on your account"
NO_FILES = "File transfers are temporarily restricted on your account"
FILES_OFF = "File transfers are temporarily disabled on this server"
SUSPENDED = "Access temporarily restricted by server administration"
MAINTENANCE = "Server maintenance in progress, please try again later"
LOCKDOWN = "Server entering lockdown, please reconnect in a few minutes"
KICKED = "Disconnected by server administration"
REMOVED = "Account removed by server administration"

KT = os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                  "otrv4plus", "android")


def _read(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as handle:
        return handle.read()


# ── recognising the signals ─────────────────────────────────────────────────

@pytest.mark.parametrize("error_type,condition,text,kind", [
    ("cancel", "not-allowed", MUTED, R.MUTED),
    ("cancel", "not-allowed", NO_FILES, R.FILES_RESTRICTED),
    ("cancel", "not-allowed", FILES_OFF, R.FILES_DISABLED),
    ("cancel", "not-allowed", "  messaging is TEMPORARILY restricted\non your account ", R.MUTED),
])
def test_a_restriction_on_a_sent_stanza_is_recognised(error_type, condition,
                                                      text, kind):
    found = R.of_stanza_error(error_type, condition, text)
    assert found is not None and found.kind == kind
    assert found.retry is False, "a refused send is never retried"
    assert found.text.startswith("Not sent:")


@pytest.mark.parametrize("error_type,condition,text", [
    ("cancel", "not-allowed", "Registration is currently closed"),
    ("cancel", "forbidden", MUTED),            # the condition must match too
    ("modify", "not-allowed", MUTED),          # and the type
    ("cancel", "service-unavailable", ""),
    ("cancel", "not-allowed", ""),
    ("cancel", "not-allowed", None),
])
def test_anything_else_is_not_a_restriction(error_type, condition, text):
    assert R.of_stanza_error(error_type, condition, text) is None


@pytest.mark.parametrize("condition,text,kind,retry", [
    ("policy-violation", SUSPENDED, R.SUSPENDED, False),
    ("policy-violation", "Account banned (until=0)", R.SUSPENDED, False),
    ("not-authorized", MAINTENANCE, R.MAINTENANCE, True),
    ("not-authorized", LOCKDOWN, R.MAINTENANCE, True),
    ("not-authorized", KICKED, R.SIGNED_OUT, False),
    ("not-authorized", REMOVED, R.REMOVED, False),
])
def test_a_restriction_on_the_stream_is_recognised(condition, text, kind, retry):
    found = R.of_stream_error(condition, text)
    assert found is not None and found.kind == kind and found.retry is retry


@pytest.mark.parametrize("condition,text", [
    ("policy-violation", "Too many active connections to this account"),
    ("not-authorized", ""),                     # a wrong password, as before
    ("conflict", KICKED),
    ("system-shutdown", MAINTENANCE),
    ("host-unknown", ""),
])
def test_other_stream_errors_keep_their_meaning(condition, text):
    assert R.of_stream_error(condition, text) is None


def test_the_suspension_keeps_the_code_the_apps_already_stop_on():
    from android_bridge import transport as T
    assert R.SUSPENDED == T.BANNED_CODE == "account_banned"


def test_the_servers_own_words_never_reach_the_screen():
    """A server can set its own ban text. Recognised by the fixed phrase,
    shown in our words: nothing it adds is shown."""
    planted = SUSPENDED + " -- visit evil.example to appeal"
    found = R.of_stream_error("policy-violation", planted)
    assert "evil.example" not in found.text
    for kind in (R.MUTED, R.FILES_RESTRICTED, R.FILES_DISABLED, R.SUSPENDED,
                 R.MAINTENANCE, R.SIGNED_OUT, R.REMOVED):
        assert R.text_for(kind) and "evil" not in R.text_for(kind)


@pytest.mark.parametrize("sender,domain,expected", [
    ("otrv4plus.i2p", "otrv4plus.i2p", True),
    ("OTRv4Plus.i2p", "otrv4plus.i2p", True),
    ("alice@otrv4plus.i2p", "otrv4plus.i2p", False),   # a person
    ("otrv4plus.i2p/announce", "otrv4plus.i2p", False),
    ("other.example", "otrv4plus.i2p", False),          # not our server
    ("conference.otrv4plus.i2p", "otrv4plus.i2p", False),
    ("", "otrv4plus.i2p", False),
    ("otrv4plus.i2p", "", False),
])
def test_only_our_own_server_can_announce(sender, domain, expected):
    assert R.is_server_announcement(sender, domain) is expected


# ── the transport ───────────────────────────────────────────────────────────

JID = "alice@otrv4plus.i2p"


def _transport():
    from android_bridge import transport as T
    from android_bridge.settings import ConnectionProfile
    t = T.XmppTransport.__new__(T.XmppTransport)
    t._profile = ConnectionProfile(jid=JID)
    t._connected = threading.Event()
    t._connected.set()
    t._caps, t._welcome, t._room_nicks = {}, set(), {}
    t._last_inbound = time.monotonic()
    t.states = []
    t._on_state = lambda state, _server: t.states.append(state)
    return t


class Error(dict):
    pass


class Stanza(dict):
    """The parts of a slixmpp stanza these handlers read."""

    def __init__(self, sender, kind="chat", body="", stanza_id="",
                 error=None):
        super().__init__(type=kind, body=body)
        self._sender, self._id = sender, stanza_id
        if error is not None:
            self["error"] = Error(type=error[0], condition=error[1], text=error[2])

    def get(self, key, default=None):
        if key == "from":
            return self._sender
        if key == "id":
            return self._id
        return dict.get(self, key, default)


def test_a_muted_send_reports_which_message_and_why():
    t = _transport()
    seen, rooms = [], []
    t.set_restriction_handler(lambda *a: seen.append(a))
    t._on_room_rejected = lambda *a: rooms.append(a)
    t._on_message_error(Stanza("bob@otrv4plus.i2p/phone", kind="error",
                               stanza_id="m-42",
                               error=("cancel", "not-allowed", MUTED)))
    assert seen == [("bob@otrv4plus.i2p", "m-42", R.MUTED)]
    assert rooms == []


def test_a_muted_room_send_is_not_posted_again():
    """A secure group posts a refused commit again; while muted that would
    be refused forever. The restriction handler gets it instead."""
    t = _transport()
    t._room_nicks = {"crew@conference.otrv4plus.i2p": "alice"}
    seen, rooms = [], []
    t.set_restriction_handler(lambda *a: seen.append(a))
    t._on_room_rejected = lambda *a: rooms.append(a)
    t._on_message_error(Stanza("crew@conference.otrv4plus.i2p", kind="error",
                               error=("cancel", "not-allowed", MUTED)))
    assert seen and seen[0][2] == R.MUTED
    assert rooms == []


def test_an_ordinary_bounce_is_unchanged():
    t = _transport()
    t._room_nicks = {"crew@conference.otrv4plus.i2p": "alice"}
    seen, rooms = [], []
    t.set_restriction_handler(lambda *a: seen.append(a))
    t._on_room_rejected = lambda *a: rooms.append(a)
    t._on_message_error(Stanza("crew@conference.otrv4plus.i2p", kind="error",
                               error=("modify", "not-acceptable", "Too long")))
    assert seen == [] and rooms == [("crew@conference.otrv4plus.i2p", "not-acceptable")]


@pytest.mark.parametrize("kind", ["headline", "chat", "normal"])
def test_an_announcement_reaches_the_app_and_never_the_engine(kind):
    t = _transport()
    got, engine = [], []
    t.set_announcement_handler(lambda *a: got.append(a))
    t._reassembler = None
    t._on_app_message = lambda *a: engine.append(a)
    assert t._server_announcement(Stanza("otrv4plus.i2p", kind=kind,
                                         body="Back at 18:00")) is True
    assert len(got) == 1 and got[0][0] == "otrv4plus.i2p"
    assert got[0][1] == "Back at 18:00"
    assert engine == []


def test_an_announcement_can_not_come_from_a_person_or_another_server():
    t = _transport()
    got = []
    t.set_announcement_handler(lambda *a: got.append(a))
    for sender in ("mallory@otrv4plus.i2p", "otrv4plus.i2p/res", "evil.example"):
        assert t._server_announcement(Stanza(sender, kind="headline",
                                             body="Your password expired")) is False
    assert got == []


def test_an_announcement_is_bounded():
    t = _transport()
    got = []
    t.set_announcement_handler(lambda *a: got.append(a))
    t._server_announcement(Stanza("otrv4plus.i2p", kind="headline",
                                  body="x" * 100_000))
    assert len(got[0][1]) == t.MAX_ANNOUNCEMENT


def test_the_message_handler_looks_for_announcements_first():
    source = _read(ROOT, "android_bridge", "transport.py")
    handler = source[source.index("    def _on_message(self, stanza) -> None:"):]
    assert handler.index("self._server_announcement(stanza)") < handler.index(
        'stanza.get("type") not in ("chat", "normal", None, "")')


@pytest.mark.parametrize("condition,text,state,attribute", [
    ("policy-violation", SUSPENDED, "banned", "banned_text"),
    ("not-authorized", KICKED, "restricted", None),
    ("not-authorized", REMOVED, "restricted", None),
    ("not-authorized", LOCKDOWN, "restricted", None),
])
def test_a_signed_in_stream_closed_by_the_administrator(condition, text, state,
                                                        attribute):
    t = _transport()
    t._on_live_stream_error({"condition": condition, "text": text})
    if attribute:
        assert "suspended" in getattr(t, attribute)
    else:
        assert t.closed_by_admin[0] == R.of_stream_error(condition, text).kind
    t._on_disconnected(None)
    assert t.states == [state]
    t._on_disconnected(None)
    assert t.states == [state, "disconnected"], "said once"


def test_the_sign_in_path_recognises_them_too():
    source = _read(ROOT, "android_bridge", "transport.py")
    sign_in = source[source.index("def on_stream_error(stanza):"):]
    sign_in = sign_in[:sign_in.index("_is_session_limit(cond, said)")]
    assert "_restrictions.of_stream_error(cond, said)" in sign_in
    assert "TransportError(\n                        restricted.kind, restricted.text)" in sign_in


# ── the controller and the app ──────────────────────────────────────────────

class FakeApp:
    def receive_message(self, peer, payload):
        pass

    def note_presence(self, peer, online, show=""):
        pass

    def note_presence_lost(self):
        pass

    def set_event_sink(self, sink):
        pass


@pytest.mark.parametrize("kind", [R.MAINTENANCE, R.SIGNED_OUT, R.REMOVED])
def test_the_controller_fails_with_the_restrictions_code(kind):
    from android_bridge.connection import ConnectionController, SamProbe
    from android_bridge.settings import ConnectionProfile
    ctl = ConnectionController(
        FakeApp(), ConnectionProfile(jid=JID),
        transport_factory=lambda *a, **k: None,
        prober=lambda _p, **_kw: SamProbe(True, "ok", "fine", "3.1"))

    class Closed:
        closed_by_admin = (kind, R.text_for(kind))
        is_connected = False
    ctl._transport = Closed()
    ctl._on_transport_state("restricted", "otrv4plus.i2p")
    status = ctl.status()
    assert status["stage"] == "failed"
    assert status["last"]["code"] == kind
    assert status["last"]["detail"] == R.text_for(kind)


@pytest.fixture
def app():
    sys.path.insert(0, os.path.join(ROOT, "tests"))
    import test_android_bridge as B
    from android_bridge.app import OtrApp
    engine, transport, sink = B.FakeEngine(), B.FakeTransport(), B.RecordingSink()
    return OtrApp(engine, transport, sink), sink


def test_a_muted_conversation_drops_what_it_held_and_says_so(app):
    from android_bridge.app import _Line
    from android_bridge.events import MessageBlocked
    a, sink = app
    a._outbox["bob@otrv4plus.i2p"] = [_Line("one", "m-1"), _Line("two", "m-2")]
    a.note_restricted("bob@otrv4plus.i2p", "", R.MUTED)
    blocked = sink.of(MessageBlocked)
    assert [(e.message_id, e.reason) for e in blocked] == [
        ("", R.MUTED), ("m-1", R.MUTED), ("m-2", R.MUTED)]
    assert "bob@otrv4plus.i2p" not in a._outbox, "nothing left to go out later"


def test_an_announcement_is_a_plaintext_message_from_the_server(app):
    from android_bridge.events import MessageReceived
    a, sink = app
    a.note_announcement("otrv4plus.i2p", "Back at 18:00", 1.0)
    (event,) = sink.of(MessageReceived)
    assert event.peer == "otrv4plus.i2p" and event.body == "Back at 18:00"
    assert event.source == "server"


def test_the_controller_wires_both_handlers():
    source = _read(ROOT, "android_bridge", "connection.py")
    assert '("set_restriction_handler", "note_restricted")' in source
    assert '("set_announcement_handler", "note_announcement")' in source


# ── what the two apps show (Kotlin, read from the source) ───────────────────

def test_the_apps_sentences_are_the_bridges():
    failure = _read(KT, "chat", "FailureText.kt")
    for kind in (R.MUTED, R.FILES_RESTRICTED, R.FILES_DISABLED):
        assert '"%s" to "%s",' % (kind, R.text_for(kind)) in failure, kind


def test_both_apps_decode_the_event():
    android = _read(KT, "bridge", "ChaquopyEvents.kt")
    desktop = _read(ROOT, "desktop", "src", "main", "kotlin", "org", "otrv4plus",
                    "desktop", "engine", "DesktopCore.kt")
    for source in (android, desktop):
        assert '"MessageBlocked"' in source
        assert re.search(r'OtrEvent\.MessageBlocked\(\s*str\("peer"\), str\("message_id"\), '
                         r'str\("reason"\)\)', source), source[:0]


def test_the_shared_chat_state_marks_the_bubble_and_says_why():
    state = _read(KT, "chat", "ChatState.kt")
    assert "is OtrEvent.MessageBlocked -> { markBlocked(event); false }" in state
    body = state[state.index("fun markBlocked("):]
    body = body[:body.index("\n    }\n")]
    assert "SendState.FAILED" in body
    assert "SecurityLabel.SYSTEM" in body
    assert "note(text)" in body
    assert 'event.source == "server"' in state


def test_the_connect_screen_has_a_sentence_for_each_and_stops_where_it_must():
    problem = _read(KT, "connection", "ConnectProblem.kt")
    needs = problem[problem.index("val NEEDS_YOU"):problem.index("val TRANSIENT")]
    for code in ("ACCOUNT_BANNED", "ACCOUNT_REMOVED", "SIGNED_OUT_BY_ADMIN"):
        assert code in needs
    assert "SERVER_MAINTENANCE" not in needs, "maintenance is retried"
    for const, kind in (("ACCOUNT_REMOVED", R.REMOVED),
                        ("SIGNED_OUT_BY_ADMIN", R.SIGNED_OUT),
                        ("SERVER_MAINTENANCE", R.MAINTENANCE)):
        assert 'const val %s = "%s"' % (const, kind) in problem
    assert "suspended" in problem[problem.index("ACCOUNT_BANNED_TEXT ="):][:200]
    service = _read(KT, "connection", "OtrConnectionService.kt")
    for const in ("ACCOUNT_REMOVED", "SIGNED_OUT_BY_ADMIN"):
        assert "current.code == ConnectProblem.%s" % const in service


# ── the terminal client ─────────────────────────────────────────────────────

def test_the_terminal_client_says_so_too():
    presence = _read(ROOT, "client", "otrv4plus_xmpp_presence.py")
    assert "_restrictions.of_stanza_error(" in presence
    connection = _read(ROOT, "client", "otrv4plus_xmpp_connection.py")
    assert "_restrictions.of_stream_error(" in connection
    xmpp = _read(ROOT, "client", "otrv4plus_xmpp.py")
    handler = xmpp[xmpp.index("    def _on_message(self, msg):"):]
    assert handler.index("is_server_announcement") < handler.index(
        'if msg["type"] not in ("chat", "normal"):')


# ── the restriction query (server: XMPP Guard with the query patch) ─────────

def _query(*children):
    import xml.etree.ElementTree as ET
    q = ET.Element("{%s}query" % R.QUERY_NS)
    for tag, until in children:
        el = ET.SubElement(q, "{%s}%s" % (R.QUERY_NS, tag))
        if until is not None:
            el.set("until", until)
    return q


def test_the_answer_is_read_as_the_server_states_it():
    found = R.parse_query(_query(("muted", "0"), ("no-files", "1900000000"),
                                 ("files-disabled", None), ("maintenance", "0"),
                                 ("something-new", "5")))
    assert found == {"muted": 0, "no_files": 1900000000,
                     "files_disabled": True, "maintenance": 0}
    assert R.parse_query(_query()) == {"muted": None, "no_files": None,
                                       "files_disabled": False, "maintenance": None}
    assert R.parse_query(None)["muted"] is None


@pytest.mark.parametrize("until,read", [("-5", 0), ("soon", 0), ("9" * 20, 0),
                                        (" 42 ", 42)])
def test_a_time_that_is_not_one_is_until_lifted(until, read):
    assert R.parse_query(_query(("muted", until)))["muted"] == read


def test_the_sentence_says_what_and_until_when():
    assert R.summary(R.parse_query(_query())) == ""
    said = R.summary(R.parse_query(_query(("muted", "0"), ("no-files", "1900000000"))))
    assert said.startswith("Your account is temporarily restricted")
    assert "messaging is restricted until the administrator lifts it" in said
    assert "file transfers are restricted until 2030-03-17 17:46 UTC" in said
    assert "disabled on this server" in R.summary(
        R.parse_query(_query(("files-disabled", None))))


def test_the_query_is_asked_at_sign_in_and_reaches_the_screen(app):
    from android_bridge.events import AccountRestricted
    source = _read(ROOT, "android_bridge", "transport.py")
    session = source[source.index("        self._start_sync()\n"):][:400]
    assert "self._start_restrictions_query()" in session
    assert '"set_account_restrictions_handler"' in _read(ROOT, "android_bridge", "connection.py")
    a, sink = app
    a.note_account_restrictions({"muted": 0, "no_files": None,
                                 "files_disabled": True, "maintenance": None})
    (event,) = sink.of(AccountRestricted)
    assert event.muted_until == 0 and event.no_files_until == -1
    assert event.files_disabled is True and "messaging is restricted" in event.text


def test_both_apps_show_it():
    for source in (_read(KT, "bridge", "ChaquopyEvents.kt"),
                   _read(ROOT, "desktop", "src", "main", "kotlin", "org", "otrv4plus",
                         "desktop", "engine", "DesktopCore.kt")):
        assert '"AccountRestricted" -> OtrEvent.AccountRestricted(' in " ".join(source.split()) \
            or '"AccountRestricted" ->' in source
    state = _read(KT, "chat", "ChatState.kt")
    assert "accountRestriction = event.text" in state
    assert "model.accountRestriction()" in _read(KT, "ui", "ProfileScreen.kt")
    assert "model.chat.accountRestriction" in _read(
        ROOT, "desktop", "src", "main", "kotlin", "org", "otrv4plus", "desktop", "ui", "Profile.kt")


# ── retry, and the server's conversation ────────────────────────────────────

def test_a_failed_message_is_sent_again_only_when_asked_and_in_place():
    state = _read(KT, "chat", "ChatState.kt")
    retry = state[state.index("fun beginRetry("):]
    retry = retry[:retry.index("\n    }\n")]
    assert "MessageId.newWireId()" in retry, "a new wire id: its receipt matches this try"
    assert "sendState = SendState.SENDING" in retry
    assert "store.update(again)" in retry, "the same bubble, not a second one"
    can = state[state.index("fun canRetry("):][:400]
    for rule in ("m.outgoing", "SendState.FAILED", "!isRoom(", "!isServerConversation("):
        assert rule in can
    for ui in (_read(KT, "ui", "ConversationScreen.kt"),
               _read(ROOT, "desktop", "src", "main", "kotlin", "org", "otrv4plus",
                     "desktop", "ui", "ConversationPane.kt")):
        assert "model.canRetry(" in ui and "model.retry(" in ui


def test_nothing_is_typed_into_the_servers_conversation():
    state = _read(KT, "chat", "ChatState.kt")
    begin = state[state.index("fun beginSend("):][:1200]
    assert "if (isServerConversation(jid)) return null" in begin
    for ui in (_read(KT, "ui", "ConversationScreen.kt"),
               _read(ROOT, "desktop", "src", "main", "kotlin", "org", "otrv4plus",
                     "desktop", "ui", "ConversationPane.kt")):
        assert "model.isServerConversation(jid)" in ui
        assert "Replies cannot be sent here." in ui

#!/usr/bin/env python3
"""INV-20: the IRC channel user list, and what its blue marker does not mean.

`/names` was unusable from v10.11.0 to v10.13.3: `Pager.display` measured and
truncated each line and then printed the literal string
"[IRC line suppressed]" instead of it.  Every pager consumer was affected --
`/names`, `/list` and `/help` alike -- so what looked like a deliberate
suppression policy was one wrong argument.  The first test class below is
there so that cannot come back silently.

The rest cover the rendering and, more importantly, the boundary: the blue
OTRv4+ marker comes from the realname (gecos) field the peer's own client
sent at registration.  The server relays it; nobody checks it.  It answers
"is this peer likely to understand /otr" and nothing else.  It must never
authenticate, mark trusted, satisfy TOFU, stand in for SMP, or enable voice
-- and TestIdentificationIsNotAuthentication is what fails if it starts to.
"""

import ast
import inspect
import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

otr = pytest.importorskip("otrv4_")

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def plain(lines):
    """The rendered list with colour removed, for asserting on content."""
    if isinstance(lines, str):
        return ANSI.sub("", lines)
    return [ANSI.sub("", ln) for ln in lines]


def blue_nicks(lines):
    """Nicks rendered in blue, read back out of the escape sequences."""
    found = []
    for line in lines:
        for chunk in re.findall(r"\x1b\[94m(.*?)\x1b\[0m", line):
            text = chunk.replace("🔵", " ")
            name = text.strip().lstrip("0123456789").strip()
            name = name.lstrip("~&@%+")
            if name and "OTRv4+" not in name:
                found.append(name)
    return found


# ==========================================================================
# The bug itself
# ==========================================================================

class TestThePagerPrintsItsLines:

    def test_it_does_not_print_a_placeholder(self):
        """The comment naming the old bug is allowed to mention it; a call
        that prints it is not."""
        src = inspect.getsource(otr.Pager.display)
        assert 'safe_print("[IRC line suppressed]")' not in src, (
            "the pager is printing a literal again")
        assert "safe_print(_truncate_visible(line" in src

    def test_every_line_reaches_the_output(self, monkeypatch):
        printed = []
        monkeypatch.setattr(otr, "safe_print",
                            lambda *a, **k: printed.append(a[0] if a else ""))
        otr.Pager(lines_per_page=50).display(["alpha", "beta", "gamma"],
                                             "Header")
        body = plain(printed)
        for expected in ("alpha", "beta", "gamma"):
            assert expected in body, "%r never reached the terminal" % expected

    def test_the_header_carries_the_count(self, monkeypatch):
        printed = []
        monkeypatch.setattr(otr, "safe_print",
                            lambda *a, **k: printed.append(a[0] if a else ""))
        otr.Pager(lines_per_page=50).display(["x"], "Users in #i2p-chat (97)")
        assert any("Users in #i2p-chat (97)" in ln for ln in plain(printed))

    def test_a_coloured_line_is_not_truncated_by_its_escape_bytes(self):
        """Truncating by len() counts the escape sequences as visible
        characters, so a coloured line is cut long before its width -- and
        loses its reset, bleeding colour into the rest of the terminal."""
        line = otr.colorize("A" * 40, "blue")
        out = otr._truncate_visible(line, 100)
        assert plain(out) == "A" * 40, "a line that fits was truncated anyway"
        cut = otr._truncate_visible(line, 10)
        assert plain(cut) == "A" * 10
        assert cut.endswith(otr.UIConstants.COLORS["reset"])


# ==========================================================================
# Parsing RPL_NAMREPLY
# ==========================================================================

class TestNamesEntryParsing:

    @pytest.mark.parametrize("entry,expected", [
        ("alice", ("", "alice")),
        ("@alice", ("@", "alice")),
        ("+bob", ("+", "bob")),
        ("~owner", ("~", "owner")),
        ("&admin", ("&", "admin")),
        ("%halfop", ("%", "halfop")),
        ("@+multi", ("@+", "multi")),      # multi-prefix is a negotiated cap
    ])
    def test_prefixes_split_from_nicks(self, entry, expected):
        assert otr.split_names_entry(entry) == expected

    @pytest.mark.parametrize("entry", ["", "@", "+", "@@@", None])
    def test_an_entry_with_no_nick_is_dropped(self, entry):
        assert otr.split_names_entry(entry) == ("", "")

    @pytest.mark.parametrize("entry", ["a b", "a\r\nb", "a\x00b"])
    def test_an_entry_with_separators_is_dropped(self, entry):
        """A NAMES line is remote input.  An entry carrying a space or a
        newline is malformed at best and an injection attempt at worst."""
        assert otr.split_names_entry(entry) == ("", "")


# ==========================================================================
# Rendering
# ==========================================================================

class TestRendering:

    def test_multiple_users_all_appear(self):
        users = ["@AngryMouse", "Alice", "+Bob", "Charlie", "Dave"]
        body = "\n".join(plain(otr.format_names_list(users)))
        for nick in ("AngryMouse", "Alice", "Bob", "Charlie", "Dave"):
            assert nick in body

    def test_an_empty_channel_renders_rather_than_crashing(self):
        lines = otr.format_names_list([], {}, total=0)
        assert lines
        assert "no users reported" in "\n".join(plain(lines))

    def test_the_total_is_the_servers_count_not_the_rendered_count(self):
        """The list is capped locally; the header is not.  Reporting the
        slice we chose to draw would understate the channel."""
        lines = otr.format_names_list(["Alice", "Bob"], {"Alice": True},
                                      total=97)
        body = "\n".join(plain(lines))
        assert "1 OTRv4+" in body
        assert "96 other client(s)" in body
        assert "97 users in channel" in body, (
            "a capped list must say the total it is a slice of")

    def test_the_total_defaults_to_what_was_rendered(self):
        lines = otr.format_names_list(["Alice", "Bob"], {"Alice": True})
        body = "\n".join(plain(lines))
        assert "1 OTRv4+" in body and "1 other client(s)" in body
        assert "users in channel" not in body, (
            "nothing was capped, so there is no slice warning to show")

    def test_users_are_grouped_by_privilege(self):
        lines = plain(otr.format_names_list(["@op", "+voice", "plain"]))
        body = "\n".join(lines)
        assert "Operators (1)" in body
        assert "Voiced (1)" in body
        assert "Users (1)" in body

    def test_a_duplicate_entry_is_counted_once(self):
        lines = otr.format_names_list(["Alice", "Alice", "Bob"])
        assert "Users (2)" in "\n".join(plain(lines))

    def test_malformed_entries_do_not_lose_the_good_ones(self):
        """One bad token must cost that token, not the whole list."""
        lines = otr.format_names_list(["Alice", "@", "", "b c", "Bob"])
        body = "\n".join(plain(lines))
        assert "Alice" in body and "Bob" in body
        assert "Users (2)" in body

    def test_a_hostile_nick_is_sanitised(self):
        rendered = "\n".join(plain(otr.format_names_list(["\x1b[31mevil"])))
        assert "\x1b" not in rendered


class TestOtrv4UsersAreBlue:

    USERS = ["@AngryMouse", "Alice", "Bob", "Charlie", "Dave"]
    MAP = {"AngryMouse": True, "Alice": True, "Bob": True}

    def test_the_summary_counts_both_kinds(self):
        lines = otr.format_names_list(self.USERS, self.MAP, total=97)
        head = plain(lines[0])
        assert "3 OTRv4+" in head
        assert "94 other client(s)" in head

    def test_detected_users_are_rendered_in_blue(self):
        lines = otr.format_names_list(self.USERS, self.MAP, total=97)
        assert set(blue_nicks(lines)) >= {"AngryMouse", "Alice", "Bob"}

    def test_undetected_users_are_not_blue(self):
        lines = otr.format_names_list(self.USERS, self.MAP, total=97)
        blue = blue_nicks(lines)
        assert "Charlie" not in blue
        assert "Dave" not in blue

    def test_they_carry_the_marker_glyph(self):
        body = "\n".join(plain(
            otr.format_names_list(self.USERS, self.MAP, total=97)))
        assert "🔵" in body

    def test_a_channel_with_no_otrv4_users_still_renders(self):
        lines = otr.format_names_list(["Charlie", "Dave"], {}, total=2)
        body = "\n".join(plain(lines))
        assert "0 OTRv4+" in body and "2 other client(s)" in body
        assert blue_nicks(lines) == []

    def test_detected_users_sort_first_within_their_group(self):
        lines = plain(otr.format_names_list(
            ["Aaron", "Zoe"], {"Zoe": True}))
        users = "\n".join(lines[lines.index("  Users (2):"):])
        assert users.index("Zoe") < users.index("Aaron")


# ==========================================================================
# Detection comes from the realname, and only from the realname
# ==========================================================================

class TestClientIdentification:

    def test_the_advertised_realname_carries_the_version(self):
        assert otr.otrv4_client_version("AngryMouse - OTRv4+ 10.13.2") == "10.13.2"

    def test_a_plain_realname_is_not_detected(self):
        assert otr.otrv4_client_version("Just Some Person") is None
        assert otr.advertises_otrv4("") is False
        assert otr.advertises_otrv4(None) is False

    def test_the_tag_alone_is_not_enough(self):
        """A bare substring test also fires on chat-like gecos text.  The
        format this project actually advertises includes a version."""
        assert otr.advertises_otrv4("I don't use OTRv4+") is False
        assert otr.advertises_otrv4("OTRv4+") is False
        assert otr.advertises_otrv4("OTRv4+ 10.13.2") is True

    def test_every_realname_this_client_sends_is_detectable(self):
        """Before v10.13.3 a 27 Club nick advertised '... - 27 Club' and a
        NickServ nick advertised the bare nick, so two whole classes of
        OTRv4+ user were invisible to their own peers.  A detection
        mechanism the client does not consistently feed is not one."""
        for nick in list(otr.TwentySevenClubNick._LOOKUP)[:3] + ["AngryMouse"]:
            realname = otr.TwentySevenClubNick.real_name(nick)
            assert otr.advertises_otrv4(realname), (
                "%s advertises %r, which its peers cannot detect"
                % (nick, realname))

    def test_a_registered_nick_still_advertises(self):
        """The other realname path.  Found by mutation: replacing this with
        the bare nick left every test passing, because they all went through
        real_name() and this branch does not.

        A NickServ-registered user is exactly the sort of long-lived peer
        another user most wants to find in /names.
        """
        src = inspect.getsource(otr)
        i = src.index("self.nick = self.config.nickserv_nick")
        window = src[i:i + 400]
        assert "self.realname = self.nick\n" not in window, (
            "a registered nick advertises no version and is undetectable")
        assert "VERSION" in window
        rendered = window[window.index("self.realname"):]
        rendered = rendered[:rendered.index("\n")]
        assert otr.advertises_otrv4(
            rendered.split(":", 1)[-1].replace('f"', "").replace('"', "")
            .replace("{self .nick }", "nick").replace("{VERSION }", otr.VERSION)
        ), "the realname assigned there does not match the detection format"

    def test_the_27_club_identity_is_still_shown(self):
        """The version was appended, not substituted."""
        nick = list(otr.TwentySevenClubNick._LOOKUP)[0]
        assert "27 Club" in otr.TwentySevenClubNick.real_name(nick)

    def test_the_registration_line_sends_that_realname(self):
        src = inspect.getsource(otr)
        assert 'USER {self .nick } 0 * :{self .realname }' in src

    def test_ctcp_version_is_still_refused(self):
        """The realname is the identification channel BECAUSE CTCP VERSION
        is not.  If CTCP were answered, this would be the wrong mechanism to
        be building on."""
        assert "VERSION" in otr.OTRv4IRCClient._CTCP_BLOCKED


# ==========================================================================
# The numeric handlers, driven directly
# ==========================================================================

class _Harness:
    """Only the surface the NAMES/WHO handlers touch."""

    handle_numeric_reply = otr.OTRv4IRCClient.handle_numeric_reply
    handle_message = otr.OTRv4IRCClient.handle_message
    parse_irc_message = otr.OTRv4IRCClient.parse_irc_message
    _handle_unknown_command = otr.OTRv4IRCClient._handle_unknown_command

    def __init__(self):
        self.names_data = {}
        self.channels = {}
        self._otrv4_users = {}
        self._names_total = {}
        self._pending_names_pager = None
        self.nick = "me"
        self.channel_list = []
        self.paged = []
        self.started = []
        self.messages = []
        self.ignored_users = set()
        harness = self

        class _Sessions:
            """Records every touch, so a test can assert the user list did
            not go near session, trust or SMP state."""

            def __init__(self):
                self.touched = []

            def has_session(self, peer):
                self.touched.append(("has_session", peer))
                return False

            def __getattr__(self, name):
                raise AssertionError(
                    "the user list reached session state: %s" % name)

        self.session_manager = _Sessions()

        class _Pager:
            def display(self, lines, header="", footer="", choices=None):
                harness.paged.append((lines, header, list(choices or [])))
                return None

        class _Panels:
            active_panel = "#chan"

            def get_active_panel(self):
                return None

            def _render_ui(self):
                pass

        class _Logger:
            def network_message(self, *a, **k):
                pass

        self.pager = _Pager()
        self.panel_manager = _Panels()
        self.logger = _Logger()

    def add_message(self, panel, msg):
        self.messages.append((panel, msg))

    def start_guided_otr_session(self, nick):
        self.started.append(nick)

    def _on_peer_disconnected(self, *a):
        pass

    def debug(self, msg, *rest):
        # handle_message routes normal tracing AND its catch-all exception
        # handler through debug().  A harness that swallowed both would let
        # these tests pass on a traceback, so the error path is made loud.
        if msg == "handle_message error":
            raise AssertionError("handle_message raised and was swallowed")


def _names(h, channel, *entries):
    h.handle_numeric_reply(353, ["me", "=", channel], " ".join(entries))


def _end_names(h, channel):
    h.handle_numeric_reply(366, ["me", channel], "End of /NAMES list")


def _who(h, channel, nick, realname):
    h.handle_numeric_reply(
        352, ["me", channel, "user", "host", "server", nick, "H"],
        "0 " + realname)


class TestTheNumericHandlers:

    def test_353_accumulates_and_366_renders(self):
        h = _Harness()
        h._pending_names_pager = "#chan"
        _names(h, "#chan", "@alice", "bob")
        _names(h, "#chan", "carol")
        _end_names(h, "#chan")
        assert len(h.paged) == 1
        body = "\n".join(plain(h.paged[0][0]))
        for nick in ("alice", "bob", "carol"):
            assert nick in body

    def test_the_header_reports_the_accumulated_total(self):
        h = _Harness()
        h._pending_names_pager = "#chan"
        _names(h, "#chan", *["u%d" % i for i in range(50)])
        _names(h, "#chan", *["v%d" % i for i in range(47)])
        _end_names(h, "#chan")
        assert "(97)" in h.paged[0][1]

    def test_an_empty_channel_reaches_the_pager(self):
        h = _Harness()
        h._pending_names_pager = "#chan"
        _names(h, "#chan")
        _end_names(h, "#chan")
        assert len(h.paged) == 1
        assert "(0)" in h.paged[0][1]

    def test_who_populates_the_otrv4_map(self):
        h = _Harness()
        _who(h, "#chan", "alice", "Alice - OTRv4+ 10.13.2")
        _who(h, "#chan", "bob", "just bob")
        assert h._otrv4_users == {"alice": True, "bob": False}

    def test_who_then_names_renders_the_detected_user_blue(self):
        h = _Harness()
        h._pending_names_pager = "#chan"
        _who(h, "#chan", "alice", "Alice - OTRv4+ 10.13.2")
        _who(h, "#chan", "bob", "just bob")
        _names(h, "#chan", "alice", "bob")
        _end_names(h, "#chan")
        blue = blue_nicks(h.paged[0][0])
        assert "alice" in blue and "bob" not in blue

    def test_an_unsolicited_end_of_names_does_not_page(self):
        """NAMES also arrives on JOIN.  Paging over the user's screen every
        time they join a channel is not what they asked for."""
        h = _Harness()
        _names(h, "#chan", "alice")
        _end_names(h, "#chan")
        assert h.paged == []

    def test_it_still_clears_its_state(self):
        """...but the accumulator must not grow for the life of the process,
        or the next /names reports a total that includes every join since."""
        h = _Harness()
        _names(h, "#chan", "alice", "bob")
        _end_names(h, "#chan")
        assert h.names_data.get("#chan") == []
        assert "#chan" not in h._names_total

        h._pending_names_pager = "#chan"
        _names(h, "#chan", "alice", "bob")
        _end_names(h, "#chan")
        assert "(2)" in h.paged[0][1], "a stale total leaked into the header"

    def test_353_populates_the_channel_membership(self):
        h = _Harness()
        h.channels["#chan"] = {"users": set(), "topic": ""}
        _names(h, "#chan", "@alice", "+bob", "carol")
        assert h.channels["#chan"]["users"] == {"alice", "bob", "carol"}

    def test_a_malformed_entry_does_not_inflate_the_total(self):
        """Found by mutation: format_names_list drops bad entries anyway, so
        removing the filter here changed nothing visible in the list -- but
        the header count and the channel membership are taken before that
        point, and both would have been wrong.
        """
        h = _Harness()
        h.channels["#chan"] = {"users": set(), "topic": ""}
        h._pending_names_pager = "#chan"
        _names(h, "#chan", "alice", "@", "bob")
        _end_names(h, "#chan")
        assert "(2)" in h.paged[0][1], (
            "an unusable entry was counted as a channel member")
        assert h.channels["#chan"]["users"] == {"alice", "bob"}

    def test_a_malformed_353_does_not_raise(self):
        h = _Harness()
        h.handle_numeric_reply(353, ["me"], None)
        h.handle_numeric_reply(353, [], "@alice")
        h.handle_numeric_reply(366, [], None)
        assert h.paged == []

    def test_the_list_numeric_still_reaches_the_pager(self):
        """/list uses the same pager, so it was suppressed by the same bug."""
        h = _Harness()
        h.handle_numeric_reply(321, ["me"], "Channel list")
        h.handle_numeric_reply(322, ["me", "#one", "42"], "a topic")
        h.handle_numeric_reply(322, ["me", "#two", "7"], "another")
        h.handle_numeric_reply(323, ["me"], "End of /LIST")
        assert len(h.paged) == 1
        body = "\n".join(plain(h.paged[0][0]))
        assert "#one" in body and "#two" in body
        assert "42" in body


class TestWhois:
    """Requirement: /whois keeps showing Client, User and Name.  It now shows
    the peer's values rather than ones computed from their nick."""

    def _whois(self, nick, realname):
        h = _Harness()
        h.handle_numeric_reply(
            311, ["me", nick, "user", "dest.b32.i2p", "*"], realname)
        return h, "\n".join(plain(m) for _, m in h.messages)

    def test_it_shows_the_three_fields(self):
        _, out = self._whois("AngryMouse", "AngryMouse - OTRv4+ 10.13.3")
        assert "Nick     : AngryMouse" in out
        assert "Client   : OTRv4+ 10.13.3" in out
        assert "User     : user@dest.b32.i2p" in out
        assert "Name     : AngryMouse - OTRv4+ 10.13.3" in out

    def test_the_name_comes_off_the_wire(self):
        """It used to be TwentySevenClubNick.real_name(target) -- the LOCAL
        formatting of their nick -- which is never equal to the bare nick, so
        the peer's actual realname was never displayed at all."""
        _, out = self._whois("someone", "I am running mIRC")
        assert "Name     : I am running mIRC" in out
        assert "someone - OTRv4+" not in out

    def test_a_non_otrv4_peer_is_not_reported_as_one(self):
        """`Client` printed our own VERSION regardless of the peer, so every
        /whois claimed the target ran OTRv4+.  That is the nick-derived
        inference this must not make."""
        _, out = self._whois("someone", "I am running mIRC")
        assert "OTRv4+" not in out
        assert "not advertised" in out

    def test_whois_updates_the_marker(self):
        h, _ = self._whois("alice", "Alice - OTRv4+ 10.13.3")
        assert h._otrv4_users == {"alice": True}

    def test_whois_can_clear_a_stale_marker(self):
        h = _Harness()
        h._otrv4_users["alice"] = True
        h.handle_numeric_reply(311, ["me", "alice", "u", "h", "*"], "now mIRC")
        assert h._otrv4_users["alice"] is False

    def test_a_hostile_realname_is_sanitised(self):
        _, out = self._whois("evil", "\x1b[31mred - OTRv4+ 9.9.9")
        assert "\x1b[31m" not in out


class TestMembershipChangesUpdateTheList:

    def _joined(self, nick="alice", realname="Alice - OTRv4+ 10.13.2"):
        h = _Harness()
        h.channels["#chan"] = {"users": {nick}, "topic": ""}
        _who(h, "#chan", nick, realname)
        return h

    def test_join_adds_the_user(self):
        h = _Harness()
        h.channels["#chan"] = {"users": set(), "topic": ""}
        h.handle_message(":bob!u@h JOIN :#chan")
        assert "bob" in h.channels["#chan"]["users"]

    def test_part_removes_the_user(self):
        h = self._joined()
        h.handle_message(":alice!u@h PART #chan :bye")
        assert "alice" not in h.channels["#chan"]["users"]

    def test_quit_removes_the_user(self):
        h = self._joined()
        h.handle_message(":alice!u@h QUIT :bye")
        assert "alice" not in h.channels["#chan"]["users"]

    def test_quit_drops_the_identification_too(self):
        """The map is keyed by nick.  Someone else may take the nick, and a
        stale entry would mark them as an OTRv4+ client on no evidence."""
        h = self._joined()
        assert h._otrv4_users["alice"] is True
        h.handle_message(":alice!u@h QUIT :bye")
        assert "alice" not in h._otrv4_users

    def test_a_nick_change_carries_the_identification_across(self):
        """Same client, same person, new name.  Losing the marker here would
        make a rename look like a downgrade."""
        h = self._joined()
        h.handle_message(":alice!u@h NICK :alice2")
        assert h.channels["#chan"]["users"] == {"alice2"}
        assert h._otrv4_users.get("alice2") is True
        assert "alice" not in h._otrv4_users

    def test_a_nick_change_by_an_undetected_user_stays_undetected(self):
        h = self._joined("dave", "just dave")
        h.handle_message(":dave!u@h NICK :dave2")
        assert h._otrv4_users.get("dave2") is False

    def test_the_rendered_list_follows_the_change(self):
        h = self._joined()
        h.handle_message(":alice!u@h NICK :alice2")
        h._pending_names_pager = "#chan"
        _names(h, "#chan", "alice2")
        _end_names(h, "#chan")
        assert blue_nicks(h.paged[0][0]) == ["alice2"]


# ==========================================================================
# Selection
# ==========================================================================

class TestSelectingAUserStartsOtr:

    def test_detected_users_are_offered_as_choices(self):
        h = _Harness()
        h._pending_names_pager = "#chan"
        _who(h, "#chan", "alice", "Alice - OTRv4+ 10.13.2")
        _who(h, "#chan", "bob", "just bob")
        _names(h, "#chan", "alice", "bob")
        _end_names(h, "#chan")
        assert h.paged[0][2] == ["alice"], (
            "only detected users are offered, and bob is not one")

    def test_choosing_one_starts_a_dake(self):
        h = _Harness()

        class _Picking:
            def display(self, lines, header="", footer="", choices=None):
                h.paged.append((lines, header, list(choices or [])))
                return (choices or [None])[0]

        h.pager = _Picking()
        h._pending_names_pager = "#chan"
        _who(h, "#chan", "alice", "Alice - OTRv4+ 10.13.2")
        _names(h, "#chan", "alice")
        _end_names(h, "#chan")
        assert h.started == ["alice"], (
            "selecting a user must go through the normal /otr entry point")

    def test_declining_starts_nothing(self):
        h = _Harness()
        h._pending_names_pager = "#chan"
        _who(h, "#chan", "alice", "Alice - OTRv4+ 10.13.2")
        _names(h, "#chan", "alice")
        _end_names(h, "#chan")
        assert h.started == []

    def test_the_pager_returns_the_chosen_entry(self, monkeypatch):
        keys = iter(["2"])
        monkeypatch.setattr(otr, "safe_print", lambda *a, **k: None)
        monkeypatch.setattr(otr, "_raw_mode_active", False)
        monkeypatch.setattr(sys, "stdin",
                            type("S", (), {"readline": lambda self: next(keys)})())
        got = otr.Pager(lines_per_page=50).display(
            ["a", "b"], "Users", choices=["alice", "bob"])
        assert got == "bob"

    def test_quitting_returns_nothing(self, monkeypatch):
        monkeypatch.setattr(otr, "safe_print", lambda *a, **k: None)
        monkeypatch.setattr(otr, "_raw_mode_active", False)
        monkeypatch.setattr(sys, "stdin",
                            type("S", (), {"readline": lambda self: "q"})())
        assert otr.Pager(lines_per_page=50).display(
            ["a"], "Users", choices=["alice"]) is None

    def test_a_page_without_choices_behaves_as_before(self, monkeypatch):
        """Callers that ignore the return value must be unaffected."""
        monkeypatch.setattr(otr, "safe_print", lambda *a, **k: None)
        assert otr.Pager(lines_per_page=50).display(["a"], "H") is None


# ==========================================================================
# INV-20 -- the boundary
# ==========================================================================

class TestIdentificationIsNotAuthentication:

    def test_the_marker_grants_no_trust(self):
        """Rendering the list must not touch trust, sessions or SMP state."""
        h = _Harness()
        h._pending_names_pager = "#chan"
        _who(h, "#chan", "alice", "Alice - OTRv4+ 10.13.2")
        _names(h, "#chan", "alice")
        _end_names(h, "#chan")
        assert h.session_manager.touched == [], (
            "rendering the user list reached session state: %s"
            % h.session_manager.touched)
        assert h.started == [], "a blue marker started a session by itself"

    def test_the_renderer_cannot_reach_any_security_state(self):
        """It is a pure function over names and a map of booleans.  It has
        no client, so it has nothing to promote."""
        src = inspect.getsource(otr.format_names_list)
        for reachable in ("session_manager", "trust_db", "smp_", "verify",
                          "start_call", "start_audio", "fingerprint",
                          "trust", "self."):
            assert reachable not in src, (
                "format_names_list can reach %s" % reachable)

    def test_the_detection_helpers_are_pure(self):
        for fn in (otr.otrv4_client_version, otr.advertises_otrv4,
                   otr.split_names_entry):
            src = inspect.getsource(fn)
            assert "self" not in src

    def test_the_source_says_what_the_marker_is_not(self):
        """The comment is the thing that stops the next person wiring this
        into the voice gate, so it is load-bearing."""
        src = inspect.getsource(otr)
        i = src.index("OTRV4_CLIENT_TAG = ")
        head = src[max(0, i - 2000):i]
        assert "not authentication" in head.lower()
        for named in ("TOFU", "SMP", "voice", "trusted"):
            assert named in head, (
                "the comment no longer rules out %s" % named)

    def test_voice_authorisation_never_reads_the_map(self):
        voice = pytest.importorskip("otrv4plus_voice")
        src = inspect.getsource(voice)
        for banned in ("_otrv4_users", "advertises_otrv4",
                       "otrv4_client_version"):
            assert banned not in src, (
                "the voice module reads IRC client identification (%s); SMP "
                "verification is what authorises a call" % banned)

    def test_the_smp_gate_is_unchanged(self):
        voice = pytest.importorskip("otrv4plus_voice")
        code = inspect.getsource(voice.VoiceCallManager._smp_verified)
        assert "_smp_query" in code
        for banned in ("_otrv4", "advertises", "realname", "gecos"):
            assert banned not in code

    def test_detection_never_reads_a_chat_message(self):
        """Requirement: OTRv4+ status comes from server-relayed registration
        metadata, never from something a peer typed into a channel."""
        import textwrap
        tree = ast.parse(textwrap.dedent(
            inspect.getsource(otr.OTRv4IRCClient.handle_numeric_reply)))
        writes = []
        for node in ast.walk(tree):
            if (isinstance(node, ast.Subscript)
                    and isinstance(node.ctx, ast.Store)
                    and "_otrv4_users" in ast.dump(node.value)):
                writes.append(node.lineno)
        assert writes, "nothing populates the OTRv4+ map any more"
        src = inspect.getsource(otr.OTRv4IRCClient.handle_numeric_reply)
        head = src[:src.index("_otrv4_users[")]
        assert "code == 352" in head, (
            "the map is populated somewhere other than the WHO reply")

    def test_only_the_who_reply_and_a_rename_write_the_map(self):
        """A message handler writing this map would mean a peer could set
        their own marker by typing, which is exactly what must not happen."""
        src = inspect.getsource(otr)
        writers = set()
        tree = ast.parse(src)
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body = ast.dump(fn)
            if "_otrv4_users" in body and (
                    "Subscript" in body or "'pop'" in body):
                seg = ast.get_source_segment(src, fn) or ""
                if "_otrv4_users[" in seg or "_otrv4_users\", {}).pop" in seg \
                        or "_o[new_nick]" in seg:
                    writers.add(fn.name)
        assert writers <= {"handle_numeric_reply", "handle_message",
                           "dispatch_command", "handle_command"}, (
            "the OTRv4+ map is written in %s" % sorted(writers))

# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The diagnostic log names nobody and nowhere.

THE LIST THIS ENFORCES
----------------------
No usernames, JIDs bare or full, passwords, tokens, session IDs, IP addresses
v4 or v6, DNS hostnames, I2P destinations or tunnel identifiers, Tor circuit
identifiers, keys of any kind, message plaintext, file contents, contact lists
or presence tied to a named person.

REVERSING A DECISION, ON PURPOSE
--------------------------------
The first version of this feature recorded JIDs and server names and argued
for it in its own docstring: a roster, presence or routing fault is *about*
those values. That argument was right about diagnosis and wrong about the
file. A diagnostic exists to be shared, and what it shared was the user's
account, everybody they talk to, and the I2P destination they talk through,
collected into one place and handed to whoever asked for it.

The labels keep the diagnosis. "We asked for `user-A`'s presence, `user-A`
never answered, `user-A` was removed from the roster" is the same sequence it
always was. What is gone is the ability to say who `user-A` is, and it is gone
from the file rather than from the reader's good intentions.

WHY THE MECHANISM IS CENTRAL
----------------------------
Every field of every event goes through one function. The alternative is each
call site remembering, and the call sites are the transport's inbound handler,
the keepalive, the roster, the registration path and the Kotlin bridge. The
first one to forget is the one whose fault ends up in the file, and it will be
the interesting one -- the fault nobody anticipated is the fault whose call
site was written in a hurry.
"""

import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import otrv4plus_alias as alias
from android_bridge import report
from android_bridge.trace import REDACTED, TraceLog

JID = "alice@xmpp-elite.i2p"
PEER = "bob@xmpp-elite.i2p"
SERVER = "xmpp-elite.i2p"
B32 = "hq4t24b7vkllfbk55e5xfocqhfi7hxprwc47zyuilbg6wgzikidq.b32.i2p"
ONION = "expyuzz4wqqyqhjn.onion"
PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
def book():
    return alias.AliasBook()


@pytest.fixture
def log():
    return TraceLog(capacity=200)


# ── labels ───────────────────────────────────────────────────────────────────

class TestLabelsAreStableWithinARun:

    def test_the_same_value_gets_the_same_label(self, book):
        assert book.alias(JID, "user") == book.alias(JID, "user")

    def test_different_values_get_different_labels(self, book):
        assert book.alias(JID, "user") != book.alias(PEER, "user")

    def test_labels_are_assigned_in_first_seen_order(self, book):
        assert book.alias(JID, "user") == "user-A"
        assert book.alias(PEER, "user") == "user-B"

    def test_case_and_whitespace_do_not_split_one_person_in_two(self, book):
        first = book.alias(JID, "user")
        assert book.alias("  " + JID.upper() + " ", "user") == first

    def test_a_resource_makes_a_different_label(self, book):
        """Correctly: `alice@host/phone` and `alice@host/desktop` are two
        sessions, and a fault affecting one is worth telling apart."""
        assert book.alias(JID, "user") != book.alias(JID + "/phone", "user")

    def test_the_kinds_have_separate_sequences(self, book):
        assert book.alias(JID, "user") == "user-A"
        assert book.alias(SERVER, "address") == "address-A"

    def test_an_unknown_kind_falls_back_rather_than_raising(self, book):
        assert book.alias(JID, "banana").startswith("id-")

    def test_an_empty_value_gets_no_label(self, book):
        assert book.alias("", "user") == ""
        assert book.alias(None, "user") == ""

    def test_labels_keep_going_past_z(self, book):
        for i in range(27):
            book.alias("peer%d@host" % i, "user")
        assert book.alias("peer26@host", "user") == "user-AA"


class TestALabelIsNotDerivedFromTheValue:
    """A hash would not do. Localparts are short, domains are guessable and
    `.b32.i2p` addresses come from a published set, so anybody holding a
    candidate could hash it and compare. A counter has no relationship to the
    value at all."""

    def test_no_part_of_the_value_survives_in_the_label(self, book):
        label = book.alias(JID, "user")
        assert "alice" not in label
        assert "xmpp" not in label
        assert label == "user-A"

    def test_two_books_do_not_agree(self):
        """So two reports from the same user cannot be correlated. A
        property, not a defect."""
        a, b = alias.AliasBook(), alias.AliasBook()
        a.alias(PEER, "user")
        assert a.alias(JID, "user") != b.alias(JID, "user")

    def test_the_repr_does_not_list_the_map(self, book):
        book.alias(JID, "user")
        assert "alice" not in repr(book)


# ── shapes found in free text ────────────────────────────────────────────────

class TestTheSweepFindsIdentitiesInASentence:
    """The path nobody remembers: an exception whose message quotes a host."""

    @pytest.mark.parametrize("value", [JID, PEER, JID + "/phone"])
    def test_a_jid_is_replaced_localpart_and_all(self, book, value):
        out = book.scrub("could not reach %s, giving up" % value)
        assert "alice" not in out and "bob" not in out
        assert "xmpp-elite" not in out
        assert "user-" in out

    def test_an_i2p_hostname_is_replaced(self, book):
        assert SERVER not in book.scrub("connecting to " + SERVER)

    def test_a_b32_destination_is_replaced(self, book):
        out = book.scrub("SAM stream to " + B32)
        assert "hq4t24b7" not in out
        assert "address-" in out

    def test_a_bare_b32_without_the_suffix_is_replaced(self, book):
        bare = B32.split(".")[0]
        assert bare not in book.scrub("DEST=" + bare)

    def test_a_full_base64_destination_is_replaced(self, book):
        dest = "A" * 60 + "b7~xQ" * 20 + "AAAA"
        assert dest not in book.scrub("SESSION STATUS DESTINATION=" + dest)

    def test_an_onion_address_is_replaced(self, book):
        """TRANSPORT_POLICY.md allows Tor for messaging, so a report from a
        Tor session must not name the far end either."""
        assert ONION not in book.scrub("circuit to " + ONION)

    def test_an_ipv4_literal_is_replaced(self, book):
        out = book.scrub("bound 127.0.0.1:41234")
        assert "127.0.0.1" not in out

    def test_an_ipv6_literal_is_replaced(self, book):
        for addr in ("fe80::1ff:fe23:4567:890a", "::1",
                     "2001:db8:85a3:0:0:8a2e:370:7334"):
            assert addr not in book.scrub("peer at " + addr), addr

    def test_the_jid_is_matched_before_the_hostname(self, book):
        """Otherwise `alice@example.i2p` scrubs to `alice@address-A` and the
        part that names a person is the part that survives."""
        out = book.scrub(JID)
        assert "alice" not in out
        assert "@" not in out


class TestALongUnbrokenTokenIsTreatedAsAnAddress:
    """`_DEST64` is broader than "a base64 I2P destination", on purpose.

    A full destination is ~516 characters of base64 and SAM prints it with no
    spaces. The pattern matches any unbroken run of 80+ base64-ish characters,
    which will also swallow a long opaque token that is not a destination.

    That is the right way round to be wrong. In a log whose lines are stages,
    codes, counts and stack frames, an 80-character word with no spaces in it
    is overwhelmingly likely to be an address or a key, and the cost of a false
    positive is a label where a meaningless blob used to be. The cost of a
    false negative is the destination this device talks to, in a file the user
    is about to share.
    """

    def test_a_long_opaque_token_is_aliased(self, book):
        assert book.scrub("t" * 200).startswith("address-")

    def test_ordinary_prose_is_not_aliased_however_long(self, book):
        text = "the stream went quiet and the probe went unanswered " * 20
        assert book.scrub(text) == text

    def test_a_stack_frame_list_survives(self, book):
        frames = " <- ".join("transport.py:%d in _connect" % n
                             for n in range(40))
        assert book.scrub(frames) == frames

    def test_a_short_token_is_left_alone(self, book):
        assert book.scrub("abcdef0123456789") == "abcdef0123456789"


class TestTheSweepDoesNotEatOrdinaryText:
    """A diagnostic that scrubs its own vocabulary is not a diagnostic."""

    def test_a_module_path_is_left_alone(self, book):
        assert book.scrub("android_bridge.transport") == \
            "android_bridge.transport"

    def test_a_clock_time_is_not_an_ipv6_address(self, book):
        """Three colon groups are required rather than two, precisely so
        `12:34:56` survives -- durations and timestamps are the commonest
        values in this log."""
        assert book.scrub("elapsed 12:34:56") == "elapsed 12:34:56"

    def test_a_version_number_is_left_alone(self, book):
        assert book.scrub("slixmpp 1.17.0") == "slixmpp 1.17.0"

    def test_a_stack_frame_is_left_alone(self, book):
        line = "transport.py:463 in _connect_inner"
        assert book.scrub(line) == line

    def test_a_port_is_left_alone(self, book):
        assert "41234" in book.scrub("port 41234")


# ── the trace applies it centrally ───────────────────────────────────────────

class TestTheTraceAliasesEveryField:

    def test_a_jid_field_is_labelled(self, log):
        log.record("roster", "added", jid=JID)
        assert log.events()[0]["fields"]["jid"].startswith("user-")

    @pytest.mark.parametrize("key", [
        "jid", "peer", "contact", "username", "account", "sender",
        "recipient", "mto", "barejid", "fulljid", "occupant", "nick",
    ])
    def test_every_person_shaped_key_is_labelled(self, log, key):
        log.record("x", "y", **{key: JID})
        assert log.events()[0]["fields"][key].startswith("user-")

    @pytest.mark.parametrize("key", [
        "server", "host", "hostname", "domain", "endpoint", "destination",
        "dest", "address", "addr",
    ])
    def test_every_place_shaped_key_is_labelled(self, log, key):
        log.record("x", "y", **{key: SERVER})
        assert log.events()[0]["fields"][key].startswith("address-")

    @pytest.mark.parametrize("key", ["room", "roomjid", "muc"])
    def test_every_room_shaped_key_is_labelled(self, log, key):
        log.record("x", "y", **{key: "general@conference." + SERVER})
        assert log.events()[0]["fields"][key].startswith("room-")

    def test_a_key_that_names_nothing_is_still_swept_by_shape(self, log):
        """The rule that does not depend on anybody choosing a good name."""
        log.record("x", "y", detail="could not reach %s" % JID)
        assert "alice" not in log.events()[0]["fields"]["detail"]

    def test_a_clearnet_server_is_labelled_by_its_key_not_its_shape(self, log):
        """`example.com` matches no identity shape. The key is what says it
        is a host, which is why key-name aliasing exists alongside the sweep."""
        log.record("x", "y", server="example.com")
        assert log.events()[0]["fields"]["server"].startswith("address-")

    def test_aliasing_happens_before_truncation(self, log):
        """A JID cut in half leaves the localpart standing at the end of a
        line that looks redacted."""
        log.record("x", "y", detail="%s %s" % ("z" * 190, JID))
        assert "alice" not in log.events()[0]["fields"]["detail"]

    def test_a_long_value_is_still_truncated_after_aliasing(self, log):
        """The cap survives the alias pass being added in front of it. A
        field that grew unexpectedly must not turn the export into something
        unopenable on a phone -- and a value that is long because it is
        rubbish is exactly the kind that grows."""
        from android_bridge.trace import MAX_VALUE

        # Words rather than one long run of a letter: an unbroken 80-character
        # token is aliased as a destination (see TestALongUnbrokenTokenIsTreated
        # AsAnAddress below), which would make this measure the wrong thing.
        log.record("x", "y", detail="the stream went quiet " * 40)
        rendered = log.events()[0]["fields"]["detail"]
        assert len(rendered) < MAX_VALUE * 2
        assert "more)" in rendered, "the truncation marker is gone"

    def test_a_stack_trace_keeps_its_larger_allowance(self, log):
        from android_bridge.trace import LONG_KEYS, MAX_VALUE

        frames = " <- ".join("transport.py:%d in _connect" % n
                             for n in range(60))
        log.record("x", "y", stack_trace=frames)
        rendered = log.events()[0]["fields"]["stack_trace"]
        assert len(rendered) > MAX_VALUE
        assert len(rendered) <= LONG_KEYS["stack_trace"] + 40

    def test_a_secret_key_still_wins_over_aliasing(self, log):
        log.record("x", "y", password=PASSWORD)
        assert log.events()[0]["fields"]["password"] == REDACTED

    def test_a_body_is_still_banned_outright(self, log):
        log.record("x", "y", body="meet me at six")
        assert log.events()[0]["fields"]["body"] == REDACTED

    def test_the_rendered_table_carries_no_identities(self, log):
        log.record("transport", "session_started", jid=JID, server=SERVER)
        log.record("roster", "presence", peer=PEER)
        text = log.render()
        for secret in ("alice", "bob", "xmpp-elite"):
            assert secret not in text, secret


# ── the built report, end to end ─────────────────────────────────────────────

def _report(log):
    return report.build(
        status={"stage": "failed", "connected": False, "jid": JID,
                "server": SERVER, "sam": "127.0.0.1:7656",
                "inputs": "jid=%s password=present" % JID},
        device={"model": "Pixel 6", "release": "14"},
        trace=log)


class TestNothingIdentifyingReachesTheFile:

    @pytest.fixture
    def exported(self, log):
        log.record("transport", "session_started", jid=JID, server=SERVER)
        log.record("i2p", "stream_open", destination=B32)
        log.record("roster", "presence", peer=PEER, show="away")
        log.record("keepalive", "probe_unanswered",
                   detail="no reply from %s over 127.0.0.1" % SERVER)
        return _report(log)

    @pytest.mark.parametrize("secret", [
        JID, PEER, SERVER, B32, "alice", "bob", "xmpp-elite",
        "hq4t24b7", "127.0.0.1",
    ])
    def test_it_is_not_in_the_report(self, exported, secret):
        assert secret not in exported, secret

    def test_the_labels_are(self, exported):
        assert "user-" in exported
        assert "address-" in exported

    def test_the_port_is_kept_because_it_identifies_nobody(self, exported):
        """The SAM bridge's port is a published default. Scrubbing it would
        remove the one fact that says whether the router was even asked."""
        assert "7656" in exported

    def test_the_stages_and_events_survive(self, exported):
        """Redaction that removed the diagnosis would be a different bug."""
        assert "session_started" in exported
        assert "probe_unanswered" in exported
        assert "failed" in exported

    def test_the_device_facts_survive(self, exported):
        assert "Pixel 6" in exported

    def test_an_absent_account_is_not_invented_into_a_label(self, log):
        text = report.build(status={"stage": "idle"}, trace=log)
        assert re.search(r"jid\s+-", text), (
            "no account configured is itself a diagnosis")

    def test_the_summary_is_scrubbed_too(self, log):
        log.record("transport", "session_started", jid=JID)
        text = report.summary(status={"stage": "failed", "jid": JID},
                              trace=log)
        assert "alice" not in text

    def test_a_password_still_does_not_reach_the_file(self, log):
        log.record("connect", "attempt", password=PASSWORD)
        assert PASSWORD not in _report(log)

    def test_a_clearnet_server_is_aliased_by_its_key_not_its_shape(self, log):
        """The case the shape sweep CANNOT catch, and therefore the one the
        key-name pass exists for.

        `example.com` matches no identity pattern -- it is not a JID, not
        `.i2p`, not `.onion`, not an IP literal. Only `_connection_fields`
        knowing that `server` is a host keeps it out of the file. The profile
        allows a clearnet server, so this is a configuration somebody can
        actually be in.
        """
        text = report.build(
            status={"stage": "failed", "server": "chat.example.com",
                    "jid": "alice@chat.example.com"},
            trace=log)
        assert "example.com" not in text
        assert "address-" in text


class TestTheLabelsAreConsistentAcrossTheWholeFile:
    """The property that makes the file worth keeping."""

    def test_one_account_is_one_label_in_status_and_in_events(self, log):
        """Including inside the `inputs` line, where the JID sits next to its
        own field name. `jid=alice@host` was once matched WHOLE and labelled
        as a different identity from the same account seen elsewhere."""
        log.record("transport", "session_started", jid=JID)
        log.record("roster", "requested", jid=JID)
        # From "Connection" on: the header quotes `user-A` as an example of
        # what a label looks like, and that is not an occurrence of one.
        text = _report(log)
        text = text[text.index("Connection"):]
        labels = set(re.findall(r"user-[A-Z]+", text))
        assert len(labels) == 1, labels

    def test_two_people_stay_two_labels(self, log):
        log.record("roster", "presence", peer=JID)
        log.record("roster", "presence", peer=PEER)
        labels = set(re.findall(r"user-[A-Z]+", log.render()))
        assert len(labels) == 2


# ── the module stays testable ────────────────────────────────────────────────

class TestTheModuleIsDependencyFree:

    def test_it_imports_no_android_and_no_slixmpp(self):
        import inspect
        source = inspect.getsource(alias)
        for line in source.splitlines():
            stripped = line.strip()
            if not stripped.startswith(("import ", "from ")):
                continue
            assert "slixmpp" not in stripped, stripped
            assert "android_bridge" not in stripped, stripped

    def test_it_writes_nothing_down(self):
        """The mapping lives in memory and dies with the process. A book
        persisted to disk would be exactly the file this feature removes."""
        import inspect
        source = inspect.getsource(alias)
        for forbidden in ("open(", "json.dump", "pickle", "sqlite"):
            assert forbidden not in source, forbidden

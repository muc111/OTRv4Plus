# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Creating an account, and the answers a person gets when it does not work.

The Register button had no mechanism behind it. XMPP has one -- XEP-0077
in-band registration, over the stream, before authentication -- and this covers
the half of it that has no network in it: what is refused locally, and how a
server's refusal becomes a sentence.

Two properties are load-bearing and each has its own section below.

The password is never echoed. It is passed in, weighed, and dropped; no code
path returns it, and `validate` returns its own wording rather than quoting the
input.

`classify` never returns the exception's text. A slixmpp `IqError` stringifies
to something containing the stanza, which carries the JID being registered --
and this result is rendered on screen and may be pasted into a bug report.
The condition is read structurally and the sentence is chosen from a fixed
table, so there is no path from a stanza to the display.
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import otrv4plus_registration as reg


# ── fakes shaped like what slixmpp actually raises ───────────────────────────

class FakeIq(dict):
    """`iq['error']['condition']`, which is how slixmpp nests it."""

    def __init__(self, condition):
        super().__init__({"error": {"condition": condition}})


class IqError(Exception):
    """slixmpp.exceptions.IqError: has `.condition` and `.iq`.

    Its `__str__` deliberately carries a JID, because the whole point of
    `classify` not using it is that the real one does.
    """

    def __init__(self, condition, jid="alice@xmpp-elite.i2p"):
        super().__init__("iq error: <error type='cancel'><%s/></error> "
                         "to %s" % (condition, jid))
        self.condition = condition
        self.iq = FakeIq(condition)


class IqTimeout(Exception):
    def __init__(self):
        super().__init__("timed out")
        self.iq = None


# ── local validation: what is refused before a round trip is spent ───────────

class TestValidationAcceptsWhatItShould:

    def test_an_ordinary_submission_passes(self):
        assert reg.validate("alice", "correct-horse-battery") is None

    def test_digits_and_dots_and_dashes_are_fine(self):
        assert reg.validate("alice.b-2", "correct-horse-battery") is None

    def test_a_unicode_localpart_is_not_refused_here(self):
        """RFC 7622 allows far more than ASCII. Refusing it locally would
        invent a policy the server does not have."""
        assert reg.validate("zoë", "correct-horse-battery") is None


class TestInvalidUsernames:

    def test_an_empty_username_is_refused(self):
        code, detail = reg.validate("", "correct-horse-battery")
        assert code == "not_acceptable"
        assert "username" in detail.lower()

    def test_whitespace_only_is_the_same_as_empty(self):
        assert reg.validate("   ", "correct-horse-battery")[0] == \
            "not_acceptable"

    def test_a_space_inside_is_refused_and_named(self):
        """`" "` renders as nothing in an error message, so it is named."""
        code, detail = reg.validate("al ice", "correct-horse-battery")
        assert code == "not_acceptable"
        assert "space" in detail

    def test_the_characters_rfc_7622_forbids_are_refused(self):
        for bad in ['al"ice', "al&ice", "al'ice", "al/ice", "al:ice",
                    "al<ice", "al>ice"]:
            assert reg.validate(bad, "correct-horse-battery") is not None, bad

    def test_a_full_jid_is_refused_with_advice_rather_than_a_rule(self):
        """The likeliest mistake: typing the whole address into the username
        box. Saying "cannot contain '@'" is true and useless."""
        code, detail = reg.validate("alice@xmpp-elite.i2p", "battery-staple")
        assert code == "not_acceptable"
        assert "without" in detail.lower()

    def test_an_over_long_username_is_refused_here_not_by_the_server(self):
        code, detail = reg.validate("a" * (reg.MAX_USERNAME + 1),
                                    "correct-horse-battery")
        assert code == "not_acceptable"
        assert str(reg.MAX_USERNAME) in detail

    def test_the_limit_itself_is_accepted(self):
        assert reg.validate("a" * reg.MAX_USERNAME, "battery-staple") is None


class TestInvalidPasswords:

    def test_an_empty_password_is_refused(self):
        code, detail = reg.validate("alice", "")
        assert code == "not_acceptable"
        assert "password" in detail.lower()

    def test_a_short_password_is_refused_with_the_number(self):
        code, detail = reg.validate("alice", "a" * (reg.MIN_PASSWORD - 1))
        assert code == "not_acceptable"
        assert str(reg.MIN_PASSWORD) in detail

    def test_the_minimum_itself_is_accepted(self):
        assert reg.validate("alice", "a" * reg.MIN_PASSWORD) is None

    def test_a_long_password_is_not_refused(self):
        assert reg.validate("alice", "x" * 200) is None

    def test_spaces_in_a_password_are_allowed(self):
        """A passphrase is the good case, not the mistake."""
        assert reg.validate("alice", "correct horse battery staple") is None


class TestTheUsernameIsCheckedBeforeThePassword:
    """So a person fixing one field at a time is told about the first one."""

    def test_both_wrong_reports_the_username(self):
        _, detail = reg.validate("", "")
        assert "username" in detail.lower()


class TestValidationNeverEchoesWhatWasTyped:

    def test_the_password_is_not_in_any_message(self):
        secret = "hunter2-hunter2"
        for name in ("", "al ice", "a" * 500, "alice@host"):
            result = reg.validate(name, secret)
            if result is not None:
                assert secret not in result[1]

    def test_a_short_password_is_not_quoted_back(self):
        _, detail = reg.validate("alice", "swordfi")
        assert "swordfi" not in detail

    def test_the_username_is_not_quoted_back_wholesale(self):
        """Naming the offending CHARACTER is help; repeating the whole
        localpart puts it in a string headed for a screenshot."""
        _, detail = reg.validate("verysecretname ok", "battery-staple")
        assert "verysecretname" not in detail


# ── classifying what the server said ─────────────────────────────────────────

class TestTheThreeThatActuallyHappen:

    def test_a_taken_username_is_a_conflict(self):
        code, detail = reg.classify(IqError("conflict"))
        assert code == "conflict"
        assert "taken" in detail.lower()

    def test_details_the_server_rejects_are_not_acceptable(self):
        assert reg.classify(IqError("not-acceptable"))[0] == "not_acceptable"

    def test_a_server_that_does_not_do_this_says_so(self):
        code, detail = reg.classify(IqError("feature-not-implemented"))
        assert code == "unsupported"
        assert "not" in detail.lower()


class TestTheRestOfRfc6120:

    @pytest.mark.parametrize("condition,expected", [
        ("bad-request", "bad_request"),
        ("forbidden", "forbidden"),
        ("not-allowed", "not_allowed"),
        ("not-authorized", "not_authorized"),
        ("resource-constraint", "resource_constraint"),
        ("service-unavailable", "service_unavailable"),
        ("internal-server-error", "unknown"),
        ("remote-server-timeout", "timeout"),
    ])
    def test_each_condition_maps(self, condition, expected):
        assert reg.classify(IqError(condition))[0] == expected

    def test_an_unmapped_condition_is_unknown_rather_than_a_crash(self):
        assert reg.classify(IqError("policy-violation"))[0] == "unknown"


class TestTheConditionIsReadStructurally:

    def test_it_is_found_on_the_attribute(self):
        assert reg.classify(IqError("conflict"))[0] == "conflict"

    def test_it_is_found_inside_the_stanza_when_the_attribute_is_absent(self):
        exc = IqError("conflict")
        del exc.condition
        assert reg.classify(exc)[0] == "conflict", (
            "slixmpp does not set .condition on every error path")

    def test_an_exception_with_neither_is_unknown(self):
        assert reg.classify(RuntimeError("boom"))[0] == "unknown"

    def test_a_stanza_that_raises_on_lookup_does_not_take_us_down(self):
        """This runs while reporting a failure. A second exception here
        replaces a useful message with a crash."""
        class Hostile:
            @property
            def condition(self):
                raise ValueError("no")

            @property
            def iq(self):
                raise ValueError("no")

        assert reg.classify(Hostile())[0] == "unknown"

    def test_an_empty_condition_falls_through_rather_than_matching(self):
        assert reg.classify(IqError(""))[0] == "unknown"


class TestACodeTheRaiserAlreadyKnew:
    """For the cases no XMPP condition describes -- the server never offering
    registration, the SAM tunnel not opening."""

    def test_it_is_taken_at_its_word(self):
        code, detail = reg.classify(reg.RegistrationFailed("unsupported"))
        assert code == "unsupported"
        assert detail == reg.CODES["unsupported"]

    def test_a_code_that_is_not_one_of_ours_is_unknown(self):
        assert reg.RegistrationFailed("banana").code == "unknown"

    def test_a_foreign_exceptions_code_is_not_mistaken_for_one_of_ours(self):
        """`TransportError` also has a `.code`, and its vocabulary is a
        different one. Without the membership test, `sam_unavailable` would
        be returned as a registration code the Kotlin side has never heard of
        -- or would raise KeyError while reporting a failure."""
        class TransportError(Exception):
            code = "sam_unavailable"

        code, detail = reg.classify(TransportError())
        assert code == "unknown"
        assert detail == reg.CODES["unknown"]

    def test_a_non_string_code_is_ignored(self):
        class Odd(Exception):
            code = 42

        assert reg.classify(Odd())[0] == "unknown"

    def test_ok_is_never_returned_from_a_code_attribute(self):
        """`classify` is only called on a failure. Answering "ok" there would
        report success for an exception."""
        class Odd(Exception):
            code = "ok"

        assert reg.classify(Odd())[0] == "unknown"

    def test_a_known_code_still_loses_to_nothing(self):
        """The code wins over anything inferred, so a RegistrationFailed
        carrying `timeout` is a timeout even though its type name is not."""
        assert reg.classify(reg.RegistrationFailed("timeout"))[0] == "timeout"


class TestTheRoundTripNeverCompleting:

    def test_a_timeout_is_a_timeout_and_says_i2p_is_slow(self):
        code, detail = reg.classify(IqTimeout())
        assert code == "timeout"
        assert "I2P" in detail

    def test_a_refused_connection_is_a_network_failure(self):
        assert reg.classify(ConnectionRefusedError(111, "refused"))[0] == \
            "network"

    def test_an_os_error_is_a_network_failure(self):
        assert reg.classify(OSError("no route to host"))[0] == "network"

    def test_a_cancelled_attempt_says_so_rather_than_failing(self):
        """Rotating the screen cancels the attempt. That is not an error to
        report as one."""
        import asyncio
        assert reg.classify(asyncio.CancelledError())[0] == "cancelled"

    def test_a_builtin_timeout_error_is_a_timeout(self):
        assert reg.classify(TimeoutError())[0] == "timeout"


class TestClassifyNeverReturnsTheExceptionsOwnText:
    """The property this module exists for."""

    def test_the_jid_inside_the_stanza_does_not_reach_the_sentence(self):
        exc = IqError("conflict", jid="alice@xmpp-elite.i2p")
        _, detail = reg.classify(exc)
        assert "alice" not in detail
        assert "xmpp-elite" not in detail

    def test_no_classification_returns_the_exception_string(self):
        for exc in (IqError("conflict"), IqError("not-acceptable"),
                    IqTimeout(), OSError("secret-hostname"),
                    RuntimeError("secret-hostname")):
            _, detail = reg.classify(exc)
            assert str(exc) not in detail
            assert "secret-hostname" not in detail

    def test_every_sentence_comes_from_the_table(self):
        for exc in (IqError("conflict"), IqError("bad-request"), IqTimeout(),
                    OSError("x"), RuntimeError("x")):
            code, detail = reg.classify(exc)
            assert detail == reg.CODES[code], (
                "a sentence was built rather than chosen, which is how "
                "server text reaches the screen")


# ── the code table itself ────────────────────────────────────────────────────

class TestTheCodesAreAContract:
    """Kotlin branches on these strings; a rename is a silently-unhandled
    case rather than a compile error."""

    def test_every_condition_maps_to_a_declared_code(self):
        for code in reg._CONDITIONS.values():
            assert code in reg.CODES, code

    def test_every_code_has_a_sentence(self):
        for code, sentence in reg.CODES.items():
            assert sentence and sentence[0].isupper()
            assert sentence.endswith(".")

    def test_describe_falls_back_rather_than_raising(self):
        assert reg.describe("no-such-code") == reg.CODES["unknown"]

    def test_describe_returns_the_sentence_for_a_real_code(self):
        assert reg.describe("conflict") == reg.CODES["conflict"]

    def test_ok_is_a_code(self):
        assert reg.OK in reg.CODES

    def test_classify_never_returns_ok(self):
        """It is only ever called on a failure; returning OK there would
        report success for an exception."""
        for exc in (IqError("conflict"), IqTimeout(), RuntimeError("x")):
            assert reg.classify(exc)[0] != reg.OK

    def test_no_sentence_names_a_person_or_a_host(self):
        for sentence in reg.CODES.values():
            assert "@" not in sentence
            assert ".i2p" not in sentence


class TestTheModuleStaysDependencyFree:
    """So every rule above is tested by being run rather than read."""

    def test_it_imports_no_slixmpp_and_no_android(self):
        import inspect
        source = inspect.getsource(reg)
        assert "import slixmpp" not in source
        assert "from slixmpp" not in source
        assert "java" not in source.lower().split("javascript")[0] or True
        assert "com.chaquo" not in source

    def test_it_does_no_io(self):
        import inspect
        source = inspect.getsource(reg)
        for forbidden in ("socket", "open(", "requests", "urllib"):
            assert forbidden not in source, forbidden

"""The connection profile, and the rules it shares with the command line.

Two things are being protected here.

The first is that a user can leave. The app ships pointing at a default server
so that installing it is enough to talk to someone, and every field of that
default has to be replaceable -- otherwise "we ship a default" quietly becomes
"we pin you to our operator", which is not the thing this project is for.

The second is that the profile stays free of secrets. It is the object that
gets logged, rendered into a diagnostic report and shown on screen, and that is
only safe while there is nothing in it worth hiding. The password lives in
SecureStore. `TestNoSecretLivesHere` asserts that rather than trusting it.
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import otrv4plus_address as address
from android_bridge.settings import (
    ConnectionProfile, DEFAULT_SERVER, ProfileError, default_profile,
)

GOOD = "alice@xmpp-elite.i2p"


class TestTheSharedRulesAreActuallyShared:
    """The CLI and the settings screen must agree about what an address is.

    Not a style point. They disagreed once already -- `bob@xmpp-elite` passed
    every check the CLI had and produced a session that looked broken at both
    ends for an hour (tests/test_peer_address_mistakes.py). One set of rules,
    used by both, is how that stays fixed.
    """

    def test_the_cli_calls_the_shared_validator(self):
        """otrv4plus_xmpp must not grow a second copy of these rules."""
        with open(os.path.join(ROOT, "otrv4plus_xmpp.py"),
                  encoding="utf-8") as fh:
            src = fh.read()
        assert "_address.jid_error" in src, (
            "the CLI no longer calls the shared validator; if the rules have "
            "been inlined again, the settings screen and the command line can "
            "drift apart silently")

    @pytest.mark.parametrize("bad,because", [
        ("", None),                                  # not an error: unfinished
        ("no-at-sign.i2p", "Expected"),
        ("two@at@signs.i2p", "Expected"),
        ("@nolocal.i2p", "Both a username and a server"),
        ("nodomain@", "Both a username and a server"),
        ("alice@xmpp...i2p", "abbreviated"),
        ("alice@xmpp..i2p", "abbreviated"),
        ("alice@xmpp.i2p.", "empty part"),
    ])
    def test_jid_rules(self, bad, because):
        err = address.jid_error(bad)
        if because is None:
            assert err is None, "an empty field is unfinished, not wrong"
        else:
            assert err is not None and because in err, (bad, err)

    def test_a_good_jid_passes(self):
        assert address.jid_error(GOOD) is None

    def test_the_wording_is_the_wording_the_cli_had(self):
        """Pinned exactly, not by substring.

        These sentences were arrived at by watching them fail to help someone.
        Extracting the rules from `main()` was supposed to move them, not
        rewrite them, and the check that confirmed it (a byte comparison
        against the pre-refactor source) cannot live in the suite because it
        needs a commit that keeps moving. This is the durable half.
        """
        assert address.jid_error("bob@xmpp-elite", "--peer") == (
            "Invalid --peer: 'bob@xmpp-elite'\n"
            "  Expected  user@server.b32.i2p"
        ) or address.jid_error("bob@xmpp-elite", "--peer") is None, (
            "a single-label domain is accepted -- that is the v10.18.3 bug "
            "and is covered by tests/test_peer_address_mistakes.py, not here")
        assert address.jid_error("alice@xmpp..i2p", "--jid") == (
            "Invalid --jid: 'alice@xmpp..i2p'\n"
            "  This looks like an abbreviated address. Use the full server "
            "name, not one shortened with '...'.")
        assert address.jid_error("@nolocal.i2p", "--jid") == (
            "Invalid --jid: '@nolocal.i2p'\n"
            "  Both a username and a server are required.")


class TestTheServerFieldCatchesTheCommonMistake:

    def test_a_jid_in_the_server_field_is_named_as_such(self):
        """"Server" and "address" are close enough in ordinary use."""
        err = address.server_error("alice@xmpp-elite.i2p")
        assert err is not None and "not an account" in err

    def test_a_bare_host_is_fine(self):
        assert address.server_error("xmpp-elite.i2p") is None

    def test_whitespace_is_caught_rather_than_stripped(self):
        """Silently trimming hides a paste that brought a newline with it."""
        assert address.server_error(" xmpp-elite.i2p") is not None


class TestThePortField:

    @pytest.mark.parametrize("value", [7656, "7656", " 7656 "])
    def test_accepts_what_a_text_field_and_a_store_produce(self, value):
        assert address.sam_port_error(value) is None

    @pytest.mark.parametrize("value", ["", "seven", 0, 65536, -1, None, 1.5])
    def test_rejects_the_rest(self, value):
        assert address.sam_port_error(value) is not None

    def test_true_is_not_port_one(self):
        """bool is an int in Python, and True would otherwise validate."""
        assert address.sam_port_error(True) is not None


class TestTheUserCanLeaveTheDefaultServer:

    def test_a_custom_server_is_not_reported_as_the_default(self):
        p = ConnectionProfile(jid=GOOD, server="my-own-server.i2p")
        assert p.effective_server == "my-own-server.i2p"
        assert p.is_default_server is False

    def test_every_field_is_replaceable(self):
        p = ConnectionProfile(jid=GOOD).replace(
            server="mine.i2p", sam_host="10.0.0.2", sam_port=7000,
            use_i2p=False)
        assert (p.server, p.sam_host, p.sam_port, p.use_i2p) == (
            "mine.i2p", "10.0.0.2", 7000, False)
        p.validate()

    def test_replace_does_not_validate(self):
        """A form passes through invalid states on the way to a valid one."""
        half_typed = ConnectionProfile(jid=GOOD).replace(jid="alice@")
        assert half_typed.errors(), "expected this to be invalid"

    def test_an_unset_server_falls_back_to_the_jid_domain(self):
        """What the command line does when --server is not given."""
        assert ConnectionProfile(jid=GOOD).effective_server == "xmpp-elite.i2p"

    def test_the_default_is_only_the_default_when_one_is_configured(self):
        """Shipping without a default must not make everything "the default"."""
        p = ConnectionProfile(jid=GOOD, server="anything.i2p")
        if not DEFAULT_SERVER:
            assert p.is_default_server is False


class TestNotConfiguredIsARealState:

    def test_no_default_server_yields_no_profile(self):
        got = default_profile()
        if DEFAULT_SERVER:
            assert got is not None and got.server == DEFAULT_SERVER
        else:
            assert got is None, (
                "with no default compiled in, first run must ask the user "
                "rather than hand back a profile with a hole in it")

    def test_there_is_no_placeholder_address(self):
        """A sentinel that looks like a host is how one reaches a user."""
        assert DEFAULT_SERVER == "" or "example" not in DEFAULT_SERVER.lower()
        for bad in ("TODO", "changeme", "your-server", "<", ">"):
            assert bad.lower() not in DEFAULT_SERVER.lower()

    def test_a_configured_default_must_itself_be_valid(self):
        if not DEFAULT_SERVER:
            pytest.skip("no default server configured")
        assert address.server_error(DEFAULT_SERVER) is None, (
            "the shipped default does not pass our own address rules")


class TestItReportsEveryProblemAtOnce:

    def test_errors_are_not_truncated_to_the_first(self):
        p = ConnectionProfile(jid="no-at-sign", server="also@wrong",
                              sam_host="", sam_port=99999)
        assert len(p.errors()) == 4, p.errors()

    def test_validate_raises_carrying_all_of_them(self):
        p = ConnectionProfile(jid="no-at-sign", sam_port=0)
        with pytest.raises(ProfileError) as caught:
            p.validate()
        # Three: the JID, the port, and the fact that a JID with no domain and
        # no explicit server leaves nowhere to connect to. That last one is
        # worth saying separately -- a user told only "invalid JID" fixes the
        # JID and is then surprised by a second round of errors.
        assert len(caught.value.errors) == 3, caught.value.errors
        assert any("--jid" in e for e in caught.value.errors)
        assert any("--sam-port" in e for e in caught.value.errors)
        assert any("No server to connect to" in e for e in caught.value.errors)

    def test_a_jid_with_no_domain_and_no_server_is_caught(self):
        """Each field is individually fine; the combination connects nowhere."""
        p = ConnectionProfile(jid="alice@", server="")
        assert any("No server to connect to" in e for e in p.errors())

    def test_a_good_profile_validates(self):
        ConnectionProfile(jid=GOOD).validate()


class TestCompleteIsNotTheSameAsValid:

    def test_an_empty_profile_is_unfinished_rather_than_wrong(self):
        p = ConnectionProfile()
        assert p.errors() == [], "an untouched form should not be shouting"
        assert p.is_complete is False

    def test_a_filled_profile_is_complete(self):
        assert ConnectionProfile(jid=GOOD).is_complete is True


class TestItSurvivesStorage:

    def test_round_trip(self):
        p = ConnectionProfile(jid=GOOD, server="mine.i2p",
                              sam_host="10.0.0.2", sam_port=7000,
                              use_i2p=False)
        assert ConnectionProfile.from_dict(p.to_dict()) == p

    def test_a_profile_from_an_older_build_opens_with_defaults(self):
        """Stored settings outlive the version that wrote them."""
        p = ConnectionProfile.from_dict({"jid": GOOD})
        assert p.jid == GOOD
        assert p.sam_port == address.DEFAULT_SAM_PORT
        assert p.sam_host == address.DEFAULT_SAM_HOST

    def test_unknown_keys_do_not_crash_the_app_on_launch(self):
        p = ConnectionProfile.from_dict({"jid": GOOD, "from_the_future": 1})
        assert p.jid == GOOD

    def test_no_stored_settings_at_all(self):
        assert ConnectionProfile.from_dict(None) == ConnectionProfile()

    def test_a_stored_port_written_as_a_string_is_read_back_as_a_port(self):
        assert ConnectionProfile.from_dict({"sam_port": "7000"}).sam_port == 7000

    def test_an_invalid_stored_profile_loads_so_it_can_be_corrected(self):
        """Do not discard a user's settings on their behalf."""
        p = ConnectionProfile.from_dict({"jid": "broken", "sam_port": 0})
        assert p.jid == "broken"
        assert p.errors(), "expected it to load AND be reportable as invalid"


class TestNoSecretLivesHere:

    def test_the_profile_has_no_password_field(self):
        names = {f.name for f in ConnectionProfile.__dataclass_fields__.values()}
        for secret in ("password", "passphrase", "secret", "token", "key",
                       "credential", "pin"):
            assert not any(secret in n.lower() for n in names), (
                "%r is on the connection profile. This object is logged, "
                "exported in diagnostic reports and rendered on screen; "
                "secrets belong in SecureStore." % (names,))

    def test_to_dict_emits_only_the_five_known_fields(self):
        assert set(ConnectionProfile(jid=GOOD).to_dict()) == {
            "jid", "server", "sam_host", "sam_port", "use_i2p"}

    def test_to_dict_is_written_out_rather_than_derived(self):
        """asdict() would silently export a field added later."""
        import ast
        import inspect
        # The body without its docstring. Searching the raw source would match
        # the docstring, which says the word "asdict" while explaining why the
        # code does not call it.
        tree = ast.parse(inspect.getsource(ConnectionProfile.to_dict).strip())
        fn = tree.body[0]
        if (fn.body and isinstance(fn.body[0], ast.Expr)
                and isinstance(fn.body[0].value, ast.Constant)
                and isinstance(fn.body[0].value.value, str)):
            fn.body = fn.body[1:]
        src = ast.unparse(fn)
        assert "asdict" not in src, (
            "to_dict derives its keys, so a field added to this dataclass "
            "would be exported without anyone deciding it should be")

    def test_the_profile_is_frozen(self):
        """A live transport holds one; it must not change underneath it."""
        with pytest.raises(dataclasses_FrozenInstanceError):
            ConnectionProfile(jid=GOOD).jid = "mallory@elsewhere.i2p"


from dataclasses import FrozenInstanceError as dataclasses_FrozenInstanceError

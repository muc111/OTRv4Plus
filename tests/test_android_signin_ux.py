# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Signing in without knowing what a b32 address is.

The rules -- what a bare username resolves to, when a full address is
respected, what a custom server does -- are `SignInTest`, which EXECUTES. What
is here is the screen and the wiring: that the server is a dropdown rather than
a field full of routing information, that the default destination is applied
internally, and that custom routing is still reachable for anyone who wants it.

The destination is routing information, not a trust anchor, and compiling it in
does not make it one: the DAKE pins the peer's identity key end to end by TOFU.
"""

import io
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JAVA = os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                    "otrv4plus", "android")

#: The default server's destination. Lives in ONE place, and this test names it
#: only to prove it is not in the other places.
B32 = "hq4t24b7vkllfbk55e5xfocqhfi7hxprwc47zyuilbg6wgzikidq.b32.i2p"


def _read(*parts):
    with io.open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def _code_only(text):
    text = re.sub(r"/\*(?:.|\n)*?\*/", " ", text)
    return re.sub(r"//[^\n]*", "", text)


@pytest.fixture(scope="module")
def screen():
    return _read(JAVA, "ui", "ConnectScreen.kt")


@pytest.fixture(scope="module")
def signin():
    return _read(JAVA, "connection", "SignIn.kt")


class TestTheUserNeverTypesAB32:

    def test_the_destination_lives_in_python_only(self):
        settings = _read(ROOT, "android_bridge", "settings.py")
        assert B32 in settings, "the default destination moved or was lost"

    def test_it_is_not_duplicated_into_kotlin(self):
        """Two copies is two places to change when the server moves, and the
        second one is always the one that gets missed.

        SHIPPED code only. A unit test may use the string as sample data for
        "a custom route is still accepted", which is the opposite of hiding a
        hard-coded default in the app.
        """
        for root, _dirs, files in os.walk(
                os.path.join(ROOT, "android", "app", "src", "main")):
            for name in files:
                if not name.endswith(".kt"):
                    continue
                text = _read(root, name)
                assert B32 not in text, (
                    "%s hard-codes the default destination" % name)

    def test_the_sign_in_layer_holds_a_name_not_a_route(self, signin):
        assert 'DEFAULT_DOMAIN = "xmpp-elite.i2p"' in signin
        assert ".b32." not in _code_only(signin)

    def test_the_default_leaves_the_route_to_the_bridge(self, signin):
        """Blank is how the profile already spells "use the compiled-in
        destination", and it is what lets `is_default_server` tell a
        deliberate choice from an inherited one."""
        block = signin[signin.index("val server = when (choice)"):]
        block = block[:block.index("}")]
        assert 'Choice.DEFAULT -> ""' in block


class TestTheServerIsADropdown:

    def test_there_is_a_dropdown(self, screen):
        assert "ExposedDropdownMenuBox" in screen, (
            "the server is still a free-text field, so signing in means "
            "knowing an address the app already knows")

    def test_the_default_is_offered_by_name(self, screen):
        assert "SignIn.DEFAULT_DOMAIN" in screen

    def test_another_server_is_offered(self, screen):
        assert "Another server" in screen

    def test_a_custom_field_appears_only_when_chosen(self, screen):
        code = _code_only(screen)
        assert "if (choice == SignIn.Choice.CUSTOM)" in code

    def test_the_custom_field_accepts_a_b32_for_those_who_want_one(self,
                                                                   screen):
        """The architecture must still allow explicit routing. The point is
        that nobody NEEDS it."""
        assert "full .b32.i2p destination" in screen


class TestTheAccountFieldAsksForAUsername:

    def test_the_label_is_username(self, screen):
        assert 'label = { Text("Username") }' in screen

    def test_the_placeholder_is_a_username_not_an_address(self, screen):
        assert 'placeholder = { Text("alice") }' in screen
        assert "you@server.i2p" not in screen

    def test_the_resolved_address_is_shown_back(self, screen):
        """So the user can see where they are about to end up without having
        to assemble it themselves."""
        code = _code_only(screen)
        assert "target?.jid" in code

    def test_a_bad_entry_says_what_is_wrong(self, screen):
        code = _code_only(screen)
        assert "isError =" in code
        assert "problem" in code


class TestTheRulesAreNotInTheScreen:
    """A Compose file cannot be executed here, so anything decided inside one
    is decided where no test can reach it."""

    def test_the_screen_decides_nothing(self, screen):
        code = _code_only(screen)
        assert "SignIn.problem(" in code
        assert "SignIn.resolve(" in code
        # No ad-hoc address assembly in the screen.
        assert not re.search(r'"\$\w+@\$\w+"', code), (
            "the screen builds a JID itself, which is a rule no test runs")

    def test_the_rules_have_no_android_import(self, signin):
        assert "import android" not in signin
        assert "import androidx" not in signin


class TestTheChoiceReachesTheConnection:

    def test_the_view_model_passes_the_server(self):
        vm = _code_only(_read(JAVA, "ConnectionViewModel.kt"))
        assert "fun connect(jid: String, password: String, server: String" in vm

    def test_the_service_carries_it_in_the_intent(self):
        service = _code_only(_read(JAVA, "connection",
                                   "OtrConnectionService.kt"))
        assert "EXTRA_SERVER" in service
        assert "putExtra(EXTRA_SERVER, server)" in service

    def test_the_server_is_not_stored_with_the_credentials(self):
        """It is not a secret, and it is recoverable from the JID's domain.
        Putting it in the vault would widen what the vault holds for no gain.
        """
        creds = _read(JAVA, "security", "CredentialStore.kt")
        assert "server" not in _code_only(creds).lower()

    def test_a_remembered_custom_account_keeps_its_route(self):
        service = _code_only(_read(JAVA, "connection",
                                   "OtrConnectionService.kt"))
        assert "SignIn.choiceFor(it.jid)" in service, (
            "a remembered custom server reverts to the default on relaunch, "
            "so the app reconnects somewhere the user did not choose")

    def test_the_prepared_connection_gets_the_server(self):
        service = _code_only(_read(JAVA, "connection",
                                   "OtrConnectionService.kt"))
        assert "core.prepareConnection(jid.trim(), server.trim())" in service

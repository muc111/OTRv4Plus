# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The rooms screen: what it offers, and the one thing it must say.

Compose cannot be compiled here -- `dl.google.com` is blocked -- so these read
the source. The decisions are deliberately not in the composable: `RoomStanding`
and `RoomOutcome` are plain Kotlin with tests that run, and
`otrv4plus_muc.privileges` decides who may do what and is tested by being
executed. What is left here is layout, and layout is what this file checks.

THE ONE THING. A room is not encrypted. OTRv4+ is a two-party protocol and a
MUC message is fanned out by the service to everybody present, so a room is
plaintext to the server hosting it. An app that shows security state on one
screen and says nothing on another is inviting exactly the wrong conclusion,
and `TestItSaysRoomsAreNotEncrypted` is what keeps the sentence there.
"""

import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

UI = os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                  "otrv4plus", "android")
SCREEN = os.path.join(UI, "ui", "RoomsScreen.kt")
MODEL = os.path.join(UI, "RoomsViewModel.kt")
BRIDGE = os.path.join(UI, "bridge", "ChaquopyOtrCore.kt")
MAIN = os.path.join(UI, "MainActivity.kt")
LIST = os.path.join(UI, "ui", "ConversationsScreen.kt")
GRADLE = os.path.join(ROOT, "android", "app", "build.gradle.kts")


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def code_of(path):
    """Source with comments stripped, so a test does not match the comment
    explaining why something is absent."""
    text = re.sub(r"/\*.*?\*/", "", read(path), flags=re.S)
    return "\n".join(line for line in text.splitlines()
                     if not line.lstrip().startswith("//"))


def body_of(text, signature):
    start = text.index(signature)
    brace = text.index("{", start)
    depth = 0
    for i in range(brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[brace:i + 1]
    raise AssertionError("unbalanced braces after %r" % signature)


@pytest.fixture(scope="module")
def screen():
    return code_of(SCREEN)


@pytest.fixture(scope="module")
def model():
    return code_of(MODEL)


# ── the claim that must not be made ──────────────────────────────────────────

class TestItSaysRoomsAreNotEncrypted:

    def test_the_sentence_is_on_the_screen(self, screen):
        text = read(SCREEN)
        assert "not end-to-end" in text or "not end-to-end encrypted" in text

    def test_it_names_who_can_read_them(self, screen):
        """"Not encrypted" is abstract. "The server hosting the room can read
        them" is the fact somebody can act on."""
        assert "server hosting the room can read" in screen

    def test_it_distinguishes_rooms_from_one_to_one(self, screen):
        assert "One-to-one" in screen or "one-to-one" in screen

    def test_no_security_state_is_rendered_here(self, screen):
        """A padlock or an ENCRYPTED badge on this screen would be a claim
        about something that is not true of a room."""
        for forbidden in ("SecurityState", "securityState", "ENCRYPTED",
                          "fingerprint", "Fingerprint"):
            assert forbidden not in screen, forbidden


# ── discovery, not guesswork ─────────────────────────────────────────────────

class TestTheServiceIsFoundRatherThanAssumed:

    def test_the_view_model_discovers(self, model):
        assert "discoverServices()" in model

    def test_it_picks_the_conference_text_identity(self, model):
        """`conference.<domain>` is a convention, not a rule; `rooms.`,
        `muc.` and `chat.` are all in use."""
        assert "hostsRooms" in model

    def test_no_service_name_is_hard_coded(self, model):
        assert "conference." not in model

    def test_discovery_runs_once_per_screen_not_per_recomposition(self, screen):
        """Two I2P round trips. Repeating them on every recomposition would
        make the screen unusable."""
        assert "LaunchedEffect(Unit)" in screen
        assert "model.discovered" in screen

    def test_having_asked_is_distinguished_from_having_found_nothing(
            self, model):
        assert "var discovered by mutableStateOf" in model

    def test_a_server_with_no_rooms_service_says_so(self, screen):
        assert "does not advertise a rooms service" in screen

    def test_joining_by_address_is_still_offered_then(self, screen):
        """A hidden room is absent from disco by design, so an empty list is
        never evidence that there is nothing to join."""
        # Matched loosely because the sentence is split across concatenated
        # string literals to fit the line length; a test that demanded the
        # whole sentence would break on rewrapping rather than on meaning.
        assert "join one by " in screen
        assert "join by address" in screen


# ── what is offered, and to whom ─────────────────────────────────────────────

class TestTheActions:

    @pytest.mark.parametrize("action", ["Join", "Create", "Leave",
                                        "Delete room"])
    def test_it_is_offered(self, screen, action):
        assert 'Text("%s")' % action in screen, action

    def test_delete_is_offered_only_to_an_owner(self, screen):
        """`standing.destroy` comes from `otrv4plus_muc.privileges`, which
        derives it from XEP-0045 §5.1. Offering it to anybody else is a button
        that fails minutes after it is pressed."""
        assert "if (standing.destroy)" in screen

    def test_leave_is_offered_to_everybody_in_the_room(self, screen):
        block = screen[screen.index('Text("Leave")') - 400:
                       screen.index('Text("Leave")')]
        assert "standing.destroy" not in block

    def test_create_is_the_secondary_action(self, screen):
        join = screen.index('Text("Join")')
        create = screen.index('Text("Create")')
        assert join < create
        assert "OutlinedButton" in screen[join:create]

    def test_nothing_is_offered_while_something_is_running(self, screen):
        assert "busy == null" in screen

    def test_joining_needs_a_nickname(self, screen):
        assert "nick.isNotBlank()" in screen


class TestBothQuestionsAreShown:
    """Affiliation is standing with the room and survives leaving; role is
    standing in this visit. An owner who joined as a visitor cannot speak, and
    showing one of the two would make that unexplainable."""

    def test_the_affiliation_is_rendered(self, screen):
        assert "standing.affiliation" in screen

    def test_the_role_is_rendered(self, screen):
        assert "standing.role" in screen

    def test_being_unable_to_speak_is_said_rather_than_left_to_be_found(
            self, screen):
        assert "standing.speak" in screen
        assert "read-only" in screen


class TestWhatAFailureInvitesTheUserToDo:

    def test_a_taken_nickname_points_at_the_nickname(self, screen):
        assert "isAboutTheNickname" in screen
        assert "different nickname" in screen

    def test_a_retry_is_only_offered_where_it_could_work(self, screen):
        """A ban will not stop being a ban, and a retry over I2P is four
        minutes of somebody's evening."""
        assert "worthRetrying" in screen

    def test_the_sentence_comes_from_python(self, screen):
        assert "it.detail" in screen


# ── the view model ───────────────────────────────────────────────────────────

class TestTheViewModel:

    def test_every_call_runs_off_the_main_thread(self, model):
        """A blocking Chaquopy call on the main thread is an ANR, and every
        one of these is an I2P round trip."""
        for name in ("fun discover(", "fun refreshRooms(", "private fun enter(",
                     "fun leave(", "fun destroy("):
            assert "Dispatchers.IO" in body_of(model, name), name

    def test_a_failed_join_does_not_put_you_in_the_room(self, model):
        """An entry with no privileges reads as a room that is broken rather
        than one that refused you."""
        assert "if (outcome.ok) joined[room] = standing" in model

    def test_leaving_removes_the_room_whatever_the_service_said(self, model):
        """Leaving is unavailable presence, not a request that can be
        refused. A room left in the list after a failed leave is one the user
        cannot get out of."""
        block = body_of(model, "fun leave(")
        assert "joined.remove(room)" in block
        assert "if (outcome.ok) joined.remove" not in block

    def test_destroying_removes_it_only_on_success(self, model):
        block = body_of(model, "fun destroy(")
        assert "if (outcome.ok) joined.remove(room)" in block

    def test_it_does_not_re_derive_permissions(self, model):
        """One place decides, and it is `otrv4plus_muc.privileges`. A second
        derivation here could disagree, and the disagreement would show up as
        a button that fails."""
        for forbidden in ('== "owner"', '== "moderator"', '== "admin"'):
            assert forbidden not in model, forbidden

    def test_only_one_operation_at_a_time(self, model):
        assert "if (busy != null) return" in model


# ── the bridge ───────────────────────────────────────────────────────────────

class TestTheBridge:

    @pytest.fixture(scope="class")
    @classmethod
    def bridge(cls):
        return code_of(BRIDGE)

    @pytest.mark.parametrize("name", [
        "fun discoverServices(", "fun discoverRooms(", "fun joinRoom(",
        "fun createRoom(", "fun leaveRoom(", "fun destroyRoom(",
        "fun joinedRooms(", "fun roomStanding(",
    ])
    def test_it_exists(self, bridge, name):
        assert name in bridge, name

    def test_nothing_here_throws_for_an_ordinary_failure(self, bridge):
        """A PyException crossing Chaquopy keeps only its message, and a MUC
        error's message carries the room, the service and the nickname."""
        assert "notPrepared()" in bridge
        block = bridge[bridge.index("fun discoverServices("):
                       bridge.index("private fun notPrepared")]
        assert "throw" not in block

    def test_the_privileges_are_read_rather_than_derived(self, bridge):
        for name in ("speak", "change_subject", "kick", "ban", "configure",
                     "destroy", "grant_membership"):
            assert '"%s"' % name in bridge, name


# ── navigation and packaging ─────────────────────────────────────────────────

class TestItIsReachable:

    def test_the_conversation_list_offers_rooms(self):
        assert 'Text("Rooms")' in code_of(LIST)

    def test_main_activity_has_a_rooms_screen(self):
        text = code_of(MAIN)
        assert "Screen.ROOMS" in text
        assert "RoomsScreen(" in text

    def test_the_rooms_view_model_is_given_the_core(self):
        assert "roomsModel.core = connection.core" in code_of(MAIN)

    def test_the_nickname_is_seeded_but_editable(self):
        """A nickname in a room is not an identity claim and the app should
        not imply it is."""
        assert "defaultNick" in code_of(MAIN)
        assert "onValueChange = { nick = it }" in code_of(SCREEN)


class TestThePythonIsPackaged:

    def test_the_muc_module_ships(self):
        assert '"otrv4plus_muc.py"' in read(GRADLE), (
            "imported by android_bridge.transport at module scope, so a "
            "missing entry is an ImportError at launch")

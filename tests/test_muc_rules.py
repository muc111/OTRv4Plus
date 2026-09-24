# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Rooms: who may do what, and what a refusal means.

THE MISTAKE THIS MODULE EXISTS TO PREVENT
-----------------------------------------
Conflating affiliation with role. Affiliation is standing with the room and
survives leaving; role is standing in this visit and is assigned on join. An
owner who joined a moderated room as a visitor cannot speak until given voice,
and a moderator who is not an owner cannot destroy a room however much of it
they run. A UI that asked only one of the two questions would enable buttons
the server refuses -- and over I2P that refusal arrives a long way after the
press, which teaches the user the app is unreliable.

WHAT IS NOT CLAIMED
-------------------
Nothing here says a room is encrypted, because it is not. OTRv4+ is a
two-party protocol and a MUC message is fanned out by the service to everybody
present, so a room is plaintext to the server hosting it. That is a property of
group chat, not a gap in this module, and the UI states it.
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import otrv4plus_muc as muc

ROOM = "general@rooms.xmpp-elite.i2p"


class Stanza(dict):
    def __init__(self, condition):
        super().__init__({"error": {"condition": condition}})


class IqError(Exception):
    def __init__(self, condition):
        super().__init__("iq error <%s/> in %s as bob" % (condition, ROOM))
        self.condition = condition
        self.iq = Stanza(condition)


class PresenceError(Exception):
    """How a FAILED JOIN arrives. Not an IqError -- joining is presence, and a
    lookup that only knew about `.iq` would miss every join failure there is."""

    def __init__(self, condition):
        super().__init__("presence error <%s/> from %s/bob"
                         % (condition, ROOM))
        self.presence = Stanza(condition)


# ── the two vocabularies are two ─────────────────────────────────────────────

class TestAffiliationAndRoleAreDifferentQuestions:

    def test_an_owner_who_is_a_visitor_cannot_speak(self):
        """Standing in the room does not grant voice in a moderated one."""
        p = muc.privileges("owner", "visitor")
        assert p.speak is False
        assert p.destroy is True, "and they can still destroy it"

    def test_a_moderator_who_owns_nothing_cannot_destroy(self):
        p = muc.privileges("none", "moderator")
        assert p.kick is True
        assert p.destroy is False
        assert p.configure is False

    def test_the_two_are_reported_back(self):
        p = muc.privileges("admin", "participant")
        assert p.affiliation == "admin"
        assert p.role == "participant"


class TestSpeaking:

    def test_a_participant_may(self):
        assert muc.privileges("none", "participant").speak is True

    def test_a_moderator_may(self):
        assert muc.privileges("none", "moderator").speak is True

    def test_a_visitor_may_not(self):
        assert muc.privileges("member", "visitor").speak is False

    def test_somebody_not_in_the_room_may_not(self):
        assert muc.privileges("member", "none").speak is False


class TestModeration:

    def test_only_a_moderator_kicks(self):
        assert muc.privileges("owner", "moderator").kick is True
        assert muc.privileges("owner", "participant").kick is False

    def test_banning_is_an_affiliation_question_not_a_role_one(self):
        """A ban outlives the visit, so it is decided by standing."""
        assert muc.privileges("admin", "participant").ban is True
        assert muc.privileges("none", "moderator").ban is False

    def test_granting_membership_needs_admin_or_owner(self):
        assert muc.privileges("admin", "visitor").grant_membership is True
        assert muc.privileges("member", "moderator").grant_membership is False


class TestOwnership:

    def test_only_an_owner_configures(self):
        assert muc.privileges("owner", "participant").configure is True
        assert muc.privileges("admin", "moderator").configure is False

    def test_only_an_owner_destroys(self):
        """§10.9. An admin who runs the room day to day still cannot delete
        it, and a Destroy button offered to them is a button that fails."""
        assert muc.privileges("owner", "visitor").destroy is True
        assert muc.privileges("admin", "moderator").destroy is False
        assert muc.privileges("member", "moderator").destroy is False


class TestAnOutcastHasNothing:

    def test_every_privilege_is_denied(self):
        p = muc.privileges("outcast", "moderator")
        for name in p.__slots__:
            if name in ("affiliation", "role"):
                continue
            assert getattr(p, name) is False, name

    def test_the_role_is_dropped_too(self):
        """They are not in the room. Reporting them as a moderator would be a
        claim about a visit that is not happening."""
        assert muc.privileges("outcast", "moderator").role == "none"


class TestNotKnowingGrantsLess:
    """A server answering something this module has not heard of must not
    produce a UI in which every button is enabled."""

    def test_an_unknown_affiliation_is_treated_as_none(self):
        assert muc.privileges("supremo", "moderator").destroy is False
        assert muc.privileges("supremo", "moderator").affiliation == "none"

    def test_an_unknown_role_is_treated_as_none(self):
        assert muc.privileges("owner", "overlord").speak is False
        assert muc.privileges("owner", "overlord").role == "none"

    def test_empty_values_do_not_raise(self):
        p = muc.privileges("", "")
        assert p.speak is False and p.destroy is False

    def test_none_does_not_raise(self):
        assert muc.privileges(None, None).speak is False


class TestEveryCombinationIsAnswerable:

    @pytest.mark.parametrize("aff", muc.AFFILIATIONS)
    @pytest.mark.parametrize("role", muc.ROLES)
    def test_it_returns_a_full_answer(self, aff, role):
        p = muc.privileges(aff, role)
        for name in p.__slots__:
            value = getattr(p, name)
            assert isinstance(value, (bool, str)), name

    def test_as_dict_carries_every_field(self):
        p = muc.privileges("owner", "moderator")
        assert set(p.as_dict()) == set(p.__slots__)

    def test_equality_is_by_value(self):
        assert muc.privileges("owner", "moderator") == \
            muc.privileges("owner", "moderator")
        assert muc.privileges("owner", "moderator") != \
            muc.privileges("admin", "moderator")

    def test_the_repr_names_no_room_and_no_person(self):
        assert "@" not in repr(muc.privileges("owner", "moderator"))


# ── addresses ────────────────────────────────────────────────────────────────

class TestPullingAnAddressApart:

    def test_the_room_drops_the_nickname(self):
        assert muc.room_of(ROOM + "/bob") == ROOM

    def test_the_nickname_is_readable(self):
        assert muc.nick_of(ROOM + "/bob") == "bob"

    def test_a_bare_room_has_no_nickname(self):
        assert muc.nick_of(ROOM) == ""

    def test_the_service_is_the_domain(self):
        assert muc.service_of(ROOM) == "rooms.xmpp-elite.i2p"

    def test_a_nickname_containing_nothing_odd_survives(self):
        assert muc.nick_of(ROOM + "/Bob Smith") == "Bob Smith"

    def test_rubbish_does_not_raise(self):
        assert muc.room_of(None) == ""
        assert muc.service_of("") == ""


class TestValidatingARoomAddress:

    def test_a_good_one_passes(self):
        assert muc.validate_room(ROOM) is None

    def test_an_empty_one_is_refused(self):
        assert muc.validate_room("")[0] == "bad_request"

    def test_a_nickname_is_refused_with_advice(self):
        """The likeliest mistake: pasting the occupant JID."""
        code, detail = muc.validate_room(ROOM + "/bob")
        assert code == "bad_request"
        assert "nickname" in detail

    def test_a_bare_word_is_refused_with_an_example(self):
        code, detail = muc.validate_room("general")
        assert code == "bad_request"
        assert "@" in detail

    def test_a_space_is_refused(self):
        assert muc.validate_room("gen eral@rooms.x.i2p") is not None

    def test_it_never_quotes_the_address_back(self):
        """A refusal is rendered on screen and pasted into reports."""
        _, detail = muc.validate_room("secretroom name@rooms.x.i2p")
        assert "secretroom" not in detail


class TestValidatingANickname:

    def test_a_good_one_passes(self):
        assert muc.validate_nick("bob") is None

    def test_a_name_with_a_space_passes(self):
        """A resourcepart may contain spaces and people use them."""
        assert muc.validate_nick("Bob Smith") is None

    def test_an_empty_one_is_refused(self):
        assert muc.validate_nick("  ")[0] == "bad_request"

    def test_a_slash_is_refused(self):
        """It would make the occupant JID unaddressable."""
        assert muc.validate_nick("bo/b") is not None

    def test_an_over_long_one_is_refused_here_not_by_the_service(self):
        code, detail = muc.validate_nick("b" * (muc.MAX_NICK + 1))
        assert code == "bad_request"
        assert str(muc.MAX_NICK) in detail

    def test_the_limit_itself_is_accepted(self):
        assert muc.validate_nick("b" * muc.MAX_NICK) is None


# ── what the service said ────────────────────────────────────────────────────

class TestJoinFailuresArriveByPresence:

    def test_a_taken_nickname_is_a_conflict(self):
        code, detail = muc.classify(PresenceError("conflict"))
        assert code == "conflict"
        assert "nickname" in detail

    def test_a_ban_is_forbidden_and_says_so_plainly(self):
        code, detail = muc.classify(PresenceError("forbidden"))
        assert code == "forbidden"
        assert "banned" in detail

    def test_a_members_only_room_says_members_only(self):
        code, detail = muc.classify(
            PresenceError("registration-required"))
        assert code == "registration_required"
        assert "members" in detail

    def test_a_password_protected_room_says_password(self):
        code, detail = muc.classify(PresenceError("not-authorized"))
        assert code == "not_authorized"
        assert "password" in detail

    def test_a_full_room_says_full(self):
        code, detail = muc.classify(PresenceError("service-unavailable"))
        assert "full" in detail

    def test_a_missing_room_is_item_not_found(self):
        assert muc.classify(PresenceError("item-not-found"))[0] == \
            "item_not_found"


class TestOtherFailures:

    def test_a_service_that_forbids_creation_says_so(self):
        code, detail = muc.classify(IqError("not-allowed"))
        assert code == "not_allowed"
        assert "create" in detail

    def test_a_server_with_no_muc_is_unsupported(self):
        assert muc.classify(IqError("feature-not-implemented"))[0] == \
            "unsupported"

    def test_a_timeout_mentions_i2p(self):
        import asyncio
        code, detail = muc.classify(asyncio.TimeoutError())
        assert code == "timeout" and "I2P" in detail

    def test_a_refusal_is_not_read_as_a_timeout(self):
        """slixmpp's contract for `join_muc_wait` is explicit: a
        `PresenceError` means the service ANSWERED with an error, and an
        `asyncio.TimeoutError` means it did not answer at all. Treating a
        refusal as a timeout tells somebody who has been banned to try
        again."""
        assert muc.classify(PresenceError("forbidden"))[0] == "forbidden"
        assert muc.classify(PresenceError("weird-new-condition"))[0] == \
            "unknown"

    def test_a_network_failure_is_a_network_failure(self):
        assert muc.classify(OSError("no route"))[0] == "network"

    def test_a_cancelled_operation_says_so(self):
        import asyncio
        assert muc.classify(asyncio.CancelledError())[0] == "cancelled"

    def test_an_unmapped_condition_is_unknown(self):
        assert muc.classify(IqError("policy-violation"))[0] == "unknown"

    def test_a_precoded_failure_is_taken_at_its_word(self):
        class Refused(Exception):
            code = "not_allowed"

        assert muc.classify(Refused())[0] == "not_allowed"

    def test_a_foreign_code_is_not_mistaken_for_one_of_ours(self):
        class Other(Exception):
            code = "sam_unavailable"

        assert muc.classify(Other())[0] == "unknown"


class TestClassifyNeverEchoesTheStanza:
    """A MUC error carries the room, the service and the nickname -- three
    things the diagnostic rules put alongside a JID."""

    def test_the_room_does_not_reach_the_sentence(self):
        for exc in (IqError("conflict"), PresenceError("forbidden")):
            _, detail = muc.classify(exc)
            assert "general" not in detail
            assert "xmpp-elite" not in detail

    def test_the_nickname_does_not_either(self):
        _, detail = muc.classify(PresenceError("conflict"))
        assert "bob" not in detail

    def test_every_sentence_comes_from_the_table(self):
        for exc in (IqError("conflict"), PresenceError("forbidden"),
                    OSError("x"), RuntimeError("x")):
            code, detail = muc.classify(exc)
            assert detail == muc.CODES[code]

    def test_a_stanza_that_raises_on_lookup_does_not_take_us_down(self):
        class Hostile:
            @property
            def condition(self):
                raise ValueError("no")

            @property
            def presence(self):
                raise ValueError("no")

        assert muc.classify(Hostile())[0] == "unknown"


class TestTheCodesAreAContract:

    def test_every_condition_maps_to_a_declared_code(self):
        for code in muc._CONDITIONS.values():
            assert code in muc.CODES, code

    def test_every_sentence_is_a_sentence(self):
        for code, text in muc.CODES.items():
            assert text and text[0].isupper() and text.endswith(".")

    def test_no_sentence_names_a_room_or_a_person(self):
        for text in muc.CODES.values():
            assert "@" not in text
            assert ".i2p" not in text

    def test_describe_falls_back_rather_than_raising(self):
        assert muc.describe("no-such-code") == muc.CODES["unknown"]


class TestTheModuleStaysTestable:

    def test_it_imports_nothing_it_cannot_run_without(self):
        import inspect
        for line in inspect.getsource(muc).splitlines():
            stripped = line.strip()
            if not stripped.startswith(("import ", "from ")):
                continue
            assert "slixmpp" not in stripped, stripped
            assert "android" not in stripped, stripped

    def test_it_does_no_io(self):
        import inspect
        source = inspect.getsource(muc)
        for forbidden in ("socket", "open(", "urllib"):
            assert forbidden not in source, forbidden

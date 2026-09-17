# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""OMEMO 2: who a message has to be encrypted to.

THE DEFECT THESE TESTS EXIST TO PREVENT
---------------------------------------
Encrypting to whoever happens to be online.

Presence is not membership. A member of a room who is offline now will read
the message later; a device that has not sent a stanza recently is still a
device. A recipient set built from the occupant list a UI is showing silently
excludes people, and the sender sees no error at all -- their message simply
never arrives for someone.

The second form of the same mistake is leaving out the sender's OWN other
devices. The message is delivered, the recipient reads it, and it is
unreadable on the sender's laptop. That looks like data loss rather than a
protocol error, which is why it survives so long in clients that have it.

Both are covered below, and neither involves any cryptography: this is the
XMPP half of XEP-0384 and it is the half that decides whether a message
reaches everybody it should.
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import otrv4plus_omemo as omemo
from otrv4plus_omemo import Device, DeviceList

ALICE = "alice@xmpp-elite.i2p"
BOB = "bob@xmpp-elite.i2p"
CAROL = "carol@xmpp-elite.i2p"
ROOM = "general@rooms.xmpp-elite.i2p"


def listing(jid, *ids, at=100.0):
    return DeviceList(jid, [Device(jid, i) for i in ids], at=at)


# ── the namespace is the right one ───────────────────────────────────────────

class TestItIsOmemo2AndNotTheOldOne:

    def test_the_namespace_is_urn_xmpp_omemo_2(self):
        assert omemo.NAMESPACE == "urn:xmpp:omemo:2"

    def test_it_is_not_the_conversations_legacy_namespace(self):
        """`eu.siacs.conversations.axolotl` is OMEMO 0.3 -- a different key
        exchange and a different wire format, not an older spelling."""
        assert "siacs" not in omemo.NAMESPACE
        assert "axolotl" not in omemo.NAMESPACE

    def test_the_pep_nodes_hang_off_the_namespace(self):
        assert omemo.DEVICES_NODE == "urn:xmpp:omemo:2:devices"
        assert omemo.BUNDLES_NODE == "urn:xmpp:omemo:2:bundles"

    def test_the_payload_wrapper_is_named(self):
        """OMEMO 2 wraps the stanza with XEP-0420 SCE. Naming it means the
        wire format is checkable rather than assumed."""
        assert omemo.SCE_NAMESPACE == "urn:xmpp:sce:1"


# ── 1:1 ──────────────────────────────────────────────────────────────────────

class TestDirectRecipients:

    def test_every_device_of_the_peer_is_included(self):
        devices = omemo.recipients_for_direct(
            listing(BOB, 11, 12), listing(ALICE, 21), own_device_id=21)
        assert {d.device_id for d in devices} == {11, 12}

    def test_the_senders_own_other_devices_are_included(self):
        """Left out, the message is readable by the recipient and unreadable
        on the sender's own laptop -- which looks like data loss."""
        devices = omemo.recipients_for_direct(
            listing(BOB, 11), listing(ALICE, 21, 22), own_device_id=21)
        assert (ALICE, 22) in {(d.jid, d.device_id) for d in devices}

    def test_the_sending_device_itself_is_excluded(self):
        """It has the plaintext, and a session with oneself is not a thing."""
        devices = omemo.recipients_for_direct(
            listing(BOB, 11), listing(ALICE, 21, 22), own_device_id=21)
        assert (ALICE, 21) not in {(d.jid, d.device_id) for d in devices}

    def test_a_peer_with_one_device_gives_one_recipient(self):
        devices = omemo.recipients_for_direct(
            listing(BOB, 11), listing(ALICE, 21), own_device_id=21)
        assert len(devices) == 1

    def test_a_peer_with_no_devices_gives_nothing_to_encrypt_to(self):
        """The caller must treat this as a failure rather than sending
        something nobody can read."""
        devices = omemo.recipients_for_direct(
            listing(BOB), listing(ALICE, 21), own_device_id=21)
        assert devices == ()

    def test_duplicates_are_collapsed(self):
        peer = DeviceList(BOB, [Device(BOB, 11), Device(BOB, 11)], at=1.0)
        devices = omemo.recipients_for_direct(
            peer, listing(ALICE, 21), own_device_id=21)
        assert len(devices) == 1


# ── rooms: the important one ─────────────────────────────────────────────────

class TestRoomRecipientsComeFromMembershipNotPresence:

    def test_every_member_is_included(self):
        devices, missing = omemo.recipients_for_room(
            members=[BOB, CAROL],
            device_lists={BOB: listing(BOB, 11), CAROL: listing(CAROL, 31),
                          ALICE: listing(ALICE, 21)},
            own_jid=ALICE, own_device_id=21)
        assert missing == ()
        assert {(d.jid, d.device_id) for d in devices} >= {
            (BOB, 11), (CAROL, 31)}

    def test_an_offline_member_is_still_a_recipient(self):
        """The whole point. They will read the message later, and a set built
        from who is online now excludes them with no error anywhere.

        Note there is no presence argument to this function at all -- the
        rule is enforced by the signature, not by remembering to obey it.
        """
        import inspect
        params = inspect.signature(omemo.recipients_for_room).parameters
        assert "presence" not in params
        assert "online" not in params
        assert "occupants" not in params

    def test_the_senders_own_other_devices_are_included(self):
        devices, _ = omemo.recipients_for_room(
            members=[BOB],
            device_lists={BOB: listing(BOB, 11),
                          ALICE: listing(ALICE, 21, 22)},
            own_jid=ALICE, own_device_id=21)
        assert (ALICE, 22) in {(d.jid, d.device_id) for d in devices}

    def test_the_sending_device_is_excluded(self):
        devices, _ = omemo.recipients_for_room(
            members=[BOB],
            device_lists={BOB: listing(BOB, 11),
                          ALICE: listing(ALICE, 21, 22)},
            own_jid=ALICE, own_device_id=21)
        assert (ALICE, 21) not in {(d.jid, d.device_id) for d in devices}

    def test_a_member_with_no_device_list_is_reported_missing(self):
        """NOT silently dropped. A message encrypted to
        everyone-we-happen-to-know-about excludes somebody without saying so."""
        devices, missing = omemo.recipients_for_room(
            members=[BOB, CAROL],
            device_lists={BOB: listing(BOB, 11), ALICE: listing(ALICE, 21)},
            own_jid=ALICE, own_device_id=21)
        assert missing == (CAROL,)

    def test_a_member_with_an_empty_device_list_is_missing_too(self):
        devices, missing = omemo.recipients_for_room(
            members=[BOB],
            device_lists={BOB: listing(BOB), ALICE: listing(ALICE, 21)},
            own_jid=ALICE, own_device_id=21)
        assert missing == (BOB,)

    def test_a_member_appearing_twice_is_one_recipient_set(self):
        devices, _ = omemo.recipients_for_room(
            members=[BOB, BOB],
            device_lists={BOB: listing(BOB, 11), ALICE: listing(ALICE, 21)},
            own_jid=ALICE, own_device_id=21)
        assert len([d for d in devices if d.jid == BOB]) == 1

    def test_case_and_resources_do_not_split_a_member(self):
        devices, missing = omemo.recipients_for_room(
            members=["BOB@XMPP-ELITE.I2P/phone"],
            device_lists={BOB: listing(BOB, 11), ALICE: listing(ALICE, 21)},
            own_jid=ALICE, own_device_id=21)
        assert missing == ()

    def test_an_empty_room_still_includes_our_own_devices(self):
        devices, _ = omemo.recipients_for_room(
            members=[], device_lists={ALICE: listing(ALICE, 21, 22)},
            own_jid=ALICE, own_device_id=21)
        assert {d.device_id for d in devices} == {22}


class TestARoomThatCannotDoOmemoSaysSo:

    def test_a_semi_anonymous_room_cannot(self):
        """OMEMO needs members' real JIDs to encrypt to their devices, and a
        semi-anonymous MUC deliberately hides them. Offering it there produces
        a message that cannot be sent, minutes after the user chose it."""
        usable, reason = omemo.room_can_use_omemo("semi-anonymous", True)
        assert usable is False
        assert "addresses" in reason

    def test_a_non_anonymous_room_can(self):
        assert omemo.room_can_use_omemo("non-anonymous", True)[0] is True

    def test_unknown_membership_is_refused_rather_than_guessed(self):
        usable, reason = omemo.room_can_use_omemo("non-anonymous", False)
        assert usable is False
        assert "everyone" in reason

    def test_the_reason_names_no_room_and_no_person(self):
        for anonymity in ("semi-anonymous", "non-anonymous"):
            for known in (True, False):
                reason = omemo.room_can_use_omemo(anonymity, known)[1]
                assert "@" not in reason


# ── bundles ──────────────────────────────────────────────────────────────────

class TestOnlyFetchBundlesWeNeed:

    def test_a_device_with_no_session_needs_one(self):
        needed = omemo.bundles_needed([Device(BOB, 11)], established=[])
        assert [d.device_id for d in needed] == [11]

    def test_a_device_we_have_a_session_with_does_not(self):
        """Refetching per message would be an I2P round trip per device per
        message, which is the difference between a chat and a spinner."""
        needed = omemo.bundles_needed([Device(BOB, 11)],
                                      established=[(BOB, 11)])
        assert needed == ()

    def test_only_the_new_device_is_fetched(self):
        needed = omemo.bundles_needed(
            [Device(BOB, 11), Device(BOB, 12)], established=[(BOB, 11)])
        assert [d.device_id for d in needed] == [12]

    def test_a_session_with_another_account_does_not_count(self):
        """Same device id, different account. Treating them as the same is a
        cross-account session confusion."""
        needed = omemo.bundles_needed([Device(BOB, 11)],
                                      established=[(CAROL, 11)])
        assert len(needed) == 1


# ── stale device lists ───────────────────────────────────────────────────────

class TestAStaleDeviceListIsRefetched:

    def test_a_fresh_list_is_not_stale(self):
        assert listing(BOB, 11, at=100.0).is_stale(now=110.0, max_age=60) \
            is False

    def test_an_old_list_is_stale(self):
        """Somebody adds a phone and every sender who has not refetched
        encrypts to everything except the phone."""
        assert listing(BOB, 11, at=100.0).is_stale(now=500.0, max_age=60) \
            is True

    def test_a_list_that_was_never_read_is_stale(self):
        assert DeviceList(BOB, [], at=0.0).is_stale(now=1.0, max_age=60) is True


# ── device ids ───────────────────────────────────────────────────────────────

class TestDeviceIds:

    def test_an_ordinary_id_is_accepted(self):
        assert omemo.validate_device_id(12345) is None

    def test_zero_is_refused(self):
        assert omemo.validate_device_id(0)[0] == "bad_device_id"

    def test_a_negative_id_is_refused(self):
        assert omemo.validate_device_id(-1) is not None

    def test_an_id_beyond_31_bits_is_refused(self):
        assert omemo.validate_device_id(omemo.MAX_DEVICE_ID + 1) is not None

    def test_the_boundaries_are_accepted(self):
        assert omemo.validate_device_id(omemo.MIN_DEVICE_ID) is None
        assert omemo.validate_device_id(omemo.MAX_DEVICE_ID) is None

    def test_rubbish_is_refused_rather_than_raising(self):
        assert omemo.validate_device_id("banana") is not None
        assert omemo.validate_device_id(None) is not None


# ── failures ─────────────────────────────────────────────────────────────────

class Stanza(dict):
    def __init__(self, condition):
        super().__init__({"error": {"condition": condition}})


class IqError(Exception):
    def __init__(self, condition):
        super().__init__("iq error <%s/> for %s device 11"
                         % (condition, ALICE))
        self.condition = condition
        self.iq = Stanza(condition)


class TestClassification:

    def test_a_missing_pep_node_means_no_devices(self):
        code, detail = omemo.classify(IqError("item-not-found"))
        assert code == "no_devices"
        assert "published no" in detail

    def test_a_server_without_omemo_says_unsupported(self):
        assert omemo.classify(IqError("feature-not-implemented"))[0] == \
            "unsupported"

    def test_a_timeout_mentions_i2p(self):
        import asyncio
        code, detail = omemo.classify(asyncio.TimeoutError())
        assert code == "timeout" and "I2P" in detail

    def test_a_network_failure_is_a_network_failure(self):
        assert omemo.classify(OSError("no route"))[0] == "network"

    def test_a_precoded_failure_is_taken_at_its_word(self):
        class Refused(Exception):
            code = "no_backend"

        assert omemo.classify(Refused())[0] == "no_backend"

    def test_a_foreign_code_is_not_mistaken_for_ours(self):
        class Other(Exception):
            code = "sam_unavailable"

        assert omemo.classify(Other())[0] == "unknown"

    def test_the_stanza_text_never_reaches_the_sentence(self):
        """An OMEMO error can carry a JID, a device id and key material."""
        _, detail = omemo.classify(IqError("item-not-found"))
        assert "alice" not in detail
        assert "device 11" not in detail

    def test_every_sentence_comes_from_the_table(self):
        for exc in (IqError("item-not-found"), OSError("x"),
                    RuntimeError("x")):
            code, detail = omemo.classify(exc)
            assert detail == omemo.CODES[code]

    def test_a_stanza_that_raises_on_lookup_does_not_take_us_down(self):
        class Hostile:
            @property
            def condition(self):
                raise ValueError("no")

            @property
            def iq(self):
                raise ValueError("no")

        assert omemo.classify(Hostile())[0] == "unknown"


class TestTheCodesAreAContract:

    def test_every_condition_maps_to_a_declared_code(self):
        for code in omemo._CONDITIONS.values():
            assert code in omemo.CODES, code

    def test_every_sentence_is_a_sentence(self):
        for code, text in omemo.CODES.items():
            assert text and text[0].isupper() and text.endswith(".")

    def test_no_sentence_names_a_person_or_a_room(self):
        for text in omemo.CODES.values():
            assert "@" not in text and ".i2p" not in text

    def test_undecryptable_is_distinct_from_not_encrypted(self):
        """"We could not read this" and "this arrived in the clear" are
        different facts and must never render the same."""
        assert omemo.CODES["undecryptable"] != omemo.CODES["not_encrypted"]

    def test_describe_falls_back_rather_than_raising(self):
        assert omemo.describe("no-such-code") == omemo.CODES["unknown"]


# ── it holds no cryptography and no identities ───────────────────────────────

class TestTheModuleStaysWhatItIs:

    def test_it_implements_no_cryptography(self):
        """The ratchet and the key agreement belong to `python-omemo` and
        `twomemo`. A second Double Ratchet written for this project would be
        the worst kind of wheel to reinvent."""
        import inspect
        source = inspect.getsource(omemo)
        for forbidden in ("hashlib", "hmac", "Cipher", "AES", "curve25519",
                          "ratchet_step", "kdf"):
            assert forbidden not in source, forbidden

    def test_it_imports_nothing_it_cannot_run_without(self):
        import inspect
        for line in inspect.getsource(omemo).splitlines():
            stripped = line.strip()
            if not stripped.startswith(("import ", "from ")):
                continue
            assert "slixmpp" not in stripped, stripped
            assert "android" not in stripped, stripped

    def test_a_device_repr_names_no_account(self):
        assert "alice" not in repr(Device(ALICE, 11))

    def test_a_device_list_repr_names_no_account(self):
        assert "alice" not in repr(listing(ALICE, 11))

#!/usr/bin/env python3
"""C1 -- protocol versioning across the MKmac wire break.

The MKmac fix changed two wire formats incompatibly:

  data message  MAC value differs (MKmac = KDF(0x14, MKenc, 64) replaced
                sha3_512(session_id || ratchet_id || msg_num)), and
                REVEALED_MAC_KEY_LEN widened 32 -> 64
  voice frame   8 bytes of the fixed padding slot now carry the sender's
                monotonic timestamp, changing the frame PLAINTEXT layout

Neither carried a version increment, so two builds would negotiate happily and
then fail deep in the cryptography. These tests pin the versioning that makes a
mismatch diagnosable.

The ClientProfile / DAKE version is deliberately NOT incremented: that format
did not change. A test below asserts it stays at 4, so a future edit cannot bump
it casually and invalidate every profile.
"""

import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otr = pytest.importorskip("otrv4_")

DATA_MSG_VERSION = 0x0005
PROFILE_VERSION = 4
VOICE_FRAME_VERSION = 4


def _framed(version, body_len=96):
    """A data message whose header carries `version`. Body is filler.

    The version is the first field decode() reads, so it is rejected before the
    body matters -- which is the property under test.
    """
    return struct.pack("!HB", version, otr.OTRv4DataMessage.TYPE) + b"\x00" * body_len


# ── (a) matching versions ────────────────────────────────────────────────────

class TestMatchingVersions:

    def test_current_revision_passes_the_version_gate(self):
        """A current-revision header must get past the version check.

        It then fails on the filler body -- that is expected and is what shows
        the version gate was cleared rather than short-circuiting everything.
        """
        with pytest.raises(ValueError) as exc:
            otr.OTRv4DataMessage.decode(_framed(DATA_MSG_VERSION))
        assert not isinstance(exc.value, otr.ProtocolVersionError), \
            "a current-revision message must not be rejected as a version mismatch"

    def test_a_real_round_trip_still_works(self):
        """End-to-end: encode then decode at the current revision."""
        msg = otr.OTRv4DataMessage()
        msg.sender_tag, msg.receiver_tag = 0x0101, 0x0202
        msg.flags, msg.prev_chain_len = 0, 0
        msg.ratchet_id, msg.message_id = 1, 0
        msg.ecdh_pub = bytes(56)
        msg.nonce = bytes(12)
        msg.ciphertext = b"round trip"
        msg.revealed_mac_keys = []
        msg.mac = bytes(64)

        decoded = otr.OTRv4DataMessage.decode(msg.encode())
        assert decoded.ciphertext == b"round trip"
        assert decoded.ratchet_id == 1

    def test_encoder_stamps_the_current_revision(self):
        msg = otr.OTRv4DataMessage()
        msg.sender_tag, msg.receiver_tag = 1, 2
        msg.flags, msg.prev_chain_len = 0, 0
        msg.ratchet_id, msg.message_id = 0, 0
        msg.ecdh_pub, msg.nonce = bytes(56), bytes(12)
        msg.ciphertext, msg.revealed_mac_keys, msg.mac = b"x", [], bytes(64)
        assert struct.unpack("!H", msg.encode()[:2])[0] == DATA_MSG_VERSION


# ── (b) mismatched versions, and (c) old/new peer interaction ────────────────

class TestMismatchedVersions:

    def test_old_peer_message_is_a_version_error_not_a_forgery(self):
        """THE C1 requirement.

        A pre-fix peer's message must be reported as a version mismatch. Before
        this change it passed the version check and failed MAC verification,
        surfacing as "message may be forged or replayed" -- an alarming and
        wrong diagnosis for a build mismatch.
        """
        with pytest.raises(otr.ProtocolVersionError) as exc:
            otr.OTRv4DataMessage.decode(_framed(0x0004))

        text = str(exc.value).lower()
        assert "version" in text or "revision" in text
        assert "forg" not in text or "not a forgery" in text, \
            "the error must not read as a forgery report"
        # Both revisions named, so the operator can see what to upgrade.
        assert "0x0004" in str(exc.value) and "0x0005" in str(exc.value)

    def test_version_error_is_catchable_as_valueerror(self):
        """Existing `except ValueError` handlers must keep working."""
        assert issubclass(otr.ProtocolVersionError, ValueError)
        with pytest.raises(ValueError):
            otr.OTRv4DataMessage.decode(_framed(0x0004))

    def test_version_error_is_not_flattened_by_the_decode_wrapper(self):
        """decode() wraps most failures in a generic ValueError.

        Regression guard: it did exactly that to this error when the typed
        exception was first added, which restored the ambiguity C1 exists to
        remove.
        """
        with pytest.raises(otr.ProtocolVersionError):
            otr.OTRv4DataMessage.decode(_framed(0x0004))

    def test_rejection_happens_before_any_key_material_is_touched(self):
        """A wrong-revision message must never reach MAC evaluation.

        The body here is pure filler: if the version gate did not fire first,
        decoding would fail somewhere in the body instead, with a different
        error type.
        """
        with pytest.raises(otr.ProtocolVersionError):
            otr.OTRv4DataMessage.decode(_framed(0x0004, body_len=4))


# ── (d) downgrade attempts ───────────────────────────────────────────────────

class TestNoDowngrade:

    @pytest.mark.parametrize("version", [0x0000, 0x0001, 0x0002, 0x0003, 0x0004])
    def test_every_older_revision_is_refused(self, version):
        """No older revision is accepted, so the old MAC construction is never
        evaluated and an attacker cannot force the weaker derivation."""
        with pytest.raises(otr.ProtocolVersionError):
            otr.OTRv4DataMessage.decode(_framed(version))

    @pytest.mark.parametrize("version", [0x0006, 0x0007, 0x00FF, 0x1000])
    def test_newer_revisions_are_also_refused(self, version):
        """Strict equality in both directions.

        Accepting an unknown-newer revision would mean guessing at a framing
        this build does not know.
        """
        with pytest.raises(otr.ProtocolVersionError):
            otr.OTRv4DataMessage.decode(_framed(version))

    def test_the_check_is_equality_not_a_minimum(self):
        import inspect
        src = inspect.getsource(otr.OTRv4DataMessage.decode)
        assert "!=" in src.split("read_uint16")[1][:200], \
            "the version gate must be strict equality, not a >= floor"


# ── (e) malformed version fields ─────────────────────────────────────────────

class TestMalformedVersionField:

    @pytest.mark.parametrize("raw", [b"", b"\x00", b"\x00\x05"])
    def test_truncated_headers_are_rejected(self, raw):
        """Too short to hold a version, or a version with no type byte."""
        with pytest.raises(ValueError):
            otr.OTRv4DataMessage.decode(raw)

    def test_max_version_value_is_rejected_cleanly(self):
        with pytest.raises(otr.ProtocolVersionError):
            otr.OTRv4DataMessage.decode(_framed(0xFFFF))

    def test_garbage_is_rejected_without_crashing(self):
        """Fuzz-ish: random leading bytes must raise, never escape."""
        for _ in range(200):
            raw = os.urandom(64)
            with pytest.raises((ValueError, struct.error)):
                otr.OTRv4DataMessage.decode(raw)


# ── The version that must NOT change ─────────────────────────────────────────

class TestProfileVersionUnchanged:
    """The ClientProfile / DAKE format did not change, so its version must not.

    Bumping it would falsely signal a handshake change and invalidate every
    existing profile. Recorded as a test so the reasoning survives.
    """

    def test_profile_version_is_still_4(self):
        assert otr.OTRConstants.PROTOCOL_VERSION == PROFILE_VERSION

    def test_profile_and_data_message_versions_are_independent(self):
        assert otr.OTRConstants.PROTOCOL_VERSION != otr.OTRv4DataMessage.PROTOCOL_VERSION, \
            "these version two different things and must not be conflated"

    def test_a_profile_still_round_trips(self):
        profile = otr.ClientProfile()
        assert otr.ClientProfile.decode(profile.encode()) is not None


# ── Voice frame revision ─────────────────────────────────────────────────────

class TestVoiceFrameVersion:
    """The frame plaintext layout changed; the header version had to follow.

    The timestamp sits INSIDE the AEAD, so a revision mismatch would otherwise
    authenticate successfully under GCM and only surface as unpad_opus
    misreading Opus data -- garbled audio, with nothing pointing at a version
    mismatch.
    """

    @pytest.fixture
    def voice(self):
        return pytest.importorskip("otrv4plus_voice")

    def test_frame_revision_was_incremented(self, voice):
        assert voice.VOICE_PROTOCOL_VERSION == VOICE_FRAME_VERSION

    def test_current_revision_header_parses(self, voice):
        # The length field is fixed-size framing (VOICE_MIN_FRAME ==
        # VOICE_MAX_FRAME == VOICE_SEALED_LEN), so a header only parses with
        # the one plausible value; anything else is rejected before the AEAD.
        hdr = voice.pack_media_header(epoch=1, counter=1,
                                      length=voice.VOICE_SEALED_LEN)
        assert voice.parse_media_header(hdr) is not None

    def test_old_revision_header_is_refused(self, voice):
        """A revision-3 frame must be rejected at the header, before the AEAD."""
        hdr = bytearray(voice.pack_media_header(epoch=1, counter=1, length=voice.VOICE_SEALED_LEN))
        hdr[1] = 3
        with pytest.raises(voice.FrameError) as exc:
            voice.parse_media_header(bytes(hdr))
        assert "version" in str(exc.value).lower()

    @pytest.mark.parametrize("bad", [0, 1, 2, 5, 255])
    def test_no_other_revision_is_accepted(self, voice, bad):
        hdr = bytearray(voice.pack_media_header(epoch=1, counter=1, length=voice.VOICE_SEALED_LEN))
        hdr[1] = bad
        with pytest.raises(voice.FrameError):
            voice.parse_media_header(bytes(hdr))

    def test_plaintext_layout_reserves_the_timestamp(self, voice):
        """The layout change the revision bump exists for."""
        assert voice.VOICE_TS_LEN == 8
        assert voice.VOICE_PLAIN_LEN == 2 + voice.VOICE_TS_LEN + voice.VOICE_OPUS_SLOT

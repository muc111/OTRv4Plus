"""SAM v3 hands back a private key, not a destination.

SESSION CREATE is answered with

    SESSION STATUS RESULT=OK DESTINATION=$privkey

and per the SAM v3 specification $privkey is the base64 of

    Destination || PrivateKey || SigningPrivateKey

For SIGNATURE_TYPE=7 that is 679 bytes -- 908 base64 characters, against the
524 of the destination alone. Treating it as a destination did two things:

  * the session's own private keys were published to the peer in every
    INVITE (observed as "sent INVITE (dest 908 B, ...)").
  * the repliable-datagram source filter compared SAM's reported source, a
    524-character destination, against the 908-character blob. They never
    matched, so a callee discarded every media datagram the caller sent:
    rx=0 for the whole call with drop climbing at the frame rate.
"""

import os

import pytest

import otrv4plus_voice as voice


def _keys_and_cert(cert_len=4, cert_type=5):
    """A KeysAndCert: 256 public + 128 signing public + type + length + body."""
    return (os.urandom(384)
            + bytes([cert_type])
            + cert_len.to_bytes(2, "big")
            + os.urandom(cert_len))


def _sam_privkey_blob(dest=None):
    """Destination || PrivateKey(256) || SigningPrivateKey(32), as SAM sends."""
    dest = dest if dest is not None else _keys_and_cert()
    return dest, dest + os.urandom(256) + os.urandom(32)


class TestBase64Alphabet:
    def test_it_round_trips(self):
        raw = os.urandom(300)
        assert voice.i2p_b64decode(voice.i2p_b64encode(raw)) == raw

    def test_it_uses_the_i2p_alphabet_not_the_standard_one(self):
        # I2P replaces + and / with - and ~. A decoder using the standard
        # alphabet silently produces different bytes for the same string.
        raw = bytes(range(256))
        text = voice.i2p_b64encode(raw)
        assert "+" not in text and "/" not in text

    def test_it_accepts_unpadded_input(self):
        raw = os.urandom(391)
        text = voice.i2p_b64encode(raw).rstrip("=")
        assert voice.i2p_b64decode(text) == raw


class TestPublicDestinationExtraction:
    def test_a_sam_private_key_blob_yields_only_the_destination(self):
        dest, blob = _sam_privkey_blob()
        got = voice.i2p_public_destination(voice.i2p_b64encode(blob))
        assert voice.i2p_b64decode(got) == dest

    def test_the_private_key_material_does_not_survive(self):
        dest, blob = _sam_privkey_blob()
        private = blob[len(dest):]
        got = voice.i2p_public_destination(voice.i2p_b64encode(blob))
        assert private not in voice.i2p_b64decode(got)
        assert len(voice.i2p_b64decode(got)) == len(dest)

    def test_the_lengths_match_the_observed_ones(self):
        # 908 is what the INVITE actually carried; 524 is what it should have.
        dest, blob = _sam_privkey_blob()
        assert len(voice.i2p_b64encode(blob)) == 908
        assert len(voice.i2p_public_destination(
            voice.i2p_b64encode(blob))) == 524

    def test_it_is_idempotent_on_a_bare_destination(self):
        # A peer may send either form; applying this to both must be safe.
        dest = _keys_and_cert()
        text = voice.i2p_b64encode(dest)
        assert voice.i2p_public_destination(text) == text

    def test_applying_it_twice_changes_nothing(self):
        _dest, blob = _sam_privkey_blob()
        once = voice.i2p_public_destination(voice.i2p_b64encode(blob))
        assert voice.i2p_public_destination(once) == once

    @pytest.mark.parametrize("cert_len", [0, 4, 8, 64])
    def test_the_certificate_length_is_honoured(self, cert_len):
        dest = _keys_and_cert(cert_len=cert_len)
        _d, blob = _sam_privkey_blob(dest)
        got = voice.i2p_public_destination(voice.i2p_b64encode(blob))
        assert voice.i2p_b64decode(got) == dest
        assert len(voice.i2p_b64decode(got)) == 387 + cert_len


class TestMalformedInputIsRefused:
    def test_something_far_too_short(self):
        with pytest.raises(ValueError):
            voice.i2p_public_destination(voice.i2p_b64encode(b"short"))

    def test_a_certificate_longer_than_the_data(self):
        raw = os.urandom(384) + bytes([5]) + (9000).to_bytes(2, "big")
        with pytest.raises(ValueError):
            voice.i2p_public_destination(voice.i2p_b64encode(raw))

    def test_a_truncated_keys_and_cert(self):
        with pytest.raises(ValueError):
            voice.i2p_public_destination(voice.i2p_b64encode(os.urandom(386)))

    def test_it_raises_rather_than_returning_something_wrong(self):
        # This value comes off the wire, so a caller needs to be able to
        # reject it rather than act on a silently truncated destination.
        with pytest.raises((ValueError, Exception)):
            voice.i2p_public_destination("!!!not base64!!!")


class TestTheFilterCanNowMatch:
    def test_both_sides_derive_the_same_string(self):
        """The exact failure: caller published a blob, callee compared a dest.

        The caller's INVITE now carries what SAM reports as the datagram
        source, so the callee's filter compares like with like.
        """
        dest, blob = _sam_privkey_blob()

        # What SAM gives the caller at SESSION CREATE, and what it reports as
        # the source of that caller's repliable datagrams.
        sam_session_status = voice.i2p_b64encode(blob)
        sam_reported_source = voice.i2p_b64encode(dest)

        published = voice.i2p_public_destination(sam_session_status)
        assert published == sam_reported_source

        # And the old behaviour, for the record.
        assert sam_session_status != sam_reported_source


class TestForeignDatagramsAreCountedSeparately:
    def _session(self, peer_dest):
        s = object.__new__(voice.VoiceCallSession)
        s._running = True
        s._peer_dest = peer_dest
        s._foreign_warned = True          # suppress the print in tests
        s._sam_session_id = "sid"
        s._dgram_send_header = None
        s.stats = {"recv": 0, "dropped": 0, "foreign": 0}
        s._drain_buffer = lambda buf: None
        return s

    def test_a_mismatched_source_is_foreign_not_dropped(self):
        # Folded into "dropped" this was indistinguishable from a lossy path,
        # which is how a filter discarding 100% of a call went unexplained.
        s = self._session("A" * 516)
        s._on_datagram(("B" * 516).encode() + b"\n" + b"\xa7frame")
        assert s.stats["foreign"] == 1
        assert s.stats["dropped"] == 0

    def test_a_matching_source_is_not_counted_at_all(self):
        s = self._session("A" * 516)
        s._on_datagram(("A" * 516).encode() + b"\n" + b"\xa7frame")
        assert s.stats["foreign"] == 0
        assert s.stats["dropped"] == 0

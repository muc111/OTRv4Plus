#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Attacker-chosen epoch and counter values at the edges of their fields.

Both are 64-bit fields on the wire, chosen by whoever sent the packet. The
Rust core is built with `overflow-checks = true` and `panic = "abort"`, so an
arithmetic overflow on one of them would not wrap -- it would end the process.
That is fail-closed for the key material and a remote kill switch for the
call. Each value here must be refused as a frame error, with the cipher still
usable afterwards.
"""

import pytest

V = pytest.importorskip("otrv4plus_voice")

CALL_ID = b"\x11" * 16
ROOT = b"\x37" * V.ROOT_LEN
U64_MAX = (1 << 64) - 1


def _pair(epoch=0):
    return (V.VoiceFrameCrypto(ROOT, CALL_ID, epoch, True),
            V.VoiceFrameCrypto(ROOT, CALL_ID, epoch, False))


def _forge(epoch, counter, body=b"\x00" * V.VOICE_SEALED_LEN):
    header = V.pack_media_header(epoch, counter, len(body))
    return header, body


@pytest.mark.parametrize("counter", [
    U64_MAX, U64_MAX - 1, 1 << 63, (1 << 62), V.VoiceFrameCrypto.MAX_COUNTER - 1,
    V.VoiceFrameCrypto.RATCHET_INTERVAL * (1 << 40),
])
def test_an_extreme_counter_is_a_frame_error(counter):
    sender, receiver = _pair()
    with pytest.raises(V.FrameError):
        receiver.open(*_forge(0, counter))
    # And the cipher is not wedged by it.
    packet = sender.seal(bytes(V.pad_opus(b"after")))
    hdr = packet[:V.VOICE_HDR_LEN]
    assert V.unpad_opus(receiver.open(hdr, packet[V.VOICE_HDR_LEN:])) == b"after"


@pytest.mark.parametrize("epoch", [U64_MAX, 1 << 63, 1 << 32, 0xFFFFFFFF, 1])
def test_an_extreme_epoch_is_a_frame_error(epoch):
    _, receiver = _pair()
    with pytest.raises(V.FrameError) as err:
        receiver.open(*_forge(epoch, 0))
    assert err.value.reason == V.FrameError.NO_KEY


def test_the_nonce_epoch_fold_cannot_collide_within_one_key():
    # media_nonce keeps only 32 bits of the epoch. That is safe because a
    # cipher belongs to exactly one epoch -- keys are per (root, epoch,
    # direction) -- and a frame for any other epoch is refused before the
    # nonce is built. Epoch 0 and epoch 2**32 share nonce bytes; they must
    # never share a key.
    assert V.media_nonce(0, 5) == V.media_nonce(1 << 32, 5)
    a = V.VoiceFrameCrypto(ROOT, CALL_ID, 0, True).seal(bytes(V.pad_opus(b"x")))
    b = V.VoiceFrameCrypto(ROOT, CALL_ID, 1 << 32, True).seal(bytes(V.pad_opus(b"x")))
    assert a[V.VOICE_HDR_LEN:] != b[V.VOICE_HDR_LEN:]


def test_the_send_counter_stops_before_its_limit():
    sender, _ = _pair()
    sender._send_counter = V.VoiceFrameCrypto.MAX_COUNTER
    with pytest.raises(V.FrameError):
        sender.seal(bytes(V.pad_opus(b"x")))


def test_a_rekey_cannot_step_past_the_epoch_limit():
    with pytest.raises(ValueError):
        V.VoiceFrameCrypto(ROOT, CALL_ID, 1 << 64, True)

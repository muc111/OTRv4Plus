# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Avatars: a peer's image is decoded only by bounded pure Python.

Owner's requirement, 2026-10-03: "It must be regex clean and limited I can't
allow hackers to craft special images which will hack users phones or
machines." The design (android_bridge/avatar.py): PNG only, size and
dimension caps, the published SHA-1 checked, every chunk length and CRC
checked, zlib output capped to exactly what the header implies, and only raw
RGBA leaves Python -- no native image decoder ever sees a peer's bytes.
"""
import base64
import hashlib
import os
import random
import struct
import sys
import zlib

import pytest
from hypothesis import given, settings, strategies as st

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from android_bridge import avatar as A  # noqa: E402


def chunk(ctype: bytes, body: bytes) -> bytes:
    return (struct.pack(">I", len(body)) + ctype + body
            + struct.pack(">I", zlib.crc32(ctype + body) & 0xFFFFFFFF))


def png(w, h, colour=6, rows=None, depth=8, interlace=0, filters=None,
        extra=(), palette=None, trns=None, idat_split=1, raw=None):
    """A minimal PNG encoder for the tests (independent of the decoder)."""
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[colour]
    if rows is None:
        rows = [bytes((x * 7 + y * 13 + c) & 0xFF
                      for x in range(w) for c in range(channels))
                for y in range(h)]
    out = bytearray()
    prev = bytes(w * channels)
    for y, row in enumerate(rows):
        f = (filters or [0])[y % len(filters or [0])]
        bpp = channels
        enc = bytearray()
        for i, v in enumerate(row):
            left = row[i - bpp] if i >= bpp else 0
            up = prev[i]
            ul = prev[i - bpp] if i >= bpp else 0
            pred = (0, left, up, (left + up) >> 1, A._paeth(left, up, ul))[f]
            enc.append((v - pred) & 0xFF)
        out.append(f)
        out += enc
        prev = row
    data = zlib.compress(bytes(out)) if raw is None else raw
    ihdr = struct.pack(">IIBBBBB", w, h, depth, colour, 0, 0, interlace)
    blob = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
    if palette is not None:
        blob += chunk(b"PLTE", palette)
    if trns is not None:
        blob += chunk(b"tRNS", trns)
    for c in extra:
        blob += c
    step = max(1, -(-len(data) // idat_split))
    for i in range(0, len(data), step):
        blob += chunk(b"IDAT", data[i:i + step])
    return blob + chunk(b"IEND", b"")


class TestValidImagesDecode:

    @pytest.mark.parametrize("colour", [0, 2, 4, 6])
    @pytest.mark.parametrize("filters", [[0], [1], [2], [3], [4], [0, 1, 2, 3, 4]])
    def test_every_colour_type_and_filter(self, colour, filters):
        w, h = 9, 7
        channels = {0: 1, 2: 3, 4: 2, 6: 4}[colour]
        rows = [bytes(random.Random(y * 31 + colour).randrange(256)
                      for _ in range(w * channels)) for y in range(h)]
        got_w, got_h, rgba = A.decode_png(png(w, h, colour, rows, filters=filters))
        assert (got_w, got_h) == (w, h) and len(rgba) == w * h * 4
        for y in range(h):
            for x in range(w):
                px = rgba[4 * (y * w + x):4 * (y * w + x) + 4]
                s = rows[y][x * channels:(x + 1) * channels]
                if colour == 0:
                    want = (s[0], s[0], s[0], 255)
                elif colour == 2:
                    want = (s[0], s[1], s[2], 255)
                elif colour == 4:
                    want = (s[0], s[0], s[0], s[1])
                else:
                    want = tuple(s)
                assert tuple(px) == want, (colour, filters, x, y)

    def test_palette_with_transparency(self):
        pal = bytes([255, 0, 0, 0, 255, 0, 0, 0, 255])
        rows = [bytes([0, 1, 2]), bytes([2, 1, 0])]
        _w, _h, rgba = A.decode_png(png(3, 2, 3, rows, palette=pal, trns=bytes([10])))
        assert rgba[:4] == bytes([255, 0, 0, 10])
        assert rgba[4:8] == bytes([0, 255, 0, 255])

    def test_split_image_data_and_ancillary_chunks(self):
        text = chunk(b"tEXt", b"Comment\x00hello")
        _w, _h, rgba = A.decode_png(png(16, 16, 6, extra=[text], idat_split=4))
        assert len(rgba) == 16 * 16 * 4

    def test_the_largest_allowed(self):
        rows = [bytes(256 * 4)] * 256
        w, h, _ = A.decode_png(png(256, 256, 6, rows))
        assert (w, h) == (256, 256)


class TestHostileImagesAreRefused:

    def _refused(self, data, code=None):
        with pytest.raises(A.AvatarError) as exc:
            A.decode_png(data)
        if code:
            assert exc.value.code == code, exc.value.code

    def test_not_a_png(self):
        self._refused(b"\xff\xd8\xff\xe0" + b"JFIF" * 10, "not_png")    # JPEG
        self._refused(b"RIFF\x00\x00\x00\x00WEBPVP8 ", "not_png")
        self._refused(b"<svg onload=alert(1)>", "not_png")
        self._refused(b"", "not_png")

    def test_too_many_bytes(self):
        self._refused(b"\x89PNG\r\n\x1a\n" + b"\x00" * A.MAX_BYTES, "too_large")

    @pytest.mark.parametrize("w,h", [(257, 1), (1, 257), (0, 5), (5, 0),
                                     (0x7FFFFFFF, 0x7FFFFFFF)])
    def test_dimensions_out_of_bounds(self, w, h):
        ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)
        self._refused(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
                      + chunk(b"IDAT", zlib.compress(b"\x00")) + chunk(b"IEND", b""),
                      "too_big")

    def test_decompression_bomb_stops_at_the_expected_size(self):
        bomb = zlib.compress(b"\x00" * (50 * 1024 * 1024), 9)  # 50 MB of zeros
        assert len(bomb) < A.MAX_BYTES
        self._refused(png(4, 4, 6, raw=bomb), "bad_image_data")

    def test_too_little_image_data(self):
        self._refused(png(8, 8, 6, raw=zlib.compress(b"\x00" * 10)), "bad_image_data")

    def test_corrupt_zlib(self):
        self._refused(png(4, 4, 6, raw=b"\x78\x9c\xff\xff\xff\xff"), "bad_image_data")

    @pytest.mark.parametrize("depth,colour", [(16, 6), (1, 0), (4, 3), (8, 5)])
    def test_unsupported_formats(self, depth, colour):
        self._refused(png(4, 4, 6, depth=depth) if colour == 6 else
                      png(4, 4, 6).replace(b"IHDR" + struct.pack(">IIBB", 4, 4, 8, 6),
                                           b"IHDR" + struct.pack(">IIBB", 4, 4, depth, colour)))

    def test_interlaced(self):
        self._refused(png(4, 4, 6, interlace=1), "unsupported_format")

    def test_bad_crc(self):
        data = bytearray(png(4, 4, 6))
        data[-20] ^= 0xFF                                  # inside IDAT
        self._refused(bytes(data))

    def test_truncated(self):
        data = png(4, 4, 6)
        for cut in (9, 20, 33, len(data) - 5):
            self._refused(data[:cut])

    def test_lying_chunk_length(self):
        data = bytearray(png(4, 4, 6))
        data[33:37] = struct.pack(">I", 0x7FFFFFF0)        # IDAT length
        self._refused(bytes(data), "truncated")

    def test_unknown_critical_chunk(self):
        self._refused(png(4, 4, 6, extra=[chunk(b"EVIL", b"x")]), "unknown_critical_chunk")

    def test_data_after_the_end(self):
        self._refused(png(4, 4, 6) + b"MZ\x90\x00 trailing payload", "data_after_end")

    def test_bad_filter_byte(self):
        raw = bytes([7]) + bytes(16) + bytes([0]) + bytes(16)
        self._refused(png(4, 2, 6, raw=zlib.compress(raw)), "bad_filter")

    def test_palette_index_out_of_range(self):
        rows = [bytes([0, 5])]
        self._refused(png(2, 1, 3, rows, palette=bytes(6)), "bad_palette")

    def test_palette_image_without_palette(self):
        self._refused(png(2, 1, 3, [bytes([0, 0])]), "bad_palette")

    def test_image_data_not_consecutive(self):
        data = png(16, 16, 6, idat_split=2)
        first = data.index(b"IDAT") - 4
        length, = struct.unpack(">I", data[first:first + 4])
        cut = first + 12 + length
        bad = data[:cut] + chunk(b"tEXt", b"a\x00b") + data[cut:]
        self._refused(bad, "bad_chunk")

    def test_a_second_header(self):
        ihdr = struct.pack(">IIBBBBB", 4, 4, 8, 6, 0, 0, 0)
        self._refused(png(4, 4, 6, extra=[chunk(b"IHDR", ihdr)]), "bad_chunk")


@settings(max_examples=400, deadline=None)
@given(st.binary(max_size=2048), st.integers(min_value=0, max_value=10**6))
def test_any_mutation_is_refused_cleanly_or_decodes_within_bounds(noise, seed):
    """Fuzz: flipping, inserting and truncating bytes of a valid PNG never
    raises anything but AvatarError, and never yields more than the caps."""
    rnd = random.Random(seed)
    data = bytearray(png(rnd.randrange(1, 20), rnd.randrange(1, 20),
                         rnd.choice([0, 2, 4, 6]),
                         filters=[rnd.randrange(5)]))
    for _ in range(rnd.randrange(1, 6)):
        op = rnd.randrange(3)
        pos = rnd.randrange(len(data))
        if op == 0:
            data[pos] ^= 1 << rnd.randrange(8)
        elif op == 1 and noise:
            data[pos:pos] = noise[:rnd.randrange(1, len(noise) + 1)]
        else:
            del data[pos:]
            if not data:
                break
    try:
        w, h, rgba = A.decode_png(bytes(data))
    except A.AvatarError:
        return
    assert 1 <= w <= A.MAX_DIMENSION and 1 <= h <= A.MAX_DIMENSION
    assert len(rgba) == w * h * 4


class TestTheBook:

    def _published(self, data=None):
        data = data or png(8, 8, 6)
        return data, hashlib.sha1(data).hexdigest(), base64.b64encode(data).decode()

    def test_announced_png_is_fetched_checked_and_kept(self):
        book = A.AvatarBook()
        data, aid, b64 = self._published()
        info = {"id": aid, "type": "image/png", "bytes": len(data),
                "width": 8, "height": 8}
        assert book.note_metadata("Bob@x.i2p/phone", [info]) == aid
        assert book.note_data("bob@x.i2p", aid, b64)
        got = book.get("bob@x.i2p")
        assert (got.width, got.height, len(got.rgba)) == (8, 8, 256)
        assert book.ids() == {"bob@x.i2p": aid}
        assert book.note_metadata("bob@x.i2p", [info]) is None   # already have it

    @pytest.mark.parametrize("info", [
        {"type": "image/jpeg", "bytes": 100},
        {"type": "image/webp", "bytes": 100},
        {"type": "image/svg+xml", "bytes": 100},
        {"type": "image/png", "bytes": A.MAX_BYTES + 1},
        {"type": "image/png", "bytes": 100, "width": 4096, "height": 10},
        {"type": "image/png", "bytes": 0},
        {"type": "image/png", "bytes": "lots"},
    ])
    def test_announcements_outside_the_rules_are_not_fetched(self, info):
        info = dict(info, id="a" * 40)
        assert A.AvatarBook().note_metadata("bob@x.i2p", [info]) is None

    @pytest.mark.parametrize("bad_id", ["", "z" * 40, "a" * 39, "../../etc/passwd",
                                        "a" * 40 + "\n<script>"])
    def test_ids_must_be_sha1_hex(self, bad_id):
        info = {"id": bad_id, "type": "image/png", "bytes": 10}
        assert A.AvatarBook().note_metadata("bob@x.i2p", [info]) is None

    def test_data_that_does_not_match_its_id_is_dropped(self):
        book = A.AvatarBook()
        data, aid, _ = self._published()
        other = base64.b64encode(png(4, 4, 2)).decode()
        book.note_metadata("bob@x.i2p", [{"id": aid, "type": "image/png", "bytes": 10}])
        assert not book.note_data("bob@x.i2p", aid, other)
        assert book.get("bob@x.i2p") is None

    def test_unrequested_data_is_dropped(self):
        data, aid, b64 = self._published()
        assert not A.AvatarBook().note_data("bob@x.i2p", aid, b64)

    def test_oversized_base64_is_not_even_decoded(self):
        book = A.AvatarBook()
        book.note_metadata("bob@x.i2p", [{"id": "a" * 40, "type": "image/png", "bytes": 10}])
        assert not book.note_data("bob@x.i2p", "a" * 40, "A" * (A.MAX_B64_CHARS + 4))

    def test_an_empty_announcement_removes_the_avatar(self):
        book = A.AvatarBook()
        data, aid, b64 = self._published()
        book.note_metadata("bob@x.i2p", [{"id": aid, "type": "image/png", "bytes": 10}])
        book.note_data("bob@x.i2p", aid, b64)
        book.note_metadata("bob@x.i2p", [])
        assert book.get("bob@x.i2p") is None

    def test_bounded(self):
        book = A.AvatarBook(limit=3)
        for i in range(5):
            book.set_own("u%d@x.i2p" % i, png(2, 2, 6))
        assert sorted(book.ids()) == ["u2@x.i2p", "u3@x.i2p", "u4@x.i2p"]

    def test_own_avatar_passes_the_same_checks(self):
        with pytest.raises(A.AvatarError):
            A.AvatarBook().set_own("me@x.i2p", b"\xff\xd8\xff")


class TestTheTransport:
    """The XEP-0084 wiring: announcement -> checks -> fetch -> decode."""

    def _transport(self, data_text):
        import asyncio
        from android_bridge import transport as T

        class Plugin:
            fetched = []
            published = []

            async def retrieve_avatar(self, jid, aid, timeout=None):
                self.fetched.append((jid, aid))
                import xml.etree.ElementTree as ET
                iq = type("Iq", (), {})()
                iq.xml = ET.fromstring(
                    '<iq xmlns="jabber:client"><pubsub xmlns="http://jabber.org/'
                    'protocol/pubsub"><items><item><data xmlns="urn:xmpp:avatar:'
                    'data">%s</data></item></items></pubsub></iq>' % data_text)
                return iq

            async def publish_avatar(self, png, timeout=None):
                self.published.append(("data", len(png)))

            async def publish_avatar_metadata(self, items, timeout=None):
                self.published.append(("meta", items[0]["type"]))

        t = T.XmppTransport.__new__(T.XmppTransport)
        t._avatars = A.AvatarBook()
        plugin = Plugin()
        t._client = {"xep_0084": plugin}
        return t, plugin, asyncio

    def _announce(self, t, infos):
        import xml.etree.ElementTree as ET
        attrs = "".join('<info %s/>' % " ".join('%s="%s"' % kv for kv in i.items())
                        for i in infos)
        xml = ET.fromstring(
            '<message xmlns="jabber:client"><event xmlns="http://jabber.org/'
            'protocol/pubsub#event"><items node="urn:xmpp:avatar:metadata">'
            '<item><metadata xmlns="urn:xmpp:avatar:metadata">%s</metadata>'
            '</item></items></event></message>' % attrs)
        msg = {"from": "Bob@x.i2p/phone"}
        m = type("Msg", (dict,), {})(msg)
        m.xml = xml
        t._on_avatar_metadata(m)

    def test_an_announced_png_is_fetched_and_decoded(self):
        data = png(12, 10, 2)
        aid = hashlib.sha1(data).hexdigest()
        t, plugin, asyncio = self._transport(base64.b64encode(data).decode())

        async def go():
            self._announce(t, [{"id": aid, "type": "image/png", "bytes": len(data),
                                "width": 12, "height": 10}])
            for _ in range(100):
                if t.avatar_ids():
                    break
                await asyncio.sleep(0.01)
        asyncio.run(go())
        assert plugin.fetched == [("bob@x.i2p", aid)]
        assert t.avatar_ids() == {"bob@x.i2p": aid}
        assert t.avatar("bob@x.i2p").width == 12

    def test_a_jpeg_announcement_fetches_nothing(self):
        t, plugin, asyncio = self._transport("")

        async def go():
            self._announce(t, [{"id": "a" * 40, "type": "image/jpeg", "bytes": 900}])
            await asyncio.sleep(0.05)
        asyncio.run(go())
        assert plugin.fetched == [] and t.avatar_ids() == {}

    def test_publishing_checks_our_own_picture_too(self):
        from android_bridge import transport as T
        t, plugin, asyncio = self._transport("")
        import threading
        t._connected = threading.Event()
        t._connected.set()
        t._profile = type("P", (), {"jid": "me@x.i2p"})()
        t._run = lambda coro, timeout: asyncio.run(coro)
        with pytest.raises(T.TransportError) as exc:
            t.publish_avatar(b"\xff\xd8\xff\xe0 not a png")
        assert exc.value.code == "avatar_refused" and plugin.published == []
        good = png(96, 96, 6)
        t.publish_avatar(good)
        assert plugin.published == [("data", len(good)), ("meta", "image/png")]
        assert "me@x.i2p" in t.avatar_ids()

    def test_a_server_without_pep_is_named_as_the_cause(self):
        """Device test (2026-10-10): the picture was fine (13 KB, 96x96 PNG
        after the app's conversion) but Prosody had no "pep" module, and the
        app only said it 'could not be published'."""
        slixmpp = pytest.importorskip("slixmpp")
        from slixmpp.exceptions import IqError
        from android_bridge import transport as T
        from android_bridge.connection import ConnectionController
        t, plugin, asyncio = self._transport("")

        async def refuse(png, timeout=None):
            iq = slixmpp.stanza.Iq()
            iq["type"] = "error"
            iq["error"]["type"] = "cancel"
            iq["error"]["condition"] = "feature-not-implemented"
            raise IqError(iq)

        plugin.publish_avatar = refuse
        import threading
        t._connected = threading.Event()
        t._connected.set()
        t._profile = type("P", (), {"jid": "me@x.i2p"})()
        t._run = lambda coro, timeout: asyncio.run(coro)
        with pytest.raises(T.TransportError) as exc:
            t.publish_avatar(png(96, 96, 6))
        assert exc.value.code == "pep_unavailable"
        ctl = ConnectionController.__new__(ConnectionController)
        ctl._transport = t
        out = ctl.set_avatar(png(96, 96, 6))
        assert not out["ok"] and out["code"] == "pep_unavailable"
        assert "pep" in out["detail"] and "modules_enabled" in out["detail"]

    def _real_run(self, t):
        """The transport's own `_run` on its own loop thread -- not
        asyncio.run, which let exceptions through that the real one turns
        into "unexpected_error" (and hid the bug below)."""
        import threading
        t._lock = threading.RLock()
        t._closed = False
        t._loop = None
        t._connected = threading.Event()
        t._connected.set()
        t._profile = type("P", (), {"jid": "me@x.i2p"})()

    def _refusing(self, plugin, make):
        async def refuse(png, timeout=None):
            raise make()
        plugin.publish_avatar = refuse

    @pytest.mark.parametrize("cond,code", [
        ("feature-not-implemented", "pep_unavailable"),
        ("not-acceptable", "avatar_server_refused"),
        ("forbidden", "avatar_server_refused"),
    ])
    def test_a_server_refusal_survives_the_real_loop(self, cond, code):
        """Device report (2026-10-16): pictures failed with PEP on, and the
        app only ever said "could not be published" -- the real `_run`
        flattened every server answer to "unexpected_error" before it was
        read. The condition must reach the user."""
        slixmpp = pytest.importorskip("slixmpp")
        from slixmpp.exceptions import IqError
        from android_bridge import transport as T
        from android_bridge.connection import ConnectionController
        t, plugin, _asyncio = self._transport("")
        self._real_run(t)

        def make():
            iq = slixmpp.stanza.Iq()
            iq["type"] = "error"
            iq["error"]["type"] = "cancel"
            iq["error"]["condition"] = cond
            return IqError(iq)

        self._refusing(plugin, make)
        with pytest.raises(T.TransportError) as exc:
            t.publish_avatar(png(96, 96, 6))
        assert exc.value.code == code
        ctl = ConnectionController.__new__(ConnectionController)
        ctl._transport = t
        out = ctl.set_avatar(png(96, 96, 6))
        assert out["code"] == code
        if code != "pep_unavailable":
            assert cond in out["detail"]

    def test_a_timeout_says_so_and_waits_long_enough(self):
        slixmpp = pytest.importorskip("slixmpp")
        from slixmpp.exceptions import IqTimeout
        from android_bridge import transport as T
        from android_bridge.connection import ConnectionController
        t, plugin, _asyncio = self._transport("")
        self._real_run(t)
        self._refusing(plugin, lambda: IqTimeout(slixmpp.stanza.Iq()))
        with pytest.raises(T.TransportError) as exc:
            t.publish_avatar(png(96, 96, 6))
        assert exc.value.code == "timeout"
        ctl = ConnectionController.__new__(ConnectionController)
        ctl._transport = t
        assert "I2P" in ctl.set_avatar(png(96, 96, 6))["detail"]
        # Each round trip gets minutes, not the 30 s a chat call gets.
        assert T.AVATAR_TIMEOUT >= 120

    def test_a_publish_through_the_real_loop_succeeds(self):
        t, plugin, _asyncio = self._transport("")
        self._real_run(t)
        good = png(96, 96, 6)
        plugin.published.clear()
        t.publish_avatar(good)
        assert plugin.published == [("data", len(good)), ("meta", "image/png")]

    def test_an_unanswered_picture_is_sent_again_smaller(self):
        """Device report (2026-10-16, rc.85): "The server did not answer
        over I2P in time". The connection stayed up: the full picture got no
        answer, so a 48 x 48 copy goes at once -- and says so."""
        slixmpp = pytest.importorskip("slixmpp")
        from slixmpp.exceptions import IqTimeout
        from android_bridge import avatar as A_
        from android_bridge.connection import ConnectionController
        t, plugin, _asyncio = self._transport("")
        self._real_run(t)
        sizes = []
        calls = [0]

        async def publish(data, timeout=None):
            sizes.append(len(data))
            calls[0] += 1
            if calls[0] == 1:
                raise IqTimeout(slixmpp.stanza.Iq())
            plugin.published.append(("data", len(data)))

        plugin.published.clear()
        plugin.publish_avatar = publish
        big = png(96, 96, 6)
        ctl = ConnectionController.__new__(ConnectionController)
        ctl._transport = t
        out = ctl.set_avatar(big)
        assert out["ok"] and "smaller" in out["detail"]
        assert sizes[0] == len(big) and sizes[1] < len(big)
        w, h, _ = A_.decode_png(A_.shrink(big))
        assert (w, h) == (A_.SMALL_SIZE, A_.SMALL_SIZE)
        # Learned: the next picture goes small straight away.
        sizes.clear()
        assert ctl.set_avatar(big)["ok"] and sizes == [len(A_.shrink(big))]

    def test_a_dropped_stream_is_named_and_the_next_try_is_small(self):
        slixmpp = pytest.importorskip("slixmpp")
        from slixmpp.exceptions import IqTimeout
        from android_bridge.connection import ConnectionController
        t, plugin, _asyncio = self._transport("")
        self._real_run(t)

        async def publish(data, timeout=None):
            t._disconnects = getattr(t, "_disconnects", 0) + 1   # the stream went
            raise IqTimeout(slixmpp.stanza.Iq())

        plugin.publish_avatar = publish
        ctl = ConnectionController.__new__(ConnectionController)
        ctl._transport = t
        out = ctl.set_avatar(png(96, 96, 6))
        assert out["code"] == "timeout" and "dropped" in out["detail"]
        assert t._avatar_small_next

    def test_the_controller_hands_raw_pixels_not_the_file(self):
        from android_bridge.connection import ConnectionController
        data = png(5, 4, 6)
        t, _plugin, _asyncio = self._transport("")
        t._avatars.set_own("bob@x.i2p", data)
        ctl = ConnectionController.__new__(ConnectionController)
        ctl._transport = t
        got = ctl.avatar_pixels("bob@x.i2p")
        assert got["width"] == 5 and got["height"] == 4
        assert len(got["rgba"]) == 5 * 4 * 4
        assert not got["rgba"].startswith(b"\x89PNG")
        assert ctl.avatar_ids() == {"bob@x.i2p": hashlib.sha1(data).hexdigest()}
        assert base64.b64decode(got["rgba_b64"]) == got["rgba"]
        assert ctl.avatar_index() == ["bob@x.i2p\t" + hashlib.sha1(data).hexdigest()]


# -- what an Android phone actually sends (device report 2026-10-15) ---------------

def _android_like_png(w, h, colour, filt_cycle=(0, 1, 2, 3, 4), idat_parts=3):
    """A PNG as Skia writes one: 8-bit RGB (colour 2) for an opaque photo or
    RGBA (6), rows filtered with every filter type, IDAT split in several."""
    import random
    import struct
    import zlib
    rnd = random.Random(w * 31 + colour)
    ch = 3 if colour == 2 else 4
    rows = [bytes(rnd.randrange(256) for _ in range(w * ch)) for _ in range(h)]

    def paeth(a, b, c):
        p = a + b - c
        pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
        return a if pa <= pb and pa <= pc else (b if pb <= pc else c)
    raw = bytearray()
    prev = bytes(w * ch)
    for y, row in enumerate(rows):
        f = filt_cycle[y % len(filt_cycle)]
        out = bytearray()
        for i, x in enumerate(row):
            a = row[i - ch] if i >= ch else 0
            b = prev[i]
            c = prev[i - ch] if i >= ch else 0
            pred = (0, a, b, (a + b) // 2, paeth(a, b, c))[f]
            out.append((x - pred) & 0xFF)
        raw += bytes([f]) + out
        prev = row
    z = zlib.compress(bytes(raw), 9)

    def chunk(t, body):
        return struct.pack(">I", len(body)) + t + body + struct.pack(">I", zlib.crc32(t + body) & 0xFFFFFFFF)
    step = max(1, len(z) // idat_parts)
    parts = [z[i:i + step] for i in range(0, len(z), step)]
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, colour, 0, 0, 0))
    png += chunk(b"sRGB", b"\x00")                         # ancillary, as Skia adds
    for p in parts:
        png += chunk(b"IDAT", p)
    png += chunk(b"IEND", b"")
    expected = bytearray()
    for row in rows:
        for i in range(0, len(row), ch):
            px = row[i:i + ch]
            expected += px + (b"\xff" if ch == 3 else b"")
    return png, bytes(expected)


@pytest.mark.parametrize("colour", [2, 6])
def test_our_own_96px_avatar_as_a_phone_encodes_it_is_accepted(colour):
    from android_bridge import avatar as A
    png, expected = _android_like_png(A.OWN_SIZE, A.OWN_SIZE, colour)
    assert len(png) <= A.MAX_BYTES
    w, h, rgba = A.decode_png(png)
    assert (w, h) == (A.OWN_SIZE, A.OWN_SIZE)
    assert rgba == expected


def test_the_bridge_takes_the_phones_base64_and_publishes_it():
    import base64
    from android_bridge import avatar as A
    from android_bridge.connection import ConnectionController
    png, _ = _android_like_png(A.OWN_SIZE, A.OWN_SIZE, 2)
    published = []

    class T:
        def publish_avatar(self, data):
            A.decode_png(data)                     # the transport's own check
            published.append(data)
    c = ConnectionController.__new__(ConnectionController)
    c._transport = T()
    out = c.set_avatar_b64(base64.b64encode(png).decode())
    assert out["ok"], out
    assert published == [png]


def test_our_encoder_round_trips_through_the_hardened_decoder():
    from android_bridge import avatar as A_
    for colour in (6, 2):
        data = png(96, 96, colour)
        w, h, rgba = A_.decode_png(data)
        again = A_.encode_png(w, h, rgba)
        assert A_.decode_png(again) == (w, h, rgba)
    small = A_.shrink(png(96, 96, 6))
    assert A_.decode_png(small)[:2] == (48, 48)
    assert A_.shrink(png(40, 40, 6)) == png(40, 40, 6)     # already small


def test_any_picture_is_fitted_to_the_limit():
    """Owner (2026-10-16): "select any image format and it should convert
    for our limits". Whatever the app hands over -- even pure noise, the
    worst case for PNG -- leaves as a square PNG within TARGET_BYTES that
    our own hardened decoder accepts."""
    import os
    from android_bridge import avatar as A_
    noisy = png(96, 96, 2, rows=[os.urandom(96 * 3) for _ in range(96)])
    assert len(noisy) > A_.TARGET_BYTES
    out = A_.fit(noisy)
    w, h, _ = A_.decode_png(out)
    assert w == h and w <= A_.OWN_SIZE and len(out) <= A_.TARGET_BYTES
    wide = png(120, 60, 6)                          # not square: centre-cropped
    w, h, _ = A_.decode_png(A_.fit(wide))
    assert w == h == 60
    small = png(40, 40, 6)                          # already fine: untouched
    assert A_.fit(small) == small


def test_the_metadata_stanza_actually_serialises():
    """Device report (2026-10-16): the avatar's metadata announcement was
    built with integer attributes, slixmpp could not write it, and it never
    left the phone -- every picture "timed out" while the server had stored
    it. This builds the real slixmpp stanza from what the transport passes
    and writes it out."""
    pytest.importorskip("slixmpp")
    from slixmpp.plugins.xep_0084.stanza import MetaData
    from android_bridge.transport import XmppTransport
    data = png(96, 96, 6)
    info = XmppTransport._avatar_info("a" * 40, data, 96, 96)
    m = MetaData()
    m.add_info(info["id"], info["type"], info["bytes"],
               height=info.get("height", ""), width=info.get("width", ""), url="")
    xml = str(m)
    assert 'bytes="%d"' % len(data) in xml and 'width="96"' in xml

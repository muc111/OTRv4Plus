# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 muc111
"""Smaller fixes from the 2026-11 red-team pass (docs/RED_TEAM_2026-11.md).

The two large ones have their own files: test_stream_guard.py and
test_sasl_hardening.py.
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def test_the_sam_session_name_cannot_be_guessed():
    """SAM has no login and any program on the machine can reach its port;
    the session name is all that stops one attaching to our session."""
    engine = _read("client", "otrv4+.py")
    assert re.search(r"SAM_SESSION_ID_BYTES\s*=\s*16\b", engine)
    names = re.findall(r'self\._session_id\s*=\s*f"otrv4plus_\{([^}]*)\}"',
                       engine)
    assert len(names) == 2
    for made in names:
        assert "SAM_SESSION_ID_BYTES" in made and "secrets" in made
    assert "token_hex (4 )" not in engine and "token_hex(4)" not in engine


def test_the_built_in_router_opens_nothing_but_sam_on_loopback():
    config = _read("android", "app", "src", "main", "java", "org",
                   "otrv4plus", "android", "connection", "RouterChoice.kt")
    body = config[config.index('fun config(samPort: Int)'):]
    body = body[:body.index('""".trimMargin()')]
    for section in ("http", "httpproxy", "socksproxy", "bob", "i2cp",
                    "i2pcontrol", "upnp"):
        assert re.search(r"\|\[%s\]\s*\n\s*\|enabled = false" % section,
                         body), section
    assert re.search(r"\|\[sam\]\s*\n\s*\|enabled = true\s*\n\s*"
                     r"\|address = 127\.0\.0\.1", body)


def test_an_admin_is_recognised_without_mod_admin_adhoc():
    server = _read("android_bridge", "transport_server.py")
    ask = server[server.index("async def _ask_server_admin"):]
    ask = ask[:ask.index("MODERATION_NS =")]
    assert "self.ADMIN_COMMAND_PREFIX, self.MODERATION_NS" in ask


def test_the_guides_say_what_gives_a_hidden_server_away():
    hardening = _read("docs", "SERVER_HARDENING.md")
    for needed in ('interfaces = { "127.0.0.1" }',
                   'modules_disabled = { "s2s" }',
                   "HIDDEN_SERVICE=1",
                   "Do **not** change `password_hash`",
                   "ss -ltnp"):
        assert needed in hardening, needed
    guide = _read("docs", "RUN_A_SERVER.md")
    assert "HIDDEN_SERVICE=1" in guide
    assert "keep-the-servers-address-hidden" in guide

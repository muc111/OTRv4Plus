# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Sound and vibration for messages and requests, and nothing that names
anyone (owner, 2026-10-17).

A message, a verification request, a group invitation and a group's
password prompt each make a tone and a buzz (or a notification that does,
in the background). What any of them may say: the kind of thing, never who
or which. Like messages, requests share ONE notification, hidden entirely
on a locked screen.
"""

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KT = os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                  "otrv4plus", "android")


def _read(*parts):
    return open(os.path.join(KT, *parts), encoding="utf-8").read()


SERVICE = _read("connection", "OtrConnectionService.kt")


def _block(src, start, end):
    body = src[src.index(start):]
    return body[:body.index(end)]


class TestTheChannelsSoundAndVibrate:

    def test_messages_have_sound_and_vibration(self):
        block = _block(SERVICE, "val messages = NotificationChannel(", "val attention")
        assert "setSound(" in block
        assert "enableVibration(true)" in block
        assert "lockscreenVisibility = Notification.VISIBILITY_SECRET" in block

    def test_the_channel_without_them_is_replaced(self):
        """A channel's sound and vibration are fixed once it exists."""
        assert 'MESSAGE_CHANNEL_ID = "otrv4plus.messages.alert"' in SERVICE
        assert "deleteNotificationChannel(OLD_MESSAGE_CHANNEL_ID)" in SERVICE

    def test_requests_have_their_own_secret_channel(self):
        block = _block(SERVICE, "val attention = NotificationChannel(", "val calls")
        assert "enableVibration(true)" in block and "setSound(" in block
        assert "lockscreenVisibility = Notification.VISIBILITY_SECRET" in block
        assert "setShowBadge(false)" in block


class TestARequestNamesNobody:

    def test_one_notification_for_every_request(self):
        assert "ATTENTION_NOTIFICATION_ID = 6" in SERVICE
        body = _block(SERVICE, "private fun needAttention(", "private fun cancelAttentionNotification")
        assert "notify(ATTENTION_NOTIFICATION_ID" in body
        assert "VISIBILITY_SECRET" in body

    def test_its_text_is_the_kind_only(self):
        body = _block(SERVICE, "private fun needAttention(", "private fun cancelAttentionNotification")
        assert "Attention.text(" in body
        for leak in ("peer", "room", "jid", "displayName", "sender"):
            assert not re.search(r"\b%s\b" % leak, body), leak

    def test_the_kinds_say_no_name(self):
        src = _read("chat", "Attention.kt")
        texts = re.findall(r'[A-Z_]+\("([^"]+)"\)', src)
        assert texts == ["Verification requested", "Group invitation",
                         "A group needs its password"]

    def test_coming_to_the_front_takes_it_down(self):
        assert "if (visible) cancelAttentionNotification()" in SERVICE


class TestEveryoneOnScreenGetsATone:

    def test_the_drain_loop_asks(self):
        assert "Attention.of(event)?.let { needAttention(it) }" in SERVICE

    def test_the_in_app_tone_also_buzzes_as_the_ring_mode_allows(self):
        fb = _read("connection", "AlertFeedback.kt")
        assert "RINGER_MODE_SILENT) return" in fb
        assert "RINGER_MODE_NORMAL) tone(context)" in fb
        assert "vibrate(context)" in fb
        assert "private fun playInAppTone() = AlertFeedback.inApp(this)" in SERVICE

    def test_the_password_prompt_does_too(self):
        screen = _read("ui", "ConversationsScreen.kt")
        i = screen.index("model.groupRoomPasswordFor?.let")
        assert "AlertFeedback.inApp(context)" in screen[i:i + 600]

    def test_vibration_is_declared(self):
        manifest = open(os.path.join(ROOT, "android", "app", "src", "main",
                                     "AndroidManifest.xml")).read()
        assert "android.permission.VIBRATE" in manifest

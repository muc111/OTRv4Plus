#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The conversation list said nothing about security at all.

`Conversation` has carried `security` and `smp` since it was written. The row
rendered a name, a preview, a timestamp, a presence dot and an unread badge --
and neither of those two fields. So a user scanning their conversations could
not tell an encrypted-and-verified thread from one going out in the clear
without opening it, which is the one comparison this application exists to
make easy.

WHAT IT SAYS, AND WHAT IT REFUSES TO SAY
========================================
A WORD, never a padlock. `ConversationScreen` states the rule and it holds in
the list: "Being connected to XMPP says nothing about whether this
conversation is encrypted, and the two are easy to blur into a reassuring icon
that means the network is up. A padlock next to a plaintext message would be
the one claim this project cannot afford to get wrong."

WHERE THE RULES LIVE
====================
`chat/RowSecurity.kt` -- plain Kotlin, no Compose and no Android -- so that
`RowSecurityTest` can EXECUTE them in CI rather than have a reader infer them
from a Composable this container cannot build. Same split as
`crypto/Verification.kt` and `connection/Startup.kt`.

This file asserts the structural facts that make those rules safe: that the
`when` is exhaustive with no `else` arm to inherit, that exactly one state
earns the verified tone, and that the Composable decides nothing. The
behaviour itself is driven in `RowSecurityTest`.
"""

import io
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANDROID = os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                       "otrv4plus", "android")
TESTS_KT = os.path.join(ROOT, "android", "app", "src", "test", "java", "org",
                        "otrv4plus", "android")


def _code(text):
    """*text* with its comments removed.

    The doc comments in `RowSecurity.kt` name the tokens these tests count --
    "exactly one [SecurityState] earns [Tone.GOOD]" is a sentence, not an arm
    -- so counting over the raw source counts the prose too.
    """
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def _read(*parts):
    with io.open(os.path.join(*parts), encoding="utf-8") as handle:
        return handle.read()


@pytest.fixture(scope="module")
def rules():
    return _read(ANDROID, "chat", "RowSecurity.kt")


@pytest.fixture(scope="module")
def screen():
    return _read(ANDROID, "ui", "ConversationsScreen.kt")


class TestTheRowSaysSomething:

    def test_the_row_renders_a_security_badge(self, screen):
        assert "SecurityBadge(conversation)" in screen, (
            "the conversation list renders neither `security` nor `smp`, so "
            "an encrypted thread and a plaintext one look identical")

    def test_it_reads_both_fields_it_is_about(self, screen):
        body = screen[screen.index("private fun SecurityBadge("):]
        assert "conversation.security" in body
        assert "conversation.smp" in body


class TestItIsAWordAndNotAPadlock:
    """The convention `ConversationScreen` states, applied to the list."""

    def test_the_badge_is_text(self, screen):
        body = screen[screen.index("private fun SecurityBadge("):]
        body = body[:body.index("\n}")]
        assert "Text(" in body

    def test_no_icon_is_used_for_security(self, screen):
        body = screen[screen.index("private fun SecurityBadge("):]
        body = body[:body.index("\n}")]
        for icon in ("Icon(", "Lock", "padlock", "imageVector"):
            assert icon not in body, (
                "the security badge became an icon; an icon blurs "
                "'the network is up' into 'this is safe'")

    def test_the_plaintext_case_is_stated_rather_than_omitted(self, rules):
        assert '"Not encrypted"' in rules, (
            "plaintext is left to be inferred from the absence of a badge")


class TestOnlyTheEnginesAnswerReadsAsVerified:
    """The one word this application must never say wrongly."""

    def test_exactly_one_arm_is_the_good_tone(self, rules):
        body = _code(rules)
        body = body[body.index("fun badge("):body.index("fun statesDescribedAsVerified")]
        assert body.count("Tone.GOOD") == 1, (
            "more than one state reads as verified")

    def test_that_arm_is_smp_verified(self, rules):
        body = rules[rules.index("fun badge("):]
        arm = body[body.index("SecurityState.SMP_VERIFIED ->"):]
        assert "Tone.GOOD" in arm[:200]

    def test_the_encrypted_arm_cannot_reach_the_good_tone(self, rules):
        """A stale `SmpState` must not be able to promote a row whose SESSION
        state is merely ENCRYPTED. The two are answers from the same engine
        and, if they disagree, the row takes the weaker one."""
        body = rules[rules.index("SecurityState.ENCRYPTED, SecurityState.FINGERPRINT ->"):]
        arm = body[:body.index("SecurityState.SMP_VERIFIED ->")]
        assert "Tone.GOOD" not in arm

    def test_the_rule_is_exposed_as_a_value_a_test_can_assert_on(self, rules):
        assert "fun statesDescribedAsVerified()" in rules, (
            "the verified rule can only be inferred from the shape of a "
            "`when`, so nothing can assert on it directly")


class TestNothingCanArriveAndInheritAFallback:

    def test_the_when_is_exhaustive_with_no_else(self, rules):
        body = rules[rules.index("fun badge("):rules.index("fun statesDescribedAsVerified")]
        assert re.search(r"\belse\s*->", body) is None, (
            "a new SecurityState can arrive and quietly inherit whatever the "
            "fallback arm happened to say")

    def test_every_security_state_has_an_arm(self, rules):
        states = re.findall(r"^\s+([A-Z_]+)\(\d+\)",
                            _read(ANDROID, "bridge", "OtrCore.kt"), re.M)
        assert "SMP_VERIFIED" in states, "the state list could not be read"
        body = rules[rules.index("fun badge("):rules.index("fun statesDescribedAsVerified")]
        for state in states:
            assert "SecurityState.%s" % state in body, (
                "SecurityState.%s has no arm" % state)


class TestTheDecisionIsExecutable:
    """The project's own pattern: the part that can be wrong lives in a
    dependency-free leaf, because this container cannot build Compose and a
    rule nothing runs is a rule nobody checked."""

    def test_the_rules_touch_neither_compose_nor_android(self, rules):
        imports = [line for line in rules.splitlines()
                   if line.startswith("import ")]
        # Its own package is not a dependency; anything else under `android.`
        # or `androidx.` is a platform one and cannot run off a device.
        for line in imports:
            assert line.startswith("import org.otrv4plus."), (
                "RowSecurity imports a platform type (%s), so its rules can "
                "no longer be executed off a device" % line.strip())
        assert "@Composable" not in rules

    def test_a_kotlin_test_drives_them(self):
        assert os.path.exists(
            os.path.join(TESTS_KT, "chat", "RowSecurityTest.kt"))

    def test_the_composable_only_maps_the_tone(self, screen):
        """It must not make a second, quieter decision of its own."""
        body = screen[screen.index("private fun SecurityBadge("):]
        body = body[:body.index("\n}")]
        assert "RowSecurity.badge(" in body
        for decision in ("SecurityState.", "SmpState."):
            assert decision not in body, (
                "the Composable branches on %s itself, so there are two "
                "places deciding what a row claims" % decision)

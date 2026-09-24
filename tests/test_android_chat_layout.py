# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The chat history collapsed into a strip at the top when the input was tapped.

THE ROOT CAUSE
--------------
The keyboard was subtracted twice.

`targetSdk` is 35, where Android enforces edge-to-edge: the window keeps its
full height when the IME opens and the app is expected to apply the inset
itself, which is what `Modifier.imePadding()` is for.

`minSdk` is 26. On Android 14 and earlier, edge-to-edge is NOT enforced, the
theme is `android:Theme.Material.Light.NoActionBar`, nothing called
`enableEdgeToEdge()`, and the platform default `adjustResize` applies: **the
window itself shrinks** by the keyboard height. `imePadding()` on the content
then subtracted that same height *again* from a window that had already lost
it. Two subtractions plus the composer's own height left `weight(1f)` almost
nothing, which is the reported "upper 1/8".

There was a second, smaller fault stacked on it: `imePadding()` sat on the
inner Column rather than on the Scaffold, so the Scaffold still believed it had
the full window. It placed the composer under the keyboard and handed the
content lambda a padding reserving space for a composer that was no longer
where the padding said.

THE FIX
-------
`WindowCompat.setDecorFitsSystemWindows(window, false)` makes the modern
behaviour the behaviour on every API level, so the window never resizes and
there is exactly one mechanism; and `imePadding()` moves to the Scaffold, where
it shrinks the whole thing so `bottomBar` lands on the keyboard and the content
padding is computed from what is really left.

WHAT THESE TESTS CAN AND CANNOT DO
----------------------------------
Compose cannot be executed here -- `dl.google.com` is blocked, so the Android
Gradle Plugin does not resolve. These read the source and pin the invariants
that were violated. **They cannot prove the layout is right on a screen**, and
the milestone's physical acceptance is what does that. What they can do is stop
the exact defect returning, which is what a regression test is for.
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
CONVERSATION = os.path.join(UI, "ui", "ConversationScreen.kt")
MAIN = os.path.join(UI, "MainActivity.kt")
GRADLE = os.path.join(ROOT, "android", "app", "build.gradle.kts")


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def code_of(path):
    """Source with comments stripped.

    Necessary rather than fastidious: these files EXPLAIN the defect at
    length, so a test searching the raw text for `imePadding` finds the
    paragraph describing where it used to be.
    """
    text = re.sub(r"/\*.*?\*/", "", read(path), flags=re.S)
    return "\n".join(line for line in text.splitlines()
                     if not line.lstrip().startswith("//"))


@pytest.fixture(scope="module")
def chat():
    return code_of(CONVERSATION)


# ── the keyboard is subtracted exactly once ──────────────────────────────────

class TestTheImeIsHandledOnce:

    def test_there_is_exactly_one_ime_padding(self, chat):
        """Two was the defect. Not 'roughly one' -- each one subtracts the
        full keyboard height from whatever it is applied to."""
        assert chat.count("imePadding()") == 1, (
            "the keyboard is being subtracted %d times"
            % chat.count("imePadding()"))

    def test_it_is_on_the_scaffold_not_the_content(self, chat):
        """On the Scaffold the whole thing shrinks, so `bottomBar` lands on
        the keyboard. On the content the Scaffold still thinks it has the full
        window and puts the composer underneath it."""
        scaffold = chat.index("Scaffold(")
        content = chat.index("Column(", scaffold)
        assert scaffold < chat.index("imePadding()") < content

    def test_the_window_is_told_not_to_resize(self):
        """The other half. Without this the window shrinks on API <= 34 and
        `imePadding()` subtracts the same height a second time."""
        assert "setDecorFitsSystemWindows(window, false)" in code_of(MAIN)

    def test_the_two_halves_are_both_needed(self):
        """Stated as a test so neither is removed as redundant: on API 35 the
        decor call is a no-op and `imePadding()` does the work; on API 26-34
        the decor call is what makes `imePadding()` correct rather than
        double-counting."""
        assert "35" in read(GRADLE)[read(GRADLE).index("targetSdk"):
                                    read(GRADLE).index("targetSdk") + 30]
        assert "26" in read(GRADLE)[read(GRADLE).index("minSdk ="):
                                    read(GRADLE).index("minSdk =") + 30]


# ── the history gets the remaining space ─────────────────────────────────────

class TestTheHistoryFillsWhatIsLeft:

    def test_the_message_list_is_flexible(self, chat):
        """`weight(1f)` is what makes it take the remaining height. A fixed
        or wrapped height is the defect in a different form."""
        block = chat[chat.index("LazyColumn("):]
        block = block[:block.index("}")]
        assert "weight(1f)" in block

    def test_the_empty_state_is_flexible_too(self, chat):
        """Otherwise an empty conversation leaves the composer floating in
        the middle of the screen."""
        block = chat[chat.index("No messages yet"):]
        start = chat.rindex("Box(", 0, chat.index("No messages yet"))
        assert "weight(1f)" in chat[start:chat.index("No messages yet")]

    def test_no_hard_coded_height_anywhere_in_the_chat_column(self, chat):
        """The brief forbids fixing this with a fixed dimension, and it would
        be a fix that breaks on every other screen size."""
        assert not re.search(r"\.height\(\s*\d+\s*\.dp\s*\)", chat), (
            "a fixed height in the chat screen")
        assert "fillMaxHeight(" not in chat
        assert "0.125" not in chat and "1/8" not in chat

    def test_the_history_is_not_hidden_when_the_keyboard_opens(self, chat):
        """Also forbidden, and it would make the app useless while typing."""
        assert "imeVisible" not in chat
        assert "isImeVisible" not in chat

    def test_the_padding_is_applied_before_the_fill(self, chat):
        """`padding(padding)` then `fillMaxSize()`: the padding reduces the
        constraints and the fill takes what is left. Reversed, the Column
        sizes to the full window and then insets, overflowing by exactly the
        padding."""
        block = chat[chat.index("Column("):]
        block = block[:block.index(") {")]
        assert block.index(".padding(padding)") < block.index(".fillMaxSize()")


class TestTheComposerStaysAtTheBottom:

    def test_it_is_the_scaffold_bottom_bar(self, chat):
        """Not the last child of the content Column: a bottomBar is anchored
        by the Scaffold, a last child is merely at the end of a list that
        might scroll."""
        assert "bottomBar = {" in chat
        block = chat[chat.index("bottomBar = {"):]
        block = block[:block.index("},")]
        assert "Composer(" in block

    def test_the_composer_clears_the_navigation_bar(self, chat):
        """The window no longer fits the decor, so without this the Send
        button sits under the gesture bar."""
        block = chat[chat.index("private fun Composer("):]
        assert "navigationBarsPadding()" in block


# ── the rest of the app still fits ───────────────────────────────────────────

class TestTurningOffDecorFittingDidNotBreakOtherScreens:

    @pytest.mark.parametrize("screen", [
        "ConnectScreen", "RoomsScreen", "DevShellScreen", "AboutScreen",
    ])
    def test_a_non_scaffold_screen_insets_itself(self, screen):
        """These are plain scrolling Columns with no Scaffold to do it for
        them. Without this the title sits under the status bar and the last
        control sits under the navigation bar."""
        source = code_of(os.path.join(UI, "ui", "%s.kt" % screen))
        assert "systemBarsPadding()" in source, screen

    @pytest.mark.parametrize("screen", ["ConversationScreen",
                                        "ConversationsScreen"])
    def test_a_scaffold_screen_does_not_double_inset(self, screen):
        """`Scaffold` already applies its `contentWindowInsets`. Adding
        `systemBarsPadding()` on top would inset twice -- the same class of
        mistake as the IME one, and it would look like a fat top margin."""
        source = code_of(os.path.join(UI, "ui", "%s.kt" % screen))
        assert "systemBarsPadding()" not in source, screen

# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The desktop UI is redrawn through `AppModel.revision`, read at the top
of each screen, so Compose's strong skipping must stay off. With it on
(the default since Kotlin 2.0.20) the message box ignored typing and the
chat list ignored clicks (device report, 2026-10-20)."""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_strong_skipping_stays_off_for_the_desktop_ui():
    with open(os.path.join(ROOT, "desktop", "build.gradle.kts"), encoding="utf-8") as fh:
        gradle = fh.read()
    assert re.search(r"featureFlags\.add\(\s*ComposeFeatureFlag\.StrongSkipping\.disabled\(\)\s*\)", gradle)

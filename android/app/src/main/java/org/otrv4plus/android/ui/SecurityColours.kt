// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.ui.graphics.Color

/**
 * The verified blue. The project's colour for SMP_VERIFIED, as the Termux
 * client draws it (`UIConstants` in otrv4+.py: blue is SMP_VERIFIED, yellow
 * ENCRYPTED, green FINGERPRINT). A fixed colour rather than the theme's
 * `primary`, which in the default Material scheme is purple and would give
 * the one reassuring state in the app a colour that means nothing.
 * Used ONLY for a state the engine reported as SMP_VERIFIED.
 *
 * From the active palette (`ThemeTokens.*.verified`): a lighter blue on dark
 * purple, the original 0xFF1565C0 on light, each checked for contrast by
 * `ThemeTokensTest`.
 */
val VerifiedBlue: Color
    @Composable @ReadOnlyComposable
    get() = LocalVerifiedColour.current

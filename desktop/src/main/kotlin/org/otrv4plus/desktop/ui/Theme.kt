// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.chat.RowSecurity
import org.otrv4plus.android.crypto.SecurityLevel
import org.otrv4plus.android.theme.ThemeTokens

/**
 * The app's theme from the SHARED tokens (`theme/ThemeTokens.kt`, compiled
 * from the Android tree): the same dark purple, the same light palette, the
 * same contrast checks. The Android AppTheme.kt, minus SharedPreferences.
 */
val LocalVerifiedColour = staticCompositionLocalOf { Color(ThemeTokens.LIGHT.verified) }

val VerifiedBlue: Color
    @Composable @ReadOnlyComposable
    get() = LocalVerifiedColour.current

private fun ThemeTokens.Palette.scheme(dark: Boolean): ColorScheme {
    fun c(v: Long) = Color(v)
    return if (dark) darkColorScheme(
        primary = c(primary), onPrimary = c(onPrimary),
        primaryContainer = c(primaryContainer), onPrimaryContainer = c(onPrimaryContainer),
        secondaryContainer = c(secondaryContainer), onSecondaryContainer = c(onSecondaryContainer),
        background = c(background), onBackground = c(onBackground),
        surface = c(surface), onSurface = c(onSurface),
        surfaceVariant = c(surfaceVariant), onSurfaceVariant = c(onSurfaceVariant),
        surfaceContainer = c(surface), surfaceContainerHigh = c(surfaceVariant),
        error = c(error), onError = c(onError),
        errorContainer = c(errorContainer), onErrorContainer = c(onErrorContainer),
        outline = c(outline),
    ) else lightColorScheme(
        primary = c(primary), onPrimary = c(onPrimary),
        primaryContainer = c(primaryContainer), onPrimaryContainer = c(onPrimaryContainer),
        secondaryContainer = c(secondaryContainer), onSecondaryContainer = c(onSecondaryContainer),
        background = c(background), onBackground = c(onBackground),
        surface = c(surface), onSurface = c(onSurface),
        surfaceVariant = c(surfaceVariant), onSurfaceVariant = c(onSurfaceVariant),
        error = c(error), onError = c(onError),
        errorContainer = c(errorContainer), onErrorContainer = c(onErrorContainer),
        outline = c(outline),
    )
}

@Composable
fun OtrTheme(mode: ThemeTokens.Mode, content: @Composable () -> Unit) {
    val dark = ThemeTokens.isDark(mode, isSystemInDarkTheme())
    val palette = ThemeTokens.palette(dark)
    CompositionLocalProvider(LocalVerifiedColour provides Color(palette.verified)) {
        MaterialTheme(colorScheme = palette.scheme(dark), content = content)
    }
}

/** The icon for a security level. Never the only signal: the label goes with it. */
fun securityIcon(state: SecurityState): ImageVector = when (SecurityLevel.of(state)) {
    SecurityLevel.Level.NOT_ENCRYPTED -> Icons.Filled.LockOpen
    SecurityLevel.Level.ENCRYPTED_UNVERIFIED -> Icons.Filled.Lock
    SecurityLevel.Level.VERIFIED -> Icons.Filled.VerifiedUser
    SecurityLevel.Level.KEY_CHANGED -> Icons.Filled.Warning
}

@Composable
fun toneColour(tone: RowSecurity.Tone): Color = when (tone) {
    RowSecurity.Tone.ALARM -> MaterialTheme.colorScheme.error
    RowSecurity.Tone.GOOD -> VerifiedBlue
    RowSecurity.Tone.NEUTRAL -> MaterialTheme.colorScheme.onSurfaceVariant
}

@Composable
fun securityColour(state: SecurityState): Color = when (SecurityLevel.of(state)) {
    SecurityLevel.Level.NOT_ENCRYPTED, SecurityLevel.Level.KEY_CHANGED -> MaterialTheme.colorScheme.error
    SecurityLevel.Level.ENCRYPTED_UNVERIFIED -> MaterialTheme.colorScheme.primary
    SecurityLevel.Level.VERIFIED -> VerifiedBlue
}

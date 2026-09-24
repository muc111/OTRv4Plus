// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import android.content.Context
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.graphics.Color
import org.otrv4plus.android.theme.ThemeTokens

/** The verified colour for the active palette. See [VerifiedBlue]. */
val LocalVerifiedColour = staticCompositionLocalOf { Color(ThemeTokens.LIGHT.verified) }

private fun ThemeTokens.Palette.scheme(dark: Boolean): ColorScheme {
    fun c(v: Long) = Color(v)
    return if (dark) darkColorScheme(
        primary = c(primary), onPrimary = c(onPrimary),
        primaryContainer = c(primaryContainer), onPrimaryContainer = c(onPrimaryContainer),
        secondaryContainer = c(secondaryContainer), onSecondaryContainer = c(onSecondaryContainer),
        background = c(background), onBackground = c(onBackground),
        surface = c(surface), onSurface = c(onSurface),
        surfaceVariant = c(surfaceVariant), onSurfaceVariant = c(onSurfaceVariant),
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

/** The whole app's theme, from [ThemeTokens]. Dark purple unless chosen otherwise. */
@Composable
fun OtrTheme(mode: ThemeTokens.Mode, content: @Composable () -> Unit) {
    val dark = ThemeTokens.isDark(mode, isSystemInDarkTheme())
    val palette = ThemeTokens.palette(dark)
    CompositionLocalProvider(LocalVerifiedColour provides Color(palette.verified)) {
        MaterialTheme(colorScheme = palette.scheme(dark), content = content)
    }
}

/**
 * The chosen theme, in the app's ordinary preferences. NOT the vault: it is
 * not secret, says nothing about any account or conversation, and must be
 * readable before anything is unlocked. Listed in `WipeAndExit.STORES`.
 */
object ThemeStore {
    const val FILE = "otrv4plus.ui"
    const val KEY = "theme"

    fun load(context: Context): ThemeTokens.Mode = ThemeTokens.Mode.fromStored(
        runCatching {
            context.getSharedPreferences(FILE, Context.MODE_PRIVATE).getString(KEY, null)
        }.getOrNull())

    fun save(context: Context, mode: ThemeTokens.Mode) {
        runCatching {
            context.getSharedPreferences(FILE, Context.MODE_PRIVATE)
                .edit().putString(KEY, mode.stored).apply()
        }
    }
}

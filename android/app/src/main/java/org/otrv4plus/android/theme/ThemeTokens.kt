// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.theme

/**
 * The app's themes, as data: which one is chosen, and every colour token.
 *
 * ONE PLACE FOR COLOUR. The Compose side (`ui/AppTheme.kt`) only turns these
 * into a `ColorScheme`; no screen hard-codes a colour. Plain Kotlin, so
 * `ThemeTokensTest` can check the contrast of every text/background pair in
 * both palettes -- the security lines are text, and text that cannot be read
 * is a security line nobody sees.
 *
 * COLOUR IS NEVER THE ONLY SIGNAL. Every security state is also said in
 * words and a mark (`RowSecurity.Badge.mark`, the security line's sentence);
 * a user who cannot tell blue from purple loses nothing.
 */
object ThemeTokens {

    enum class Mode(val stored: String, val label: String) {
        DARK_PURPLE("dark_purple", "Dark purple"),
        LIGHT("light", "Light"),
        SYSTEM("system", "Follow system");

        companion object {
            /** An unknown or missing stored value falls back to [DEFAULT]. */
            @JvmStatic
            fun fromStored(value: String?): Mode =
                entries.firstOrNull { it.stored == value } ?: DEFAULT
        }
    }

    val DEFAULT = Mode.DARK_PURPLE

    /** Whether [mode] renders dark, given what the system prefers. */
    @JvmStatic
    fun isDark(mode: Mode, systemDark: Boolean): Boolean = when (mode) {
        Mode.DARK_PURPLE -> true
        Mode.LIGHT -> false
        Mode.SYSTEM -> systemDark
    }

    /** ARGB colours. Named by role, never by hue. */
    data class Palette(
        val background: Long,
        val onBackground: Long,
        val surface: Long,
        val onSurface: Long,
        val surfaceVariant: Long,
        val onSurfaceVariant: Long,
        val primary: Long,
        val onPrimary: Long,
        val primaryContainer: Long,
        val onPrimaryContainer: Long,
        val secondaryContainer: Long,
        val onSecondaryContainer: Long,
        val error: Long,
        val onError: Long,
        val errorContainer: Long,
        val onErrorContainer: Long,
        val outline: Long,
        /** SMP_VERIFIED only. Blue, as the Termux client draws it. */
        val verified: Long,
    )

    val DARK = Palette(
        background = 0xFF140F1F,
        onBackground = 0xFFECE6F5,
        surface = 0xFF1B1428,
        onSurface = 0xFFECE6F5,
        surfaceVariant = 0xFF2A2140,
        onSurfaceVariant = 0xFFCFC4E3,
        primary = 0xFFC9B2FF,
        onPrimary = 0xFF2B1260,
        primaryContainer = 0xFF4A2F8A,
        onPrimaryContainer = 0xFFEADDFF,
        secondaryContainer = 0xFF3A2F55,
        onSecondaryContainer = 0xFFE8DEF8,
        error = 0xFFFFB4AB,
        onError = 0xFF690005,
        errorContainer = 0xFF93000A,
        onErrorContainer = 0xFFFFDAD6,
        outline = 0xFF978DAA,
        verified = 0xFF8EC5FF,
    )

    val LIGHT = Palette(
        background = 0xFFFDFBFF,
        onBackground = 0xFF1C1B1F,
        surface = 0xFFFDFBFF,
        onSurface = 0xFF1C1B1F,
        surfaceVariant = 0xFFE9E1F2,
        onSurfaceVariant = 0xFF48454E,
        primary = 0xFF5B3FA8,
        onPrimary = 0xFFFFFFFF,
        primaryContainer = 0xFFEADDFF,
        onPrimaryContainer = 0xFF22005D,
        secondaryContainer = 0xFFE8DEF8,
        onSecondaryContainer = 0xFF1D192B,
        error = 0xFFB3261E,
        onError = 0xFFFFFFFF,
        errorContainer = 0xFFF9DEDC,
        onErrorContainer = 0xFF410E0B,
        outline = 0xFF79747E,
        verified = 0xFF1565C0,
    )

    @JvmStatic
    fun palette(dark: Boolean): Palette = if (dark) DARK else LIGHT

    // -- WCAG 2.x contrast, for the tests and for anyone adding a token -----

    @JvmStatic
    fun luminance(argb: Long): Double {
        fun ch(shift: Int): Double {
            val c = ((argb shr shift) and 0xFF) / 255.0
            return if (c <= 0.03928) c / 12.92 else Math.pow((c + 0.055) / 1.055, 2.4)
        }
        return 0.2126 * ch(16) + 0.7152 * ch(8) + 0.0722 * ch(0)
    }

    @JvmStatic
    fun contrast(a: Long, b: Long): Double {
        val la = luminance(a)
        val lb = luminance(b)
        return (maxOf(la, lb) + 0.05) / (minOf(la, lb) + 0.05)
    }

    /** Text/background pairs the screens actually use. */
    @JvmStatic
    fun textPairs(p: Palette): Map<String, Pair<Long, Long>> = mapOf(
        "onBackground/background" to (p.onBackground to p.background),
        "onSurface/surface" to (p.onSurface to p.surface),
        "onSurfaceVariant/surfaceVariant" to (p.onSurfaceVariant to p.surfaceVariant),
        "onSurfaceVariant/surface" to (p.onSurfaceVariant to p.surface),
        "onPrimary/primary" to (p.onPrimary to p.primary),
        "onPrimaryContainer/primaryContainer" to (p.onPrimaryContainer to p.primaryContainer),
        "onSecondaryContainer/secondaryContainer" to (p.onSecondaryContainer to p.secondaryContainer),
        "onError/error" to (p.onError to p.error),
        "onErrorContainer/errorContainer" to (p.onErrorContainer to p.errorContainer),
        "error/surface" to (p.error to p.surface),
        "error/surfaceVariant" to (p.error to p.surfaceVariant),
        "verified/surface" to (p.verified to p.surface),
        "verified/surfaceVariant" to (p.verified to p.surfaceVariant),
        "primary/surface" to (p.primary to p.surface),
    )
}

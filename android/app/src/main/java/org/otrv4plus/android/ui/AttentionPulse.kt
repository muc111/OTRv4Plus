// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.graphics.Color
import org.otrv4plus.android.chat.Attention

/** The yellow a chat needing the user pulses with (Attention.TINT). */
internal val AttentionYellow = Color(Attention.TINT)

/**
 * The pulsing tint's alpha while [on], else 0. Colour is never the only
 * signal: the row also says what it needs in words.
 */
@Composable
internal fun attentionAlpha(on: Boolean): Float {
    if (!on) return 0f
    val pulse = rememberInfiniteTransition(label = "attention")
    val alpha by pulse.animateFloat(
        initialValue = Attention.TINT_LOW,
        targetValue = Attention.TINT_HIGH,
        animationSpec = infiniteRepeatable(tween(Attention.PULSE_MS), RepeatMode.Reverse),
        label = "attention tint",
    )
    return alpha
}

// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.material3.LocalContentColor
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * A microphone, drawn: capsule, cradle, stem and base. Drawn here rather
 * than taken from an icon library -- the app ships none, and one glyph is
 * not worth a dependency. Takes the surrounding content colour.
 */
@Composable
fun MicIcon(contentDescription: String, size: Dp = 22.dp) {
    val color = LocalContentColor.current
    Canvas(Modifier.size(size).semantics { this.contentDescription = contentDescription }) {
        val w = this.size.width
        val h = this.size.height
        val stroke = w * 0.09f
        // The capsule.
        val capW = w * 0.36f
        val capH = h * 0.52f
        drawRoundRect(color, topLeft = Offset((w - capW) / 2, h * 0.06f),
                      size = Size(capW, capH), cornerRadius = CornerRadius(capW / 2, capW / 2))
        // The cradle: a U around the lower half of the capsule.
        val cradle = w * 0.56f
        drawArc(color, startAngle = 0f, sweepAngle = 180f, useCenter = false,
                topLeft = Offset((w - cradle) / 2, h * 0.30f), size = Size(cradle, h * 0.42f),
                style = Stroke(width = stroke, cap = StrokeCap.Round))
        // The stem and the base.
        drawLine(color, Offset(w / 2, h * 0.72f), Offset(w / 2, h * 0.88f),
                 strokeWidth = stroke, cap = StrokeCap.Round)
        drawLine(color, Offset(w * 0.34f, h * 0.90f), Offset(w * 0.66f, h * 0.90f),
                 strokeWidth = stroke, cap = StrokeCap.Round)
    }
}

// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import kotlin.math.roundToInt

/**
 * The file viewer's zoom: how far, by how much a button press goes, and how
 * far a zoomed picture may be dragged.
 *
 * A picture is never smaller than the view at [MIN] and never dragged so far
 * that its edge comes away from the view's: [clampPan] keeps it covering
 * the view on each axis.
 *
 * Plain Kotlin, driven by `ZoomTest`.
 */
object Zoom {
    const val MIN = 1f
    const val MAX = 5f

    /** One press of + or -. */
    const val STEP = 1.5f

    /** Where a double tap goes from [MIN]; a double tap when zoomed returns to [MIN]. */
    const val DOUBLE_TAP = 2.5f

    fun clamp(scale: Float): Float = scale.coerceIn(MIN, MAX)

    fun zoomIn(scale: Float): Float = clamp(scale * STEP)

    fun zoomOut(scale: Float): Float = clamp(scale / STEP)

    fun doubleTap(scale: Float): Float = if (scale > MIN) MIN else DOUBLE_TAP

    /** The furthest a picture scaled by [scale] may move along an axis [size] long. */
    fun maxPan(scale: Float, size: Float): Float = (size * (scale - 1f) / 2f).coerceAtLeast(0f)

    fun clampPan(pan: Float, scale: Float, size: Float): Float {
        val limit = maxPan(scale, size)
        return pan.coerceIn(-limit, limit)
    }

    fun label(scale: Float): String = "${(scale * 100).roundToInt()}%"
}

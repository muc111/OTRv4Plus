// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import kotlin.test.Test
import kotlin.test.assertEquals

class ZoomTest {

    @Test
    fun `buttons step and stop at the ends`() {
        assertEquals(1.5f, Zoom.zoomIn(1f))
        assertEquals(Zoom.MAX, Zoom.zoomIn(4f))
        assertEquals(Zoom.MIN, Zoom.zoomOut(1.2f))
        assertEquals(Zoom.MIN, Zoom.zoomOut(Zoom.MIN))
    }

    @Test
    fun `a pinch cannot shrink below the view or grow past the limit`() {
        assertEquals(Zoom.MIN, Zoom.clamp(0.3f))
        assertEquals(Zoom.MAX, Zoom.clamp(40f))
    }

    @Test
    fun `double tap zooms in, and out again`() {
        assertEquals(Zoom.DOUBLE_TAP, Zoom.doubleTap(1f))
        assertEquals(Zoom.MIN, Zoom.doubleTap(3f))
    }

    @Test
    fun `an unzoomed picture does not move`() {
        assertEquals(0f, Zoom.clampPan(120f, 1f, 1000f))
    }

    @Test
    fun `a zoomed picture moves only until its edge meets the view's`() {
        // At 2x a 1000-pixel view shows half the picture: 500 either way.
        assertEquals(500f, Zoom.clampPan(900f, 2f, 1000f))
        assertEquals(-500f, Zoom.clampPan(-900f, 2f, 1000f))
        assertEquals(200f, Zoom.clampPan(200f, 2f, 1000f))
    }

    @Test
    fun `the label is a percentage`() {
        assertEquals("100%", Zoom.label(1f))
        assertEquals("250%", Zoom.label(2.5f))
    }
}

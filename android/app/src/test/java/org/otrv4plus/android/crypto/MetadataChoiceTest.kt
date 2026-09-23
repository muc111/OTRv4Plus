// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.MetadataFinding
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * When the user is asked about metadata, and what they are told.
 *
 * The scrub itself is exercised in Python against real photographs
 * (`tests/test_metadata_scrub.py`). This covers the conversation.
 */
class MetadataChoiceTest {

    private fun finding(canScrub: Boolean, carries: Boolean, bytes: Int = 0) =
        MetadataFinding(if (canScrub) "jpeg" else "unknown", carries, bytes,
                        canScrub)

    @Test
    fun `a photo carrying metadata is asked about`() {
        val next = MetadataChoice.next(finding(true, true, 216))
        assertTrue(next is MetadataChoice.Next.Ask)
        assertTrue("216 bytes" in (next as MetadataChoice.Next.Ask).question)
    }

    @Test
    fun `a clean photo is not asked about`() {
        // Asking about nothing teaches people to dismiss the question.
        assertEquals(MetadataChoice.Next.Send,
            MetadataChoice.next(finding(true, false)))
    }

    @Test
    fun `an uncheckable file is never described as clean`() {
        val next = MetadataChoice.next(finding(false, false))
        assertTrue(next is MetadataChoice.Next.SendUnchecked,
            "an uncheckable file was sent silently, which reads as clean")
        assertTrue("cannot check" in
            (next as MetadataChoice.Next.SendUnchecked).notice)
    }

    @Test
    fun `an uncheckable file is not offered a scrub it cannot have`() {
        // Even if something upstream claimed metadata, a format the app does
        // not understand cannot be scrubbed, and offering to would be a lie.
        assertTrue(MetadataChoice.next(finding(false, true, 99))
                       !is MetadataChoice.Next.Ask)
    }

    @Test
    fun `the unknown default promises nothing`() {
        assertTrue(MetadataChoice.next(MetadataFinding.UNKNOWN)
                       is MetadataChoice.Next.SendUnchecked)
    }

    @Test
    fun `the question says what the metadata is`() {
        val question = (MetadataChoice.next(finding(true, true, 10))
                           as MetadataChoice.Next.Ask).question
        assertTrue("where and when" in question)
    }

    @Test
    fun `both answers are spelled out`() {
        assertTrue(MetadataChoice.STRIP.isNotBlank())
        assertTrue(MetadataChoice.KEEP.isNotBlank())
        assertTrue(MetadataChoice.STRIP != MetadataChoice.KEEP)
    }
}

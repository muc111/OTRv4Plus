// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

/**
 * Where MLS messages go, without saying what carries them.
 *
 * THE POINT OF THIS FILE
 * ----------------------
 * MLS is intended to be prototyped over this project's I2P datagram
 * transport. This interface is the line that keeps that a choice rather than
 * an assumption:
 *
 *     MLS protocol engine
 *            ↓
 *     MlsTransport          ← here
 *            ↓
 *     I2P datagrams  │  possibly something else later
 *
 * An MLS engine that called SAM directly, or that reached for an XMPP stanza,
 * would make "MLS over a different transport" a rewrite. With this line it is
 * another implementation of four methods.
 *
 * WHY DATAGRAMS RATHER THAN A STREAM
 * ----------------------------------
 * MLS handshake and application messages are self-contained and each one is
 * independently meaningful — it is a message protocol, not a byte stream. I2P
 * repliable datagrams fit that directly, and framing them onto the existing
 * SAM STREAM the XMPP client uses would mean inventing a length prefix and a
 * reassembler for something that already has message boundaries.
 *
 * It also keeps the two apart operationally: the XMPP stream carries the
 * user's account and is authenticated to a server, and MLS group traffic has
 * no business sharing that session.
 *
 * WHAT AN IMPLEMENTATION MUST NOT DO
 * ----------------------------------
 * Not touch Android. Not touch XMPP. Not log a destination — an I2P
 * destination is on the list of things `otrv4plus_alias` exists to keep out of
 * diagnostics, and a transport is exactly where one would otherwise appear.
 */
interface MlsTransport {

    /** Whether this transport could carry anything right now. */
    val isAvailable: Boolean

    /**
     * Send one MLS message to a group's peers.
     *
     * `group` is an opaque identifier chosen by the engine. This interface
     * deliberately does not know what it means — an MLS group id is not an
     * XMPP room JID and must not be assumed to be one, or the "not coupled to
     * MUC" property is lost on the first implementation.
     */
    suspend fun send(group: String, payload: ByteArray): TransportOutcome

    /**
     * Deliver inbound messages to [sink] until [close].
     *
     * A callback rather than a returned list: datagrams arrive when they
     * arrive, and an engine that had to poll would either add latency or spin.
     */
    fun receive(sink: (group: String, payload: ByteArray) -> Unit)

    /** Stop. Idempotent. */
    fun close()

    /** Whether the operation worked, and if not, whether retrying could help. */
    data class TransportOutcome(
        val ok: Boolean,
        val retryable: Boolean = false,
        /**
         * A short code, never a message from below.
         *
         * A SAM error text can contain a destination. This field is rendered
         * and exported, so it carries a vocabulary of this file's own.
         */
        val code: String = "",
    ) {
        companion object {
            val OK = TransportOutcome(true)
            fun failed(code: String, retryable: Boolean = false) =
                TransportOutcome(false, retryable, code)
        }
    }

    /**
     * The transport for a build where MLS cannot run.
     *
     * A real object rather than a null, so `MlsProvider` can hold a transport
     * unconditionally and there is no nullable path to get wrong later. Every
     * call fails; nothing pretends.
     */
    object Unavailable : MlsTransport {
        override val isAvailable = false

        override suspend fun send(group: String, payload: ByteArray) =
            TransportOutcome.failed("no_transport")

        override fun receive(sink: (String, ByteArray) -> Unit) = Unit

        override fun close() = Unit
    }
}

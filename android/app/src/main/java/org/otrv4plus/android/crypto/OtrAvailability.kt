// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

/**
 * Whether a contact's client speaks OTRv4Plus, and what the screen says.
 *
 * The CAPABILITY question, answered by the transport per XMPP resource
 * (`otrv4plus_caps`: XEP-0030 disco#info / XEP-0115 caps for the OTRv4Plus
 * feature, or an OTRv4+ frame the resource itself sent). It is not a security
 * state: "available" means a client has claimed the protocol -- not that
 * anything is encrypted, trusted or verified. Those stay separate
 * ([SecurityLevel], SMP).
 *
 * Plain Kotlin, driven by `OtrAvailabilityTest`.
 */
object OtrAvailability {

    const val UNKNOWN = "unknown"
    const val OFFLINE = "offline"
    const val CHECKING = "checking"
    const val AVAILABLE = "available"
    const val UNAVAILABLE = "unavailable"

    /** Whether an automatic OTRv4+ start may be attempted. */
    @JvmStatic
    fun mayStart(capability: String): Boolean = capability == AVAILABLE

    /**
     * The security line for a conversation that is NOT encrypted, by
     * capability. Every one says plainly that it is not encrypted; none
     * shows a padlock.
     */
    @JvmStatic
    fun plaintextLine(capability: String): String = when (capability) {
        AVAILABLE ->
            "OTRv4Plus available — establishing secure OTRv4+ session…"
        CHECKING ->
            "Checking whether this contact's client supports OTRv4Plus… " +
                "Not encrypted yet."
        OFFLINE ->
            "Contact offline. OTRv4+ starts automatically when they return. " +
                "Not encrypted."
        UNAVAILABLE ->
            "OTRv4Plus unavailable — this contact is using a client that " +
                "does not support OTRv4Plus. Messages here are NOT encrypted."
        else ->
            "Not encrypted — anything sent here is readable by the server."
    }

    /** Why no Start button, when there is none. Null when one is offered. */
    @JvmStatic
    fun noStartReason(capability: String): String? = when (capability) {
        UNAVAILABLE -> "OTRv4Plus unavailable: this contact's client does not " +
            "support it. There is no fallback to other encryption."
        OFFLINE -> "OTRv4+ will start when this contact comes online."
        CHECKING -> "Checking this contact's client for OTRv4Plus…"
        else -> null
    }
}

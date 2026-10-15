// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import java.util.Locale
import kotlin.math.abs
import kotlin.math.floor
import kotlin.math.max
import kotlin.math.min
import kotlin.math.round

/**
 * Location pins: computed on the device, sent only inside encryption.
 *
 * Owner (2026-10-15): a pin "for pinpointing locations for users to find",
 * without what3words -- whose words come from a commercial service that
 * would see every location looked up -- and without loading a web map,
 * whose tile server would see where people look.
 *
 * A PIN is an ordinary chat message, so it is encrypted exactly as text is
 * (OTR in a chat, MLS in a secure group), and a client that knows nothing of
 * pins still shows something readable:
 *
 *     📍 Location 9C3XGV4C+XV
 *     geo:51.50740,-0.12780;u=12
 *
 * The second line is an RFC 5870 `geo:` URI; the first carries an Open
 * Location Code ("Plus Code") -- an open, offline alternative to three-word
 * addresses: anyone can turn it back into the place with no service.
 *
 * Plain Kotlin, no network, driven by `LocationTest`.
 */
object Location {

    data class Pin(val lat: Double, val lon: Double, val accuracyMeters: Double? = null) {
        val code: String get() = PlusCode.encode(lat, lon)
    }

    const val MARKER = "📍 Location"

    /** The message body for [pin]. */
    fun body(pin: Pin): String {
        val coords = "%.5f,%.5f".format(Locale.ROOT, pin.lat, pin.lon)
        val u = pin.accuracyMeters?.takeIf { it > 0 }?.let { ";u=%d".format(Locale.ROOT, round(it).toLong()) } ?: ""
        return "$MARKER ${pin.code}\ngeo:$coords$u"
    }

    private val GEO = Regex("""(?m)^geo:(-?\d{1,2}(?:\.\d{1,10})?),(-?\d{1,3}(?:\.\d{1,10})?)(?:;u=(\d{1,7}(?:\.\d{1,3})?))?\s*$""")

    /** The pin a message carries (a line holding a `geo:` URI), or null. */
    fun parse(body: String): Pin? {
        if (body.length > 1024) return null
        val m = GEO.find(body) ?: return null
        val lat = m.groupValues[1].toDoubleOrNull() ?: return null
        val lon = m.groupValues[2].toDoubleOrNull() ?: return null
        if (lat !in -90.0..90.0 || lon !in -180.0..180.0) return null
        val u = m.groupValues[3].takeIf { it.isNotEmpty() }?.toDoubleOrNull()
        return Pin(lat, lon, u)
    }

    /**
     * What the user typed: a full Plus Code ("9C3XGV4C+XV"), coordinates
     * ("51.5074, -0.1278"), or a `geo:` URI. Null if it is none of those.
     * A SHORT Plus Code ("GV4C+XV London") needs a reference place to be
     * completed, which would mean a lookup; it is refused, with [typedHint].
     */
    fun fromTyped(text: String): Pin? {
        val t = text.trim()
        if (t.isEmpty() || t.length > 200) return null
        parse(t)?.let { return it }
        PlusCode.decode(t)?.let { return it }
        val parts = t.removePrefix("geo:").split(',', ' ', ';').filter { it.isNotBlank() }
        if (parts.size >= 2) {
            val lat = parts[0].toDoubleOrNull()
            val lon = parts[1].toDoubleOrNull()
            if (lat != null && lon != null && lat in -90.0..90.0 && lon in -180.0..180.0) {
                return Pin(lat, lon)
            }
        }
        return null
    }

    const val typedHint =
        "A full Plus Code (like 9C3XGV4C+XV) or coordinates (51.5074, -0.1278). " +
        "Short codes with a town name need a lookup, which this app does not do."

    /** What to say under the typed field: nothing, or how to write one. */
    fun typedStatus(text: String, pin: Pin?): String? =
        if (text.isBlank() || pin != null) null else typedHint

    /** "51.50740, -0.12780". */
    fun coordinates(pin: Pin): String = "%.5f, %.5f".format(Locale.ROOT, pin.lat, pin.lon)

    fun accuracy(pin: Pin): String? = pin.accuracyMeters?.let { "±%d m".format(Locale.ROOT, round(it).toLong()) }

    /** For a maps app the user explicitly chose to open. */
    fun geoUri(pin: Pin): String =
        "geo:%.6f,%.6f?q=%.6f,%.6f".format(Locale.ROOT, pin.lat, pin.lon, pin.lat, pin.lon)

    /** Said before handing a location to another app. */
    const val OPEN_WARNING =
        "This hands the location to another app. An offline map (OsmAnd, " +
        "Organic Maps) keeps it on this phone; an online one (Google Maps) " +
        "sends it to its servers, outside I2P."

    /** Why sending is refused where it is. */
    const val NEEDS_ENCRYPTION =
        "A location is only sent in an encrypted conversation."

    /**
     * Owner (2026-10-15): "GPS location should be behind verification to
     * avoid accidentally leaking users' GPS". Encrypted is not enough: an
     * encrypted conversation nobody has verified is encrypted to whoever
     * answered. A location goes only where a file may: a contact verified
     * with SMP, or a secure group whose other members are all verified. The
     * sheet does not even open before that, so the GPS is never started.
     * Null when sharing is allowed; otherwise what to say.
     */
    fun shareRefusal(encrypted: Boolean, verified: Boolean, group: Boolean): String? = when {
        !encrypted -> NEEDS_ENCRYPTION
        verified -> null
        group -> "A location goes only to a group whose members are all verified."
        else -> "A location goes only to a contact verified with SMP (Verify, above)."
    }

    /**
     * A location the user SETS rather than reads from the satellites is
     * always allowed: a typed Plus Code or coordinates, or a fix from a
     * mock-location app (Android: Developer options, "Select mock location
     * app"), which Android delivers through the same GPS provider this app
     * reads. Nothing here inspects or rejects a mocked fix, and the receiver
     * is not told how a pin was made.
     */
    const val SET_HINT =
        "To share somewhere else, type a Plus Code or coordinates, or use a " +
        "mock-location app (Developer options): the app accepts its position."
}

/**
 * Open Location Code ("Plus Code"), the open standard
 * (github.com/google/open-location-code, Apache-2.0 specification),
 * implemented here from the specification: 10 digits (about 14 m) plus one
 * grid digit (about 3 m). Offline by construction.
 */
object PlusCode {
    private const val ALPHABET = "23456789CFGHJMPQRVWX"
    private const val SEPARATOR = '+'
    private const val SEPARATOR_POSITION = 8
    private const val PAIR_LENGTH = 10
    private const val GRID_ROWS = 5
    private const val GRID_COLUMNS = 4
    /** Ten pair digits and one grid digit. */
    const val LENGTH = 11

    // Integer resolution of the finest digit we produce (one grid step).
    private const val LAT_MULT = 8000L * GRID_ROWS          // 40 000 per degree
    private const val LNG_MULT = 8000L * GRID_COLUMNS       // 32 000 per degree

    fun encode(latitude: Double, longitude: Double): String {
        var lat = min(max(latitude, -90.0), 90.0)
        var lng = longitude
        while (lng < -180.0) lng += 360.0
        while (lng >= 180.0) lng -= 360.0
        var latVal = floor((lat + 90.0) * LAT_MULT + 1e-9).toLong()
        var lngVal = floor((lng + 180.0) * LNG_MULT + 1e-9).toLong()
        // 90° exactly is outside the last cell: step back one.
        latVal = min(latVal, 180L * LAT_MULT - 1)
        lngVal = min(lngVal, 360L * LNG_MULT - 1)
        val rev = StringBuilder()
        // The grid digit (finest).
        rev.append(ALPHABET[((latVal % GRID_ROWS) * GRID_COLUMNS + (lngVal % GRID_COLUMNS)).toInt()])
        latVal /= GRID_ROWS
        lngVal /= GRID_COLUMNS
        // Five pairs, finest first; reversed below, so lat ends up first.
        repeat(PAIR_LENGTH / 2) {
            rev.append(ALPHABET[(lngVal % 20).toInt()])
            rev.append(ALPHABET[(latVal % 20).toInt()])
            latVal /= 20
            lngVal /= 20
        }
        val digits = rev.reverse().toString()
        return digits.substring(0, SEPARATOR_POSITION) + SEPARATOR + digits.substring(SEPARATOR_POSITION)
    }

    /** A FULL code -> the centre of its area. Null for anything else
     *  (short codes, padded codes, junk). */
    fun decode(code: String): Location.Pin? {
        val c = code.trim().uppercase(Locale.ROOT)
        val sep = c.indexOf(SEPARATOR)
        if (sep != SEPARATOR_POSITION || c.lastIndexOf(SEPARATOR) != sep) return null
        val digits = c.removeRange(sep, sep + 1)
        if (digits.length < PAIR_LENGTH || digits.length > LENGTH + 4) return null
        if (digits.any { it !in ALPHABET }) return null
        // The first digit pair cannot exceed the world (lat < 180°, lng < 360°).
        if (ALPHABET.indexOf(digits[0]) > 8 || ALPHABET.indexOf(digits[1]) > 17) return null
        var lat = -90.0
        var lng = -180.0
        var res = 20.0
        var i = 0
        while (i < PAIR_LENGTH) {
            lat += ALPHABET.indexOf(digits[i]) * res
            lng += ALPHABET.indexOf(digits[i + 1]) * res
            i += 2
            if (i < PAIR_LENGTH) res /= 20.0
        }
        var latRes = res
        var lngRes = res
        while (i < digits.length) {
            val d = ALPHABET.indexOf(digits[i])
            latRes /= GRID_ROWS
            lngRes /= GRID_COLUMNS
            lat += (d / GRID_COLUMNS) * latRes
            lng += (d % GRID_COLUMNS) * lngRes
            i++
        }
        val accuracy = abs(latRes) * 111_320.0 / 2
        return Location.Pin(lat + latRes / 2, lng + lngRes / 2, accuracy)
    }
}

// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

/**
 * What to tell the user about a message that arrived while they were elsewhere.
 *
 * A COUNT AND NOTHING ELSE
 * ------------------------
 * No sender, no display name, no body, no conversation. That is not an
 * oversight or a placeholder for a richer notification later: a notification is
 * rendered on a lock screen, in a car, on a watch, over the user's shoulder,
 * and is read by every accessibility service and notification-listener app on
 * the device. "alice@xmpp-elite.i2p: are you free tonight" on a lock screen
 * undoes what the I2P tunnel underneath it is for.
 *
 * So [Alert] carries an integer. The messages themselves are behind the app,
 * which is behind the lock screen, and -- once app lock lands -- behind that
 * too.
 *
 * WHY THIS IS PLAIN KOTLIN
 * ------------------------
 * Every decision about whether to interrupt somebody is here, with no Android
 * import, so the rules are tested by running them. `OtrConnectionService` does
 * the platform half -- build a Notification, post it, cancel it -- and makes no
 * decisions at all.
 *
 * THREADING
 * ---------
 * Two threads reach this: [note] from the service's drain loop on
 * `Dispatchers.IO`, and [setUiVisible] from the Activity's `onStart`/`onStop`
 * on the main thread. Both mutate [unseen], so both are synchronized -- without
 * it a reset racing an increment is silently lost and the user is told about
 * five messages when one arrived. The critical sections are two field writes
 * and call nothing, so there is nothing here to deadlock on.
 */
class InboundAlerts {

    /** Whether a screen of this app is in front of the user right now. */
    @Volatile
    var uiVisible: Boolean = false
        private set

    /**
     * Messages that have arrived since the user last looked.
     *
     * Not "since the app started" and not "unread": a conversation can be
     * unread for a week without that being worth a notification. This counts
     * arrivals the user has not had the chance to see.
     */
    @Volatile
    var unseen: Int = 0
        private set

    /**
     * The UI came to the front, or went away.
     *
     * Returns true when a posted notification should now be taken down --
     * i.e. the user is looking at the app, so whatever the notification was
     * telling them they can now see for themselves. Returns false when there is
     * nothing to take down, so the caller does not post-and-cancel on every
     * lifecycle event.
     */
    @Synchronized
    fun setUiVisible(visible: Boolean): Boolean {
        uiVisible = visible
        if (!visible) return false
        val had = unseen > 0
        unseen = 0
        return had
    }

    /**
     * A message was stored. Should the user be interrupted?
     *
     * Null while the UI is visible, for both of the cases that covers: the
     * conversation is open and the message is already on screen, or the list is
     * open and the row has just gained an unread badge. Interrupting somebody
     * about something they are currently looking at is noise, and noise is what
     * makes people turn notifications off.
     *
     * Called only for messages that were actually STORED -- a duplicate that
     * the store rejected is not an arrival, and notifying on one would let a
     * peer who resends buzz the phone repeatedly.
     */
    @Synchronized
    fun note(): Alert? {
        if (uiVisible) return null
        unseen += 1
        return Alert(unseen)
    }

    /** The user dismissed the notification, or read everything. */
    @Synchronized
    fun clear() {
        unseen = 0
    }

    /**
     * One posted notification, described without anything sensitive in it.
     *
     * [count] is the only field, and that is the point. There is deliberately
     * no peer, no preview and no conversation id: a type that cannot carry a
     * name cannot leak one, however the notification is later built.
     */
    data class Alert(val count: Int) {
        init {
            require(count > 0) { "an alert with no messages is not an alert" }
        }

        /** Whether this is the first of a run, and so may make a sound. */
        val first: Boolean get() = count == 1
    }
}

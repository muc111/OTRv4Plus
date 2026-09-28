// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.security

import java.util.concurrent.atomic.AtomicBoolean

/**
 * Wipe & Exit: what it destroys, in what order, and what it deliberately keeps.
 *
 * Dependency-free, so `WipeAndExitTest` runs it on CI. The service supplies
 * one platform action per [Step]; the ORDER, the idempotence and the
 * guarantee that every step is attempted live here.
 *
 * THREE OPERATIONS, NOT ONE WITH FLAGS
 * ------------------------------------
 *   Disconnect  ends the connection. Sessions end; the account, its history
 *               and its contacts stay; nothing is described as erased.
 *   Sign out    ends the connection and forgets THIS account: credentials and
 *               its history. The app stays open for the next sign-in.
 *   Wipe & Exit destroys every session secret in Rust, every sensitive record
 *               on disk -- by deleting the key they are sealed under -- every
 *               temporary file, every notification, and ends the process.
 *
 * WHY THE ORDER IS THIS ORDER
 * ---------------------------
 * [Step.STOP_BACKGROUND] first: the drain loop writes arriving messages into
 * the vault and the reconnect loop can start a new connection. Either one
 * running after the vault is destroyed would write something back, or bring
 * a session back. Stopped first, nothing re-creates what later steps destroy.
 * The service also LATCHES the vault here (`LatchedVault`): cancelling the
 * drain loop does not wait for a write already in progress, and a latched
 * vault refuses it.
 *
 * [Step.DESTROY_CRYPTO] second: every secret destroyed in Rust -- OTR
 * sessions, DAKE and SMP state, identity, call key schedules, file keys
 * (`OtrApp.wipe_crypto`). Local and fast, and nothing that can wait on the
 * network comes before it, so the keys are gone whatever happens next.
 *
 * [Step.CLEAR_NOTIFICATIONS], [Step.CLEAR_MEMORY] and [Step.DESTROY_VAULT]
 * next, BEFORE the subsystems stop, and this is the order that makes "wiped"
 * true on a handset. They are local and take milliseconds.
 * [Step.STOP_SUBSYSTEMS] closes calls, the XMPP stream and the I2P tunnel,
 * and each of those is bounded by a network timeout -- tens of seconds over
 * three I2P hops. When the vault came after that, the whole of that time was
 * a window in which the conversation list was still in memory and every
 * record still on disk (WipePersistenceTest).
 *
 * [Step.DESTROY_VAULT] deletes the AndroidKeyStore key and then the files.
 * The key is what makes this erasure rather than deletion: a sealed record
 * whose key no longer exists cannot be opened, whatever the flash still holds.
 *
 * [Step.WIPE_APP_DATA] after every subsystem has stopped, so nothing writes
 * behind it: every entry in app-private storage and the app-specific external
 * directories ([AppDataWipe]) -- not a list of known files. The ~11.28 MB of
 * user data and ~254 KB of cache a handset measured after the old wipe were
 * what that list did not name: the extracted Python runtime, shared_prefs,
 * code_cache and the rest.
 *
 * [Step.EXIT] last, and always attempted, even when an earlier step failed:
 * the process ending is what finally releases anything a step could not.
 */
object WipeAndExit {

    /**
     * The stages, in order:
     *  A. STOP_BACKGROUND  -- no writer runs from here on (vault latched,
     *                         loops cancelled), so nothing recreates state.
     *  B. DESTROY_CRYPTO   -- every secret destroyed IN RUST first: sessions,
     *                         DAKE, SMP, identity, call and file keys. Local
     *                         and fast; nothing waits on the network before it.
     *     CLEAR_NOTIFICATIONS, CLEAR_MEMORY, DESTROY_VAULT -- what is on
     *                         screen, in memory and sealed on disk (the vault
     *                         key is deleted: cryptographic erasure).
     *  C. STOP_SUBSYSTEMS  -- calls, SAM, the XMPP stream and I2P tunnel, the
     *                         loop thread; Python overwrites what it wrote.
     *                         Bounded by network timeouts, hence after B.
     *  D. WIPE_APP_DATA    -- every entry in app-private storage and the
     *                         app-specific external directories (AppDataWipe).
     *     EXIT             -- the process ends; nothing reachable survives.
     */
    enum class Step {
        STOP_BACKGROUND,
        DESTROY_CRYPTO,
        CLEAR_NOTIFICATIONS,
        CLEAR_MEMORY,
        DESTROY_VAULT,
        STOP_SUBSYSTEMS,
        WIPE_APP_DATA,
        EXIT,
    }

    /**
     * Whether a wipe has started in this process. Process-wide on purpose:
     * a screen opened while the engine step is still running must show
     * nothing and close, not render whatever it can still reach.
     */
    private val begun = AtomicBoolean(false)

    val inProgress: Boolean get() = begun.get()

    /** Marks the wipe begun. Returns false if it already was. */
    fun begin(): Boolean = begun.compareAndSet(false, true)

    /** The order the steps run in. */
    val ORDER: List<Step> = Step.entries.toList()

    /** How a piece of stored state is treated. */
    enum class Category {
        /** Deliberately persistent and not sensitive. KEPT. */
        CONFIGURATION,
        /** Sensitive, and on disk. DESTROYED. */
        SENSITIVE_PERSISTENT,
        /** Sensitive, in memory only. DESTROYED. */
        SENSITIVE_EPHEMERAL,
        /** Scratch. DELETED. */
        TEMPORARY,
        /**
         * Not secret, but app data: regenerated (the Python runtime) or back
         * to its default (the theme) on the next launch. DELETED -- a wipe
         * that leaves megabytes behind is not believable, and a list of what
         * may stay is how the next sensitive file slips through.
         */
        APP_DATA,
    }

    /**
     * One place state lives, and what happens to it.
     *
     * [step] is null exactly when the state is KEPT, which only
     * [Category.CONFIGURATION] may be -- enforced by the test.
     */
    data class Store(
        val what: String,
        val where: String,
        val category: Category,
        val step: Step?,
    )

    /**
     * Every place this app keeps state, audited. See ANDROID_WIPE_AND_EXIT.md.
     *
     * A new store must be added here with a policy, or it is a store the wipe
     * does not know about.
     */
    val STORES: List<Store> = listOf(
        Store("Account credentials (JID and password)",
              "vault: account.credentials", Category.SENSITIVE_PERSISTENT,
              Step.DESTROY_VAULT),
        Store("Message history and its index",
              "vault: chat.<account>.*", Category.SENSITIVE_PERSISTENT,
              Step.DESTROY_VAULT),
        Store("Saved contacts", "vault: contacts.<account>",
              Category.SENSITIVE_PERSISTENT, Step.DESTROY_VAULT),
        Store("Deleted-conversation list (addresses only)", "vault: deleted.<account>",
              Category.SENSITIVE_PERSISTENT, Step.DESTROY_VAULT),
        Store("The vault's sealing key",
              "AndroidKeyStore: otrv4plus.vault.v1",
              Category.SENSITIVE_PERSISTENT, Step.DESTROY_VAULT),
        Store("OTR sessions: ratchets, DAKE state, SMP state and secret",
              "Rust, in memory", Category.SENSITIVE_EPHEMERAL, Step.DESTROY_CRYPTO),
        Store("Long-term identity and prekey (in memory; not persisted on Android)",
              "Rust, in memory", Category.SENSITIVE_EPHEMERAL, Step.DESTROY_CRYPTO),
        Store("Call keys, key schedules and key exchanges",
              "Rust / VoiceCallManager", Category.SENSITIVE_EPHEMERAL,
              Step.DESTROY_CRYPTO),
        Store("File-transfer keys and partial files",
              "Rust / FileTransferManager", Category.SENSITIVE_EPHEMERAL,
              Step.DESTROY_CRYPTO),
        Store("In-memory trust pins and SMP auto-respond secrets",
              "Python engine, in memory", Category.SENSITIVE_EPHEMERAL,
              Step.DESTROY_CRYPTO),
        Store("Engine files and received files (overwritten, then unlinked)",
              "Python home: ~/.otrv4plus (files/, files/.incoming/)",
              Category.SENSITIVE_PERSISTENT, Step.STOP_SUBSYSTEMS),
        Store("Audio streams, SAM sessions, XMPP stream, I2P tunnel, loop thread",
              "Python transport", Category.SENSITIVE_EPHEMERAL, Step.STOP_SUBSYSTEMS),
        Store("Presence, last activity, OTR mode per peer",
              "Python facade, in memory", Category.SENSITIVE_EPHEMERAL,
              Step.STOP_SUBSYSTEMS),
        Store("Conversation on screen, drafts, roster, call states, unread",
              "ChatState, in memory", Category.SENSITIVE_EPHEMERAL,
              Step.CLEAR_MEMORY),
        Store("Arrival, incoming-call and connection notifications",
              "NotificationManager", Category.SENSITIVE_EPHEMERAL,
              Step.CLEAR_NOTIFICATIONS),
        Store("Files staged for sending and metadata-scrubbed copies",
              "cache: outbox/", Category.TEMPORARY, Step.WIPE_APP_DATA),
        Store("Exported diagnostic reports",
              "cache: diagnostics/", Category.TEMPORARY, Step.WIPE_APP_DATA),
        Store("A received file copied for \"Open with another app\"",
              "cache: handoff/", Category.TEMPORARY, Step.WIPE_APP_DATA),
        Store("Everything else in app-private storage, the vault directory and "
              + "the Python home included",
              "data dir: files/ cache/ code_cache/ databases/ shared_prefs/ "
              + "no_backup/ app_*/ -- every entry but the system lib link",
              Category.APP_DATA, Step.WIPE_APP_DATA),
        Store("Chaquopy runtime and bundled Python code (re-extracted on launch)",
              "files: chaquopy/", Category.APP_DATA, Step.WIPE_APP_DATA),
        Store("Theme choice (Dark purple / Light / Follow system)",
              "shared_prefs: otrv4plus.ui.xml", Category.APP_DATA, Step.WIPE_APP_DATA),
        Store("App-specific external storage, if any",
              "Android/data/org.otrv4plus.android/", Category.APP_DATA,
              Step.WIPE_APP_DATA),
        Store("Python event trace and error log (in memory)",
              "Python process", Category.SENSITIVE_EPHEMERAL, Step.EXIT),
        Store("Recents-screen snapshot of the app",
              "system task list", Category.SENSITIVE_EPHEMERAL, Step.EXIT),
        Store("Notification channel settings the user chose",
              "system", Category.CONFIGURATION, null),
        Store("Granted runtime permissions (microphone, notifications)",
              "system", Category.CONFIGURATION, null),
        Store("The installed APK and its native-library link",
              "package manager: lib ->", Category.CONFIGURATION, null),
    )

    /** What a run did. */
    data class Report(
        val ran: Boolean,
        val completed: List<Step>,
        val failed: List<Step>,
    ) {
        val ok: Boolean get() = ran && failed.isEmpty()
    }

    /**
     * Runs the steps once, in [ORDER], attempting every one.
     *
     * A step that throws is recorded and the rest still run: a wipe that
     * stopped at its first problem would leave everything after it intact.
     * A second [run] does nothing and says so -- the Wipe button pressed
     * twice, or the service asked twice, must not run the teardown twice
     * over half-destroyed state.
     */
    class Runner(private val actions: Map<Step, () -> Unit>) {
        private val started = AtomicBoolean(false)

        init {
            val missing = ORDER.filterNot { it in actions }
            require(missing.isEmpty()) { "no action for $missing" }
        }

        fun run(): Report {
            if (!started.compareAndSet(false, true)) {
                return Report(ran = false, completed = emptyList(), failed = emptyList())
            }
            val completed = mutableListOf<Step>()
            val failed = mutableListOf<Step>()
            for (step in ORDER) {
                try {
                    actions.getValue(step).invoke()
                    completed += step
                } catch (e: Throwable) {
                    failed += step
                }
            }
            return Report(ran = true, completed = completed, failed = failed)
        }
    }

    /** The confirmation the user must accept. Says what is lost, plainly. */
    const val CONFIRM_TITLE = "Wipe everything and exit?"

    const val CONFIRM_BODY =
        "This ends every conversation and call, destroys all encryption " +
        "keys and verification, and erases your saved account, contacts, " +
        "message history and received files from this device. It cannot be " +
        "undone. The app will close. Next time it starts with a new identity: " +
        "contacts will need to verify you again."

    const val CONFIRM = "Wipe and exit"

    const val CANCEL = "Cancel"
}

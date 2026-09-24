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
 * [Step.CLEAR_NOTIFICATIONS], [Step.CLEAR_MEMORY] and [Step.DESTROY_VAULT]
 * next, BEFORE the engine, and this is the order that makes "wiped" true on
 * a handset. They are local and take milliseconds. [Step.WIPE_ENGINE] ends
 * calls and closes the XMPP stream and I2P tunnel, and each of those is
 * bounded by a network timeout -- tens of seconds over three I2P hops. When
 * the vault came after it, the whole of that time was a window in which the
 * conversation list was still in memory and every record still on disk: a
 * user who reopened the app to check saw every conversation still there, and
 * anything that stopped the process in that window (the system, a force
 * stop, a crash in the teardown) left them there for good. The engine does
 * not read the vault or the chat state, so nothing it does depends on them.
 *
 * [Step.DESTROY_VAULT] deletes the AndroidKeyStore key and then the files.
 * The key is what makes this erasure rather than deletion: a sealed record
 * whose key no longer exists cannot be opened, whatever the flash still holds.
 *
 * [Step.CLEAR_CACHE] before the engine too: staged outgoing files are local.
 * A transfer still reading one keeps its open descriptor until the engine
 * step ends it.
 *
 * [Step.WIPE_ENGINE] then, while the transport still exists: the engine must
 * be wiped on the transport's loop thread (see `OtrApp.wipe`), and calls end
 * over the OTR session that step destroys.
 *
 * [Step.EXIT] last, and always attempted, even when an earlier step failed:
 * the process ending is what finally releases anything a step could not.
 */
object WipeAndExit {

    enum class Step {
        STOP_BACKGROUND,
        CLEAR_NOTIFICATIONS,
        CLEAR_MEMORY,
        DESTROY_VAULT,
        CLEAR_CACHE,
        WIPE_ENGINE,
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
        Store("The vault's sealing key",
              "AndroidKeyStore: otrv4plus.vault.v1",
              Category.SENSITIVE_PERSISTENT, Step.DESTROY_VAULT),
        Store("Engine key-storage file and received files",
              "Python home: ~/.otrv4plus (keys/, files/, files/.incoming/)",
              Category.SENSITIVE_PERSISTENT, Step.WIPE_ENGINE),
        Store("OTR sessions: ratchets, DAKE state, SMP state and secret",
              "Rust, in memory", Category.SENSITIVE_EPHEMERAL, Step.WIPE_ENGINE),
        Store("Long-term identity and prekey (in memory; not persisted on Android)",
              "Rust, in memory", Category.SENSITIVE_EPHEMERAL, Step.WIPE_ENGINE),
        Store("In-memory trust pins and SMP auto-respond secrets",
              "Python engine, in memory", Category.SENSITIVE_EPHEMERAL,
              Step.WIPE_ENGINE),
        Store("Call keys, key exchanges, audio streams, SAM session",
              "Rust / VoiceCallManager", Category.SENSITIVE_EPHEMERAL,
              Step.WIPE_ENGINE),
        Store("File-transfer keys and partial files",
              "Rust / FileTransferManager", Category.SENSITIVE_EPHEMERAL,
              Step.WIPE_ENGINE),
        Store("XMPP stream, I2P tunnel, transport loop thread",
              "Python transport", Category.SENSITIVE_EPHEMERAL, Step.WIPE_ENGINE),
        Store("Presence, last activity, OTR mode per peer",
              "Python facade, in memory", Category.SENSITIVE_EPHEMERAL,
              Step.WIPE_ENGINE),
        Store("Conversation on screen, drafts, roster, call states, unread",
              "ChatState, in memory", Category.SENSITIVE_EPHEMERAL,
              Step.CLEAR_MEMORY),
        Store("Arrival, incoming-call and connection notifications",
              "NotificationManager", Category.SENSITIVE_EPHEMERAL,
              Step.CLEAR_NOTIFICATIONS),
        Store("Files staged for sending and metadata-scrubbed copies",
              "cache: outbox/", Category.TEMPORARY, Step.CLEAR_CACHE),
        Store("Exported diagnostic reports",
              "cache: diagnostics/", Category.TEMPORARY, Step.CLEAR_CACHE),
        Store("Python event trace and error log (in memory)",
              "Python process", Category.SENSITIVE_EPHEMERAL, Step.EXIT),
        Store("Recents-screen snapshot of the app",
              "system task list", Category.SENSITIVE_EPHEMERAL, Step.EXIT),
        Store("Chaquopy runtime and bundled Python code",
              "files: chaquopy/", Category.CONFIGURATION, null),
        Store("Notification channel settings the user chose",
              "system", Category.CONFIGURATION, null),
        Store("Granted runtime permissions (microphone, notifications)",
              "system", Category.CONFIGURATION, null),
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

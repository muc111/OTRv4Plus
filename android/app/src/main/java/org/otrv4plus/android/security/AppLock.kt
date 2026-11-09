// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.security

import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import com.chaquo.python.PyObject
import com.chaquo.python.Python
import java.io.File
import java.io.FileOutputStream

/**
 * The app lock (docs/APP_LOCK_PASSPHRASE.md): set up, unlock, change, turn
 * off, lock, and lock by itself after a time in the background.
 *
 * The 256-bit data key is made and held by Rust (Rust/src/app_lock.rs,
 * through android_bridge/app_lock.py); this object handles the record file,
 * the key store's HMAC (AppLockKeystore), the guess throttle and the clock.
 * The passphrase reaches Rust as bytes encoded straight from the typed
 * CharArray -- never a String -- and every buffer on the way is zeroed.
 *
 * LOCKED MEANS SIGNED OUT, then the process ends: the connection is closed,
 * Rust zeroizes the data key, and no JVM or Python heap that held messages
 * or keys survives. Nothing sent while locked is lost (1:1 senders queue;
 * group messages replay from the room), but there are no notifications.
 */
object AppLock {

    enum class Mode { NONE, PASSPHRASE, DEVICE }

    /** How an unlock attempt went. [Wrong] carries no reason, on purpose. */
    sealed interface Outcome {
        data object Ok : Outcome
        data object Wrong : Outcome
        data class Wait(val millis: Long) : Outcome
        data class Failed(val why: String) : Outcome
    }

    private const val DIR = "applock"
    private const val RECORD = "record.bin"
    private const val PREFS = "applock"
    private const val KEY_TIMEOUT = "auto_lock"
    private const val KEY_FAILURES = "failures"
    private const val KEY_LAST_FAILURE = "last_failure"

    /** Set by the connection service: a call in progress postpones the
     *  automatic lock (ending a call is not what a timer should do). */
    @Volatile
    var callActive: () -> Boolean = { false }

    /** Lock requests are carried out by the service when it runs, so the
     *  connection is closed cleanly first. Set by the service. */
    @Volatile
    var serviceLock: ((restartUi: Boolean) -> Unit)? = null

    @Volatile
    private var cachedMode: Mode? = null

    private val module: PyObject by lazy {
        Python.getInstance().getModule("android_bridge.app_lock")
    }

    /** The Rust layer for [LockLayerVault]; null until Python is up. */
    val crypto: AppLockCrypto? get() = if (Python.isStarted()) PythonCrypto else null

    private object PythonCrypto : AppLockCrypto {
        override val unlocked: Boolean
            get() = runCatching { module.callAttr("unlocked").toBoolean() }.getOrDefault(false)

        override fun seal(name: String, plaintext: ByteArray): ByteArray =
            module.callAttr("seal", name, plaintext).toJava(ByteArray::class.java)

        override fun open(name: String, record: ByteArray): ByteArray? =
            module.callAttr("open_sealed", name, record)?.toJava(ByteArray::class.java)
    }

    // ── state ────────────────────────────────────────────────────────────────

    fun mode(context: Context): Mode = cachedMode ?: readMode(context).also { cachedMode = it }

    fun enrolled(context: Context): Boolean = mode(context) != Mode.NONE

    fun unlocked(): Boolean = crypto?.unlocked == true

    /** The app may not show anything until [unlock] succeeds. */
    fun mustUnlock(context: Context): Boolean = enrolled(context) && !unlocked()

    fun securityLevel(): SecurityLevel = AppLockKeystore.securityLevel()

    fun autoLock(context: Context): AutoLock =
        AutoLock.of(prefs(context).getString(KEY_TIMEOUT, null))

    fun setAutoLock(context: Context, choice: AutoLock) {
        prefs(context).edit().putString(KEY_TIMEOUT, choice.name).apply()
    }

    /**
     * At process start, after Python: a device-mode record (the lock turned
     * off after use) opens by itself, as the app did before the lock. A
     * passphrase record waits for the unlock screen.
     */
    fun startUp(context: Context) {
        if (mode(context) != Mode.DEVICE || unlocked()) return
        runCatching {
            val record = readRecord(context) ?: return
            val hw = AppLockKeystore.hmac(AppLockKeystore.DEVICE, salt(record))
            try {
                module.callAttr("unlock", null, hw, record)
            } finally {
                hw.fill(0)
            }
        }
    }

    // ── unlock ───────────────────────────────────────────────────────────────

    /** Try [chars]; they are zeroed whatever happens. Blocking (Argon2id):
     *  call off the main thread. */
    fun unlock(context: Context, chars: CharArray): Outcome {
        try {
            val throttle = throttle(context)
            val decision = throttle.check()
            if (decision is AttemptThrottle.Decision.Blocked) return Outcome.Wait(decision.retryAfterMillis)
            val record = readRecord(context) ?: return Outcome.Failed("The app lock is not set up.")
            val ok = withSecrets(chars, AppLockKeystore.PASSPHRASE, salt(record)) { pass, hw ->
                module.callAttr("unlock", pass, hw, record).toBoolean()
            }
            return if (ok) {
                throttle.recordSuccess()
                Outcome.Ok
            } else {
                throttle.recordFailure()
                Outcome.Wrong
            }
        } catch (e: Exception) {
            return Outcome.Failed(keystoreProblem(e))
        } finally {
            chars.fill('\u0000')
        }
    }

    // ── settings ─────────────────────────────────────────────────────────────

    /**
     * Turn the lock on with [new]. The first time, this makes the data key
     * and seals every stored record under it; after the lock was turned off
     * it only re-wraps the key. Returns null on success, else why not.
     * Zeroes [new]. Blocking.
     */
    fun enable(context: Context, new: CharArray): String? {
        try {
            return when (mode(context)) {
                Mode.PASSPHRASE -> "The app lock is already on."
                Mode.DEVICE -> {
                    if (!unlocked()) return "The app is locked."
                    val salt = newSalt()
                    val record = withSecrets(new, AppLockKeystore.PASSPHRASE, salt) { pass, hw ->
                        rewrap(pass, hw, salt)
                    }
                    writeRecord(context, record, Mode.PASSPHRASE)
                    null
                }
                Mode.NONE -> {
                    val salt = newSalt()
                    val record = withSecrets(new, AppLockKeystore.PASSPHRASE, salt) { pass, hw ->
                        module.callAttr("enrol", pass, hw, salt).toJava(ByteArray::class.java)
                    }
                    // The record first, durably; only then does Rust start
                    // using the key (a crash in between loses nothing).
                    writeRecord(context, record, Mode.PASSPHRASE)
                    module.callAttr("commit")
                    KeystoreVault.sealAllSections(context)
                    null
                }
            }
        } catch (e: Exception) {
            return keystoreProblem(e)
        } finally {
            new.fill('\u0000')
        }
    }

    /** Change the passphrase: [current] must open the record. Nothing is
     *  re-encrypted. Null on success. Zeroes both. Blocking. */
    fun change(context: Context, current: CharArray, new: CharArray): String? {
        try {
            if (mode(context) != Mode.PASSPHRASE) return "The app lock is off."
            if (!checks(context, current)) return "The current passphrase is not right."
            val salt = newSalt()
            val record = withSecrets(new, AppLockKeystore.PASSPHRASE, salt) { pass, hw ->
                rewrap(pass, hw, salt)
            }
            writeRecord(context, record, Mode.PASSPHRASE)
            return null
        } catch (e: Exception) {
            return keystoreProblem(e)
        } finally {
            current.fill('\u0000')
            new.fill('\u0000')
        }
    }

    /**
     * Turn the lock off: [current] must open the record. The data key stays
     * and is re-wrapped under the phone's key store alone -- the protection
     * the app had before the lock. Null on success. Zeroes [current].
     */
    fun disable(context: Context, current: CharArray): String? {
        try {
            if (mode(context) != Mode.PASSPHRASE) return "The app lock is off."
            if (!checks(context, current)) return "The passphrase is not right."
            val salt = newSalt()
            val hw = AppLockKeystore.hmac(AppLockKeystore.DEVICE, salt)
            val record = try {
                module.callAttr("rewrap", null, hw, salt).toJava(ByteArray::class.java)
            } finally {
                hw.fill(0)
            }
            writeRecord(context, record, Mode.DEVICE)
            return null
        } catch (e: Exception) {
            return keystoreProblem(e)
        } finally {
            current.fill('\u0000')
        }
    }

    // ── locking ──────────────────────────────────────────────────────────────

    private val timer = Handler(Looper.getMainLooper())
    private var backgroundedAt = -1L
    private val timedLock = Runnable { lockIfDue(restartUi = false) }
    @Volatile
    private var appContext: Context? = null

    /** Lock now (Settings → Lock now, or the timer). Does nothing when the
     *  lock is not on. With [restartUi] the unlock screen comes back. */
    fun lockNow(context: Context, restartUi: Boolean) {
        if (mode(context) != Mode.PASSPHRASE) return
        val viaService = serviceLock
        if (viaService != null) viaService(restartUi) else finishLock(context, restartUi)
    }

    /** The last step of a lock, after the connection is closed: Rust
     *  zeroizes the data key, then the process ends. */
    fun finishLock(context: Context, restartUi: Boolean) {
        runCatching { module.callAttr("lock") }
        if (restartUi) {
            runCatching {
                context.packageManager.getLaunchIntentForPackage(context.packageName)?.let {
                    it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
                    context.startActivity(it)
                }
            }
        }
        android.os.Process.killProcess(android.os.Process.myPid())
        kotlin.system.exitProcess(0)
    }

    /** MainActivity.onStop: start the background countdown. */
    fun onBackgrounded(context: Context) {
        appContext = context.applicationContext
        if (mode(context) != Mode.PASSPHRASE || !unlocked()) return
        val choice = autoLock(context)
        if (choice == AutoLock.NEVER) return
        backgroundedAt = SystemClock.elapsedRealtime()
        timer.removeCallbacks(timedLock)
        timer.postDelayed(timedLock, choice.millis)
    }

    /**
     * MainActivity.onStart: whether the app was away long enough to lock.
     * The timer may not have fired (Doze delays it); the clock here counts
     * sleep, so this check on return is what the lock relies on. The caller
     * covers the screen and then calls [lockNow].
     */
    fun lockDueOnReturn(context: Context): Boolean {
        appContext = context.applicationContext
        timer.removeCallbacks(timedLock)
        val since = backgroundedAt
        backgroundedAt = -1L
        if (since < 0 || mode(context) != Mode.PASSPHRASE || !unlocked()) return false
        if (callActive()) return false
        return AutoLock.due(autoLock(context), SystemClock.elapsedRealtime() - since)
    }

    private fun lockIfDue(restartUi: Boolean) {
        val context = appContext ?: return
        if (backgroundedAt < 0) return
        if (callActive()) {
            // Not during a call: look again shortly after.
            timer.postDelayed(timedLock, 30_000L)
            return
        }
        lockNow(context, restartUi)
    }

    /** Wipe & Exit: the record and both key store keys. The key store
     *  first: without it, the record is a 256-bit unknown. */
    fun destroy(context: Context): Boolean {
        runCatching { if (Python.isStarted()) module.callAttr("lock") }
        val keys = AppLockKeystore.destroy()
        runCatching { File(context.filesDir, DIR).deleteRecursively() }
        runCatching { prefs(context).edit().clear().commit() }
        cachedMode = Mode.NONE
        return keys
    }

    // ── internals ────────────────────────────────────────────────────────────

    private fun checks(context: Context, chars: CharArray): Boolean {
        val record = readRecord(context) ?: return false
        val copy = chars.copyOf()
        return withSecrets(copy, AppLockKeystore.PASSPHRASE, salt(record)) { pass, hw ->
            module.callAttr("check", pass, hw, record).toBoolean()
        }
    }

    /** UTF-8 of [chars] and the key store HMAC of [salt], zeroed after
     *  [use] (which hands them to Rust; Rust zeroes its own copies). */
    private fun <T> withSecrets(chars: CharArray, alias: String, salt: ByteArray,
                                use: (ByteArray, ByteArray) -> T): T {
        val pass = Passphrase.utf8(chars)
        chars.fill('\u0000')
        var hw: ByteArray? = null
        try {
            hw = AppLockKeystore.hmac(alias, salt)
            return use(pass, hw)
        } finally {
            pass.fill(0)
            hw?.fill(0)
        }
    }

    private fun rewrap(pass: ByteArray, hw: ByteArray, salt: ByteArray): ByteArray =
        module.callAttr("rewrap", pass, hw, salt).toJava(ByteArray::class.java)

    private fun newSalt(): ByteArray = module.callAttr("new_salt").toJava(ByteArray::class.java)

    private fun salt(record: ByteArray): ByteArray =
        module.callAttr("record_info", record).callAttr("get", "salt").toJava(ByteArray::class.java)

    private fun recordFile(context: Context) = File(File(context.filesDir, DIR), RECORD)

    private fun readRecord(context: Context): ByteArray? =
        recordFile(context).takeIf { it.isFile }?.readBytes()

    /** The mode byte (offset 8, after the 8-byte magic) of the record. */
    private fun readMode(context: Context): Mode {
        val record = readRecord(context) ?: return Mode.NONE
        if (record.size < 9) return Mode.NONE
        return when (record[8].toInt()) {
            1 -> Mode.PASSPHRASE
            2 -> Mode.DEVICE
            else -> Mode.NONE
        }
    }

    /** Durably: a temporary file, synced, then renamed over the old one. */
    private fun writeRecord(context: Context, record: ByteArray, mode: Mode) {
        val file = recordFile(context)
        file.parentFile?.mkdirs()
        val scratch = File(file.parentFile, "$RECORD.tmp")
        FileOutputStream(scratch).use { out ->
            out.write(record)
            out.fd.sync()
        }
        check(scratch.renameTo(file)) { "the app-lock record could not be stored" }
        cachedMode = mode
    }

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Failed guesses survive a restart; the wall clock, so a reboot does
     *  not reset the wait (AttemptThrottle treats a clock moved back as
     *  no time passed). */
    private fun throttle(context: Context) = AttemptThrottle(
        store = object : ThrottleStore {
            override fun failureCount() = prefs(context).getInt(KEY_FAILURES, 0)
            override fun setFailureCount(value: Int) {
                prefs(context).edit().putInt(KEY_FAILURES, value).commit()
            }
            override fun lastFailureAtMillis() = prefs(context).getLong(KEY_LAST_FAILURE, 0L)
            override fun setLastFailureAt(millis: Long) {
                prefs(context).edit().putLong(KEY_LAST_FAILURE, millis).commit()
            }
        },
        clock = { System.currentTimeMillis() },
    )

    private fun keystoreProblem(e: Exception): String =
        "The phone's key store refused (${e.javaClass.simpleName}). Unlock the phone and try again."
}

// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

import android.content.Context
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.util.zip.ZipInputStream

/**
 * The I2P router the APK carries: i2pd, with only its SAM bridge listening.
 *
 * Built from pinned source by `.github/scripts/build-i2pd-android.sh` and
 * packaged as `lib/<abi>/libi2pd.so`, because Android only lets an app run a
 * file from its native library directory. It runs as a child process of the
 * app, owned by [OtrConnectionService]: started when an I2P sign-in needs it,
 * stopped when the connection is stopped, on sign-out and on Wipe & Exit.
 *
 * Its data (router identity, network database, peer profiles, address book)
 * lives in `no_backup/i2pd`, private to the app and never in a backup. Kept
 * between runs so the next start does not have to join the network from
 * nothing; removed by Wipe & Exit with everything else.
 *
 * What it is configured to do is in [RouterChoice.config].
 */
class BundledRouter(private val context: Context) {

    private val binary: File
        get() = File(context.applicationInfo.nativeLibraryDir, BINARY)

    private val dir: File get() = File(context.noBackupFilesDir, DIR)

    @Volatile
    private var process: Process? = null

    /** When the current router process started, or 0. */
    @Volatile
    var startedAt: Long = 0L
        private set

    /** Whether this router had never joined the network on this phone. */
    @Volatile
    var fresh: Boolean = false
        private set

    /** Whether this APK carries a router at all (a local build may not). */
    val available: Boolean get() = binary.isFile

    /** Whether our router is up, judged by its SAM bridge answering. */
    fun running(): Boolean = samAnswers(RouterChoice.BUILT_IN_SAM_PORT)

    /**
     * Start the router unless it is already up, and wait for its SAM bridge.
     *
     * Returns true once SAM accepts connections -- which i2pd does within
     * seconds; the slow part, joining the network and building tunnels,
     * happens behind SAM's SESSION CREATE, which the connection waits on.
     * Blocking: call from an IO thread.
     */
    @Synchronized
    fun start(): Boolean {
        if (running()) {
            if (startedAt == 0L) startedAt = System.currentTimeMillis()
            return true
        }
        if (!available) return false
        stopProcess()
        dir.mkdirs()
        fresh = !File(dir, "router.info").isFile
        File(dir, CONF).writeText(RouterChoice.config())
        // An empty tunnels file, so i2pd does not go looking for one.
        File(dir, TUNNELS).writeText("")
        installCertificates()
        val proc = ProcessBuilder(
            binary.absolutePath,
            "--datadir=${dir.absolutePath}",
            "--conf=${File(dir, CONF).absolutePath}",
            "--tunconf=${File(dir, TUNNELS).absolutePath}",
            "--certsdir=${File(dir, CERTS).absolutePath}",
            "--pidfile=${File(dir, PID).absolutePath}",
            "--logfile=${File(dir, LOG).absolutePath}",
        ).directory(dir)
            .redirectErrorStream(true)
            .redirectOutput(File("/dev/null"))
            .start()
        process = proc
        startedAt = System.currentTimeMillis()
        val deadline = startedAt + SAM_WAIT_MS
        while (System.currentTimeMillis() < deadline) {
            if (!proc.isAlive) {
                startedAt = 0L
                process = null
                return false
            }
            if (running()) return true
            Thread.sleep(250)
        }
        return running()
    }

    /** Stop the router, including one left behind by an earlier process. */
    @Synchronized
    fun stop() {
        stopProcess()
        // A router started by a previous run of the app (the process was
        // killed, the child was not) is found by its pid file. Same UID, so
        // only ever our own -- and only if that pid is still i2pd: a stale
        // file's number may since belong to this very app.
        runCatching {
            val pid = File(dir, PID).readText().trim().toInt()
            val cmd = File("/proc/$pid/cmdline").readText()
            if (pid > 0 && pid != android.os.Process.myPid() && BINARY in cmd) {
                android.os.Process.killProcess(pid)
            }
        }
        runCatching { File(dir, PID).delete() }
        startedAt = 0L
    }

    private fun stopProcess() {
        val proc = process ?: return
        process = null
        runCatching {
            proc.destroy()
            if (!waitFor(proc, STOP_WAIT_MS)) proc.destroyForcibly()
        }
    }

    private fun waitFor(proc: Process, ms: Long): Boolean {
        val end = System.currentTimeMillis() + ms
        while (System.currentTimeMillis() < end) {
            if (!proc.isAlive) return true
            Thread.sleep(100)
        }
        return !proc.isAlive
    }

    /**
     * Unpack the reseed and family certificates from the APK, once per build.
     *
     * i2pd checks what it downloads when it first joins the network against
     * these (`reseed.verify = true`). Entries are written only below the
     * certificates directory: a name that would land anywhere else is refused.
     */
    private fun installCertificates() {
        val marker = File(dir, "certificates.build")
        val build = org.otrv4plus.android.BuildConfig.BUILD_ID
        val target = File(dir, CERTS)
        if (marker.isFile && marker.readText() == build && target.isDirectory) return
        target.deleteRecursively()
        val root = dir.canonicalFile
        context.assets.open(CERT_ASSET).use { raw ->
            ZipInputStream(raw).use { zip ->
                while (true) {
                    val entry = zip.nextEntry ?: break
                    val out = File(dir, entry.name).canonicalFile
                    require(out.path.startsWith(File(root, CERTS).path + File.separator)) {
                        "certificate archive entry outside its directory"
                    }
                    if (entry.isDirectory) {
                        out.mkdirs()
                    } else {
                        out.parentFile?.mkdirs()
                        out.outputStream().use { zip.copyTo(it) }
                    }
                }
            }
        }
        marker.writeText(build)
    }

    companion object {
        const val BINARY = "libi2pd.so"
        private const val DIR = "i2pd"
        private const val CONF = "i2pd.conf"
        private const val TUNNELS = "tunnels.conf"
        private const val CERTS = "certificates"
        private const val PID = "i2pd.pid"
        private const val LOG = "i2pd.log"
        private const val CERT_ASSET = "i2pd-certificates.zip"

        /** How long i2pd may take to open its SAM port. */
        private const val SAM_WAIT_MS = 30_000L
        private const val STOP_WAIT_MS = 5_000L

        /** Whether a SAM bridge answers on loopback at [port]. Milliseconds. */
        fun samAnswers(port: Int): Boolean = runCatching {
            Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 500); true }
        }.getOrDefault(false)
    }
}

/**
 * The user's router choice ([RouterChoice.Mode]), in the app's ordinary
 * preferences beside the theme: not secret, about no account, and needed
 * before anything is unlocked. Listed in `WipeAndExit.STORES`.
 */
object RouterStore {
    private const val FILE = "otrv4plus.ui"
    private const val KEY = "i2p_router"

    fun load(context: Context): RouterChoice.Mode = RouterChoice.Mode.fromStored(
        runCatching {
            context.getSharedPreferences(FILE, Context.MODE_PRIVATE).getString(KEY, null)
        }.getOrNull())

    fun save(context: Context, mode: RouterChoice.Mode) {
        runCatching {
            context.getSharedPreferences(FILE, Context.MODE_PRIVATE)
                .edit().putString(KEY, mode.stored).apply()
        }
    }
}

package org.otrv4plus.android.bridge

import android.content.Context
import android.os.Build
import com.chaquo.python.PyObject
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform

/**
 * [OtrCore] backed by CPython via Chaquopy.
 *
 * Every call crosses into `android_bridge.app.OtrApp`. This class does no
 * protocol work of its own -- the DAKE, SMP, ratchet and session sequencing all
 * stay in the Python orchestration layer, which is where they were audited.
 * Reimplementing any of that in Kotlin would put security-critical sequencing
 * into a second language with no test coverage.
 *
 * Threading: none of these methods may run on the main thread. SMP performs
 * multi-minute computations and the DAKE takes roughly 20 seconds; the engine
 * expects to be driven from the service thread that owns it.
 */
class ChaquopyOtrCore(private val appContext: Context) : OtrCore {

    private var app: PyObject? = null
    private var sink: OtrEventSink? = null

    private val python: Python
        get() {
            if (!Python.isStarted()) {
                Python.start(AndroidPlatform(appContext))
            }
            return Python.getInstance()
        }

    override fun initialize(): InitResult {
        return try {
            val py = python
            val bootstrap = py.getModule("android_bridge.bootstrap")
            // Fails fast and loudly on Python < 3.12 or a missing otrv4_core,
            // rather than surfacing as a SyntaxError deep inside an import.
            bootstrap.callAttr("ensure_runtime")
            bootstrap.callAttr("load_orchestration")

            val diagnostics = py.getModule("android_bridge.diagnostics")
            val report = diagnostics.callAttr("collect", true, androidBuildInfo(py))

            val otr = py.getModule("otrv4_")
            val config = otr.callAttr("OTRConfig")
            val engine = otr.callAttr("EnhancedSessionManager", config)

            val appModule = py.getModule("android_bridge.app")
            app = appModule.callAttr("OtrApp", engine)

            InitResult(
                ok = report.callAttr("get", "ok").toBoolean(),
                pythonVersion = section(report, "python", "version"),
                abi = section(report, "abi", "android_abi"),
                rustCoreLoaded = section(report, "rust_core", "loaded").toBoolean(),
                engineInitialized = section(report, "otrv4plus", "initialized").toBoolean(),
            )
        } catch (t: Throwable) {
            // Deliberately no `t.message`: Python exception text can embed data
            // the engine was handling.
            InitResult(
                ok = false,
                pythonVersion = "",
                abi = Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown",
                rustCoreLoaded = false,
                engineInitialized = false,
                failureCode = t.javaClass.simpleName,
            )
        }
    }

    /** Values only Kotlin can read; Python is told them rather than guessing. */
    private fun androidBuildInfo(py: Python): PyObject {
        val builtins = py.getBuiltins()
        val dict = builtins.callAttr("dict")
        dict.callAttr("__setitem__", "sdk_int", Build.VERSION.SDK_INT)
        dict.callAttr("__setitem__", "release", Build.VERSION.RELEASE ?: "")
        dict.callAttr("__setitem__", "supported_abis", Build.SUPPORTED_ABIS.joinToString(","))
        // Model is useful for a bug report and is not sensitive, but it is
        // device-identifying, so it must not be written into repository logs.
        dict.callAttr("__setitem__", "model", Build.MODEL ?: "")
        return dict
    }

    private fun section(report: PyObject, group: String, key: String): String =
        report.callAttr("get", group)?.callAttr("get", key)?.toString() ?: ""

    private fun requireApp(): PyObject =
        app ?: throw OtrBridgeException("not_initialized")

    override fun shutdown() {
        try {
            app?.callAttr("shutdown")
        } catch (_: Throwable) {
            // Teardown must not throw during process shutdown.
        } finally {
            app = null
        }
    }

    override fun localFingerprint(): String =
        requireApp().callAttr("local_fingerprint").toString()

    override fun securityState(peer: String): SecurityState =
        SecurityState.fromLevel(requireApp().callAttr("security_state", peer).toInt())

    override fun smpState(peer: String): SmpState =
        SmpState.fromName(
            requireApp().callAttr("smp_state", peer).get("name")?.toString() ?: "IDLE"
        )

    override fun smpProgress(peer: String): SmpProgress {
        val p = requireApp().callAttr("smp_progress", peer)
        return SmpProgress(
            step = p.get("step")?.toInt() ?: 0,
            total = p.get("total")?.toInt() ?: 4,
            state = SmpState.fromName(p.get("state")?.get("name")?.toString() ?: "IDLE"),
        )
    }

    override fun securityDetails(peer: String): SecurityDetails {
        val d = requireApp().callAttr("security_details", peer)
        return SecurityDetails(
            peer = peer,
            security = SecurityState.fromLevel(d.get("security")?.toInt() ?: 0),
            smp = SmpState.fromName(d.get("smp")?.get("name")?.toString() ?: "IDLE"),
            smpPhase = d.get("smp_phase")?.toString() ?: "",
            localFingerprint = d.get("local_fingerprint")?.toString() ?: "",
            peerFingerprint = d.get("peer_fingerprint")?.toString(),
            trusted = d.get("trusted")?.toBoolean() ?: false,
        )
    }

    override fun contacts(): List<Contact> =
        requireApp().callAttr("contacts").asList().map { c ->
            Contact(
                jid = c.get("jid")?.toString() ?: "",
                displayName = c.get("display_name")?.toString() ?: "",
                online = c.get("online")?.toBoolean() ?: false,
                security = SecurityState.fromLevel(c.get("security")?.toInt() ?: 0),
                smp = SmpState.fromName(c.get("smp")?.get("name")?.toString() ?: "IDLE"),
                callAvailable = c.get("call_available")?.toBoolean() ?: false,
            )
        }

    override fun startSession(peer: String) {
        wrap { requireApp().callAttr("start_session", peer) }
    }

    override fun sendMessage(peer: String, body: String) {
        wrap { requireApp().callAttr("send_message", peer, body) }
    }

    override fun smpStart(peer: String, secret: String, question: String) {
        wrap { requireApp().callAttr("smp_start", peer, secret, question) }
    }

    override fun smpRespond(peer: String, secret: String) {
        wrap { requireApp().callAttr("smp_respond", peer, secret) }
    }

    override fun smpAbort(peer: String) {
        wrap { requireApp().callAttr("smp_abort", peer) }
    }

    override fun setEventSink(sink: OtrEventSink?) {
        this.sink = sink
        // Wiring the Python event sink through to Kotlin needs a Chaquopy
        // static proxy, which is Phase 3 work alongside the first real screens.
        // Until then the UI polls the typed getters above; no code path scrapes
        // terminal output either way.
    }

    /**
     * Convert any Python-side failure into a bare code.
     *
     * The message is dropped on purpose: `BridgeError` carries a code, but a
     * lower-level Python exception can embed the plaintext or peer data it was
     * handling, and that must not reach a Kotlin log or a crash report.
     */
    private inline fun <T> wrap(block: () -> T): T =
        try {
            block()
        } catch (t: Throwable) {
            throw OtrBridgeException(codeFrom(t))
        }

    private fun codeFrom(t: Throwable): String {
        val name = t.javaClass.simpleName
        return if (name.isBlank()) "bridge_error" else name
    }
}

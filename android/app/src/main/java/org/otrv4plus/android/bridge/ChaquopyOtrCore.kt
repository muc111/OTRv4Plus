package org.otrv4plus.android.bridge

import android.content.Context
import android.os.Build
import com.chaquo.python.PyObject
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import org.otrv4plus.android.BuildConfig

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
                diagnosticsText = renderReport(diagnostics, report),
            )
        } catch (t: Throwable) {
            // Still deliberately no `t.message` -- Python exception text can
            // embed data the engine was handling, and that has not changed.
            //
            // What HAS changed is that `t.javaClass.simpleName` alone was the
            // entire failure report on the first handset this ever ran on:
            //
            //     Failure    PyException
            //
            // which says only "a Python exception happened". With FLAG_SECURE
            // set, that could not even be photographed. The app announced that
            // it had failed and structurally prevented anyone learning why.
            //
            // android_bridge.failure.describe() is the answer: it classifies
            // the exception and returns a safe detail plus `file:line in func`
            // frames. It is safe in every build -- see its module docstring --
            // so there is no debug gate here. A diagnostic that is only safe
            // in debug is a diagnostic waiting to be promoted.
            describeFailure(t)
        }
    }

    /**
     * Build a failure report, and collect diagnostics WHILE FAILING.
     *
     * The original flow only ran `diagnostics.collect()` on the success path,
     * so the one report that could explain a failed start was the one thing a
     * failed start never produced. collect() needs no orchestration layer and
     * guards every probe individually, which is exactly what makes it usable
     * here.
     */
    private fun describeFailure(t: Throwable): InitResult {
        var code = t.javaClass.simpleName
        var detail = ""
        var frames = ""
        var rustLoaded = false
        var pyVersion = ""

        try {
            val py = Python.getInstance()
            val f = py.getModule("android_bridge.failure").callAttr("describe", t)
            code = f.callAttr("get", "code")?.toString() ?: code
            detail = f.callAttr("get", "detail")?.toString() ?: ""
            val causedBy = f.callAttr("get", "caused_by")?.toString() ?: ""
            if (causedBy.isNotBlank()) detail = "$detail\ncaused by $causedBy"
            frames = f.callAttr("get", "frames")?.asList()
                ?.joinToString("\n") { it.toString() } ?: ""
        } catch (_: Throwable) {
            // The reporter itself failed. Keep the class name and carry on --
            // a half report beats an exception thrown while explaining one.
        }

        var diagnosticsText: String? = null
        try {
            val py = Python.getInstance()
            val diagnostics = py.getModule("android_bridge.diagnostics")
            // include_selftest = false: the self-test exercises the Rust core,
            // and this is the path where the core may be the thing that is
            // broken. A diagnostic that crashes while diagnosing is worthless.
            val report = diagnostics.callAttr("collect", false, androidBuildInfo(py))
            rustLoaded = section(report, "rust_core", "loaded").toBoolean()
            pyVersion = section(report, "python", "version")
            diagnosticsText = renderReport(diagnostics, report)
        } catch (_: Throwable) {
            // Diagnostics are a bonus on this path, never a second failure.
        }

        return InitResult(
            ok = false,
            pythonVersion = pyVersion,
            abi = Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown",
            rustCoreLoaded = rustLoaded,
            engineInitialized = false,
            failureCode = code,
            failureDetail = detail.ifBlank { null },
            failureFrames = frames.ifBlank { null },
            diagnosticsText = diagnosticsText,
        )
    }

    /**
     * The report as text, rendered in Python.
     *
     * Not formatted here on purpose. `diagnostics.as_text` applies
     * SENSITIVE_KEY_HINTS to the finished string, and a Kotlin renderer would
     * be a second place deciding what a diagnostic may say -- which is the
     * place that would forget the rule the first time a field was added.
     */
    private fun renderReport(diagnostics: PyObject, report: PyObject): String? =
        try {
            diagnostics.callAttr("as_text", report)?.toString()
        } catch (_: Throwable) {
            null
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
        // The first question asked of any report: is this the build that was
        // meant to be under test? A report against the wrong APK wastes the
        // round trip it took to get it.
        dict.callAttr("__setitem__", "app_version", BuildConfig.VERSION_NAME)
        dict.callAttr("__setitem__", "build_id", BuildConfig.BUILD_ID)
        return dict
    }

    private fun section(report: PyObject, group: String, key: String): String =
        report.callAttr("get", group)?.callAttr("get", key)?.toString() ?: ""

    private fun requireApp(): PyObject =
        app ?: throw OtrBridgeException("not_initialized")

    // ── Connection control ────────────────────────────────────────────────
    //
    // Deliberately NOT on the OtrCore interface. OtrCore is about an
    // established session -- fingerprints, SMP, security state -- and those
    // are questions for the engine. Bringing a transport up is a different
    // concern with a different failure vocabulary, and folding it in would
    // mean every future OtrCore implementation had to own a socket too.
    //
    // Every method here calls into Python and must therefore run off the main
    // thread. A tunnel build can take minutes; on the main thread that is an
    // ANR, not a slow connection.

    private var controller: PyObject? = null

    /**
     * Prepare a controller for [jid], using the compiled-in default server.
     *
     * Blank [server], [samHost] and [samPort] mean "use the default", which is
     * the common case: the app ships pointing somewhere and the user overrides
     * only if they run their own.
     */
    fun prepareConnection(
        jid: String,
        server: String = "",
        samHost: String = "",
        samPort: Int = 0,
    ): ConnectionStatus {
        val module = python.getModule("android_bridge.connection")
        controller = module.callAttr(
            "controller_for", requireApp(), jid, server, samHost, samPort)
        return connectionStatus()
    }

    /**
     * Bring the connection up. Never throws for an ordinary failure.
     *
     * The Python side returns a result map rather than raising, because an
     * exception crossing Chaquopy arrives as a PyException whose message is
     * all that survives -- which is exactly how the first handset report came
     * back saying nothing but "PyException".
     *
     * [password] is passed straight through and is not retained here, not
     * logged, and not put in any status field.
     */
    fun connect(password: String): ConnectionStatus {
        val ctl = controller ?: throw OtrBridgeException("not_prepared")
        val result = ctl.callAttr("connect", password)
        return statusFrom(ctl, result)
    }

    fun disconnect(): ConnectionStatus {
        val ctl = controller ?: return connectionStatus()
        val result = ctl.callAttr("disconnect")
        return statusFrom(ctl, result)
    }

    /**
     * Stop a connect that is still running.
     *
     * Returns at once; the blocked [connect] call on the other thread is what
     * unwinds, and it comes back with code `cancelled`.
     *
     * This exists because cancelling the Kotlin coroutine around [connect]
     * does nothing to the work: it is a blocking JNI call into Python, and the
     * thread stays inside it until Python returns. Without this, backing out
     * of a four-minute tunnel build left it building.
     */
    fun cancelConnect() {
        val ctl = controller ?: return
        ctl.callAttr("cancel")
    }

    /** Probe the SAM bridge alone: milliseconds, and it answers the question
     * "is a router running" without a four-minute tunnel attempt. */
    fun probeRouter(): RouterProbe {
        val ctl = controller ?: throw OtrBridgeException("not_prepared")
        val probe = ctl.callAttr("probe")
        return RouterProbe(
            reachable = probe.callAttr("get", "reachable")?.toBoolean() ?: false,
            code = probe.callAttr("get", "code")?.toString() ?: "unknown",
            detail = probe.callAttr("get", "detail")?.toString() ?: "",
            version = probe.callAttr("get", "version")?.toString() ?: "",
        )
    }

    fun connectionStatus(): ConnectionStatus {
        val ctl = controller ?: return ConnectionStatus()
        return statusFrom(ctl, null)
    }

    // ── the shareable error log ───────────────────────────────────────────

    /**
     * Record something only the Android half can see.
     *
     * Service lifecycle, Activity bind/unbind and recreation, connection
     * phase changes. It goes into the SAME log as the transport's own events,
     * because the whole value of the thing is one ordering: two logs would
     * have to be merged by eye, and by then the moment is lost.
     *
     * Silent on failure and never throws. This is called from lifecycle
     * callbacks; a diagnostic that can crash the thing it is diagnosing is
     * worse than no diagnostic.
     */
    fun note(component: String, event: String, severity: String = "info",
             detail: String = "") {
        // The TIME IS TAKEN NOW, on the calling thread, and the WRITE happens
        // on the notes worker. Both halves matter:
        //
        //  - crossing into Python blocks, and Chaquopy's JNI calls are not
        //    interruptible; one of those on Android's main thread is an ANR,
        //    not a slow log line. Most callers here are lifecycle callbacks,
        //    which ARE the main thread.
        //  - a timeline whose entries carry the moment they were flushed
        //    rather than the moment they happened is not a timeline, and the
        //    ordering of the run-up to a failure is the entire point.
        //
        // One single-threaded executor, so notes keep their order relative to
        // each other.
        val at = System.currentTimeMillis() / 1000.0
        runCatching {
            notes.execute {
                runCatching {
                    controller?.callAttr("note", component, event, severity,
                                         detail, at)
                }
            }
        }
    }

    /**
     * Where notes are written. One thread, so they stay in order.
     *
     * Daemon, and discards silently when saturated: a diagnostic must never
     * hold the process open at shutdown, and must never block a caller.
     */
    private val notes: java.util.concurrent.ExecutorService by lazy {
        java.util.concurrent.ThreadPoolExecutor(
            1, 1, 0L, java.util.concurrent.TimeUnit.MILLISECONDS,
            java.util.concurrent.ArrayBlockingQueue(256),
            { runnable ->
                Thread(runnable, "otrv4plus-notes").apply { isDaemon = true }
            },
            java.util.concurrent.ThreadPoolExecutor.DiscardPolicy(),
        )
    }

    /**
     * The whole error log, as text, ready to be written to a file.
     *
     * Rendered in Python by `android_bridge.report`, which is the one place
     * that decides what a diagnostic may contain. Kotlin supplies the device
     * facts it alone knows and writes the bytes; it does not format, filter
     * or add anything, because a second renderer would be a second place to
     * forget the redaction rule.
     */
    fun diagnosticReport(): String {
        val ctl = controller
            ?: return "OTRv4+ diagnostic report\n\n" +
                "No connection has been prepared in this session, so there " +
                "is no connection state or event history to report.\n"
        return runCatching {
            ctl.callAttr("diagnostic_report", androidBuildInfo(python))
                .toString()
        }.getOrElse {
            // Not `it.message`: a PyException carries Python's own text.
            "OTRv4+ diagnostic report\n\nThe report could not be built " +
                "(${it.javaClass.simpleName}).\n"
        }
    }

    /** A short version for the clipboard. The file stays authoritative. */
    fun diagnosticSummary(): String {
        val ctl = controller ?: return "No connection in this session."
        return runCatching {
            ctl.callAttr("diagnostic_summary", androidBuildInfo(python))
                .toString()
        }.getOrElse { "Summary unavailable (${it.javaClass.simpleName})." }
    }

    private fun statusFrom(ctl: PyObject, result: PyObject?): ConnectionStatus {
        val s = ctl.callAttr("status")
        fun str(k: String) = s.callAttr("get", k)?.toString() ?: ""
        fun bool(k: String) = s.callAttr("get", k)?.toBoolean() ?: false
        val last = result ?: s.callAttr("get", "last")
        return ConnectionStatus(
            stage = str("stage"),
            connected = bool("connected"),
            jid = str("jid"),
            server = str("server"),
            isDefaultServer = bool("is_default_server"),
            sam = str("sam"),
            code = last?.callAttr("get", "code")?.toString() ?: "",
            detail = last?.callAttr("get", "detail")?.toString() ?: "",
            inputs = runCatching { ctl.callAttr("inputs_text").toString() }
                .getOrDefault(""),
            workerAlive = bool("worker_alive"),
        )
    }

    override fun shutdown() {
        // The connection FIRST, and this is not cosmetic ordering.
        //
        // This used to shut the engine down and leave the controller alone,
        // so the transport's worker thread, its I2P tunnel and its local
        // listening socket all outlived the object that owned them -- with
        // nothing left holding a reference that could ever close them. On a
        // phone that is a live I2P lease belonging to an app the user has
        // closed.
        try {
            controller?.callAttr("disconnect")
        } catch (_: Throwable) {
            // Teardown must not throw: it runs from lifecycle callbacks and
            // from process shutdown, where there is nobody to tell.
        } finally {
            controller = null
        }
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

    override fun sendUserText(peer: String, body: String): SendOutcome = wrap {
        SendOutcome.fromName(
            requireApp().callAttr("send_user_text", peer, body).toString())
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
        // Events are PULLED, not pushed -- see [drainEvents]. This setter is
        // kept because OtrCore declares it and a caller may want the callback
        // shape; drainEvents feeds it.
    }

    /**
     * Take everything the engine has emitted since the last call.
     *
     * Pull rather than push, and the reason is threading. These events are
     * emitted on the transport's asyncio loop thread. A Python callback into
     * Kotlin from there would arrive on a thread Compose must not be updated
     * from, so every handler any future screen writes would carry a
     * marshalling obligation, and one that forgot would crash only under load
     * and only sometimes. Pulling puts the UI in charge of its own thread.
     *
     * Delivered once and in order: the Python queue removes what it returns,
     * because an event handed over twice puts a message on screen twice and
     * nothing downstream can tell that from a peer who sent the same text
     * again.
     *
     * Also feeds [setEventSink]'s sink, if one was set.
     */
    fun drainEvents(limit: Int = 0): List<OtrEvent> {
        val ctl = controller ?: return emptyList()
        val raw = runCatching { ctl.callAttr("drain_events", limit) }
            .getOrNull() ?: return emptyList()
        val out = mutableListOf<OtrEvent>()
        for (item in raw.asList()) {
            val event = runCatching { eventFrom(item) }.getOrNull() ?: continue
            out.add(event)
            sink?.let { s -> runCatching { s.onEvent(event) } }
        }
        return out
    }

    /**
     * Ask [jid] to let us see their presence, and add them to the roster.
     *
     * Goes to the transport rather than the engine: a roster is an XMPP
     * concept and the OTR engine has no opinion about who is on it. Adding
     * someone establishes nothing cryptographic — the conversation is
     * plaintext until a DAKE runs, and the conversation screen says so.
     *
     * RETURNS THE ANSWER, and that is the point of this signature.
     *
     * `ConnectionController.add_contact` has always returned
     * `{ok, code, detail}` -- including `not_connected` with the sentence
     * "Connect before changing the contact list." -- and this threw all of it
     * away. On a handset that read exactly as the button doing nothing:
     * Python declined, said why, and nobody looked.
     */
    fun addContact(jid: String, name: String = ""): RosterResult {
        val ctl = controller
            ?: return RosterResult(false, "not_prepared",
                                   "The connection is not ready yet.")
        return rosterResult { ctl.callAttr("add_contact", jid, name) }
    }

    /**
     * Read Python's result dict without letting an exception become the only
     * survivor. `detail` comes from the controller, which writes it for a
     * person; engine exception text never reaches it.
     */
    private inline fun rosterResult(call: () -> PyObject?): RosterResult =
        try {
            val r = call()
            RosterResult(
                ok = r?.callAttr("get", "ok")?.toBoolean() ?: false,
                code = r?.callAttr("get", "code")?.toString() ?: "no_result",
                detail = r?.callAttr("get", "detail")?.toString() ?: "",
            )
        } catch (e: OtrBridgeException) {
            RosterResult(false, e.code, "")
        } catch (e: Throwable) {
            // The TYPE, never the message: a PyException carries the engine's
            // own text, which can quote what it was handling.
            RosterResult(false, "bridge_error", "")
        }

    fun removeContact(jid: String) {
        val ctl = controller ?: throw OtrBridgeException("not_prepared")
        wrap { ctl.callAttr("remove_contact", jid) }
    }

    /** How many events the bounded queue discarded. A gap is worth saying. */
    fun eventsDropped(): Int =
        controller?.let {
            runCatching { it.callAttr("events_dropped").toInt() }.getOrDefault(0)
        } ?: 0

    private fun eventFrom(item: PyObject): OtrEvent? {
        fun str(k: String) = item.callAttr("get", k)?.toString() ?: ""
        fun num(k: String) = item.callAttr("get", k)?.toDouble() ?: 0.0
        fun int(k: String) = item.callAttr("get", k)?.toInt() ?: 0
        return when (str("type")) {
            "ConnectionStateChanged" ->
                OtrEvent.ConnectionChanged(
                    ConnectionState.entries.firstOrNull {
                        it.name == str("state")
                    } ?: ConnectionState.DISCONNECTED)

            "SessionStateChanged" ->
                OtrEvent.SessionChanged(
                    str("peer"), SecurityState.fromLevel(int("security_level")))

            "MessageReceived" ->
                OtrEvent.MessageReceived(
                    str("peer"), str("body"), num("timestamp"))

            // The Python class is SmpProgress, the Kotlin event is
            // SmpProgressed. The names differ and that is a trap: these
            // branches are checked against android_bridge.events by
            // tests/test_android_event_mapping.py, because three of them were
            // wrong when first written and nothing would have noticed.
            "SmpProgress" ->
                OtrEvent.SmpProgressed(
                    str("peer"),
                    SmpProgress(int("step"), int("total"),
                        SmpState.fromName(str("state"))))

            "SmpResult" ->
                OtrEvent.SmpFinished(str("peer"), SmpState.fromName(str("state")))

            "FingerprintChanged" ->
                OtrEvent.FingerprintChanged(
                    str("peer"), str("stored_fingerprint"),
                    str("received_fingerprint"))

            // Carries no body -- a receipt for something already on screen.
            // Mapped to Failed(code) would be a lie; there is no Kotlin event
            // for it yet, so it is skipped deliberately rather than by
            // omission, and the drift test knows that.
            "MessageDelivered" -> null

            "CallStateChanged" ->
                OtrEvent.CallChanged(
                    str("peer"), CallState.fromName(str("state")),
                    int("duration_seconds"))

            "ErrorOccurred" ->
                OtrEvent.Failed(str("peer").ifBlank { null }, str("code"))

            // An event type this build does not know about is skipped rather
            // than guessed at. A wrong mapping is worse than a missing one:
            // the screen would show something confident and untrue.
            else -> null
        }
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

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

    /**
     * The report from the initialisation that actually ran.
     *
     * Held so a second caller can be answered without redoing the work. See
     * [initialize] for why a second caller exists and what repeating it cost.
     */
    private var initResult: InitResult? = null

    private val python: Python
        get() {
            if (!Python.isStarted()) {
                Python.start(AndroidPlatform(appContext))
            }
            return Python.getInstance()
        }

    /**
     * Bring the stack up, ONCE.
     *
     * WHY THE GUARD, AND WHAT IT COST WITHOUT ONE
     * -------------------------------------------
     * This method is not a query. It runs `diagnostics.collect`, constructs an
     * `EnhancedSessionManager`, and REPLACES `app` with a new `OtrApp` over it.
     * It had no idempotence guard, and it has two callers:
     *
     *   * `OtrConnectionService.connectLoop`, guarded by its own `initialised`
     *     flag, so it runs the work once;
     *   * `ConnectionViewModel.onServiceConnected`, guarded by nothing, which
     *     runs on EVERY service bind -- every Activity creation, so every
     *     launch, every rotation, every return to the app.
     *
     * The ViewModel's comment said "the engine starts once, in the service.
     * Asking here is what gives the connect screen something to show" -- true
     * of the intent, not of the call, because the call builds its own.
     *
     * The cost was not only time. Measured in Python, running the equivalent
     * of a second initialisation over a live session:
     *
     *     after first initialize + DAKE : security=ENCRYPTED  OTR asked=True
     *     after a second initialize()   : security=PLAINTEXT  OTR asked=False
     *
     * A fresh engine has no sessions, so rotating the phone dropped an
     * established OTR session. Worse, the fresh `OtrApp` has a fresh
     * `OtrMode`, so a conversation the user had explicitly asked to encrypt
     * became willing to send plaintext again -- which is precisely the
     * downgrade `OtrMode` exists to refuse ("a failed handshake is not consent
     * to continue without one").
     *
     * So this is a correctness fix that happens to also remove repeated work:
     * ~300ms of Python per bind on a developer machine, and a handset is
     * slower.
     *
     * A FAILED initialisation is NOT cached. The guard is on `app`, which
     * stays null when the work threw, so a later caller genuinely retries
     * rather than being handed a stale failure forever.
     */
    override fun initialize(): InitResult {
        initResult?.let { if (app != null) return it }
        return try {
            val py = python
            val bootstrap = py.getModule("android_bridge.bootstrap")
            // Fails fast and loudly on Python < 3.12 or a missing otrv4_core,
            // rather than surfacing as a SyntaxError deep inside an import.
            bootstrap.callAttr("ensure_runtime")
            bootstrap.callAttr("load_orchestration")

            // THE REAL ENGINE FIRST, so diagnostics can report on it instead
            // of building a second one to look at.
            //
            // `_otrv4plus_info` constructed its own `EnhancedSessionManager`
            // purely to answer "does one come up, and what is its fingerprint
            // prefix" -- measured at ~106ms of the ~298ms startup path, spent
            // on an object thrown away immediately afterwards.
            //
            // Null on failure, deliberately: `collect` then falls back to its
            // own probe, so the diagnostic report survives exactly the case it
            // exists for. Losing the report when the engine will not start
            // would be trading the answer for the question.
            val otr = py.getModule("otrv4_")
            val engine = try {
                otr.callAttr("EnhancedSessionManager", otr.callAttr("OTRConfig"))
            } catch (_: Throwable) {
                null
            }

            val diagnostics = py.getModule("android_bridge.diagnostics")
            val report = diagnostics.callAttr(
                "collect", true, androidBuildInfo(py), engine)

            val appModule = py.getModule("android_bridge.app")
            app = appModule.callAttr(
                "OtrApp", engine ?: throw OtrBridgeException("engine_unavailable"))

            InitResult(
                ok = report.callAttr("get", "ok").toBoolean(),
                pythonVersion = section(report, "python", "version"),
                abi = section(report, "abi", "android_abi"),
                rustCoreLoaded = section(report, "rust_core", "loaded").toBoolean(),
                engineInitialized = section(report, "otrv4plus", "initialized").toBoolean(),
                diagnosticsText = renderReport(diagnostics, report),
            ).also { initResult = it }
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

    /**
     * Create the account [prepareConnection] was given. Never throws.
     *
     * XEP-0077 in-band registration, over the same SAM tunnel a login uses.
     * It does NOT sign in afterwards: the caller connects next, so that a
     * registration that succeeded and a login that failed have two outcomes
     * rather than one. On a network where the second half can take four
     * minutes, that is the difference between retyping a password and
     * creating a second account.
     *
     * The returned [code] is from `otrv4plus_registration` -- `conflict`,
     * `not_acceptable`, `unsupported` and the rest -- and [detail] is a
     * sentence chosen from that module's table, never the server's own words.
     *
     * [password] is passed straight through, not retained here, not logged,
     * and not put in any status field.
     */
    fun register(password: String): RegistrationOutcome {
        val ctl = controller ?: throw OtrBridgeException("not_prepared")
        val result = ctl.callAttr("register", password)
        fun str(k: String) = result?.callAttr("get", k)?.toString() ?: ""
        return RegistrationOutcome(
            ok = result?.callAttr("get", "ok")?.toBoolean() ?: false,
            code = str("code").ifBlank { "unknown" },
            detail = str("detail"),
        )
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

    // ── service discovery and rooms ───────────────────────────────────────
    //
    // Every call here blocks on an I2P round trip and must run off the main
    // thread. None of them throws for an ordinary failure: the controller
    // answers {ok, code, detail, value} and these flatten it, because an
    // exception crossing Chaquopy arrives as a PyException whose message is
    // all that survives — and a MUC error's message carries the room, the
    // service and the nickname.

    /** What the server hosts. Finding the rooms service is what this is for. */
    fun discoverServices(): Pair<RoomOutcome, List<DiscoveredService>> {
        val result = call("discover_services") ?: return notPrepared() to
            emptyList()
        val outcome = outcomeOf(result)
        val services = mutableListOf<DiscoveredService>()
        listValue(result)?.let { items ->
            for (item in items.asList()) {
                services += DiscoveredService(
                    jid = entry(item, "jid"),
                    name = entry(item, "name"),
                    category = entry(item, "category"),
                    type = entry(item, "type"),
                )
            }
        }
        return outcome to services
    }

    /** The rooms a service advertises. Hidden rooms are absent by design. */
    fun discoverRooms(service: String): Pair<RoomOutcome, List<RoomSummary>> {
        val result = call("discover_rooms", service)
            ?: return notPrepared() to emptyList()
        val rooms = mutableListOf<RoomSummary>()
        listValue(result)?.let { items ->
            for (item in items.asList()) {
                rooms += RoomSummary(entry(item, "jid"), entry(item, "name"))
            }
        }
        return outcomeOf(result) to rooms
    }

    fun joinRoom(room: String, nick: String, password: String = ""):
        Pair<RoomOutcome, RoomStanding> = roomWithStanding(
            "join_room", room, nick, password)

    /** [password] non-empty makes the room password-protected. Not kept. */
    fun createRoom(room: String, nick: String, password: String = ""):
        Pair<RoomOutcome, RoomStanding> =
        if (password.isEmpty()) roomWithStanding("create_room", room, nick)
        else roomWithStanding("create_room", room, nick, password)

    fun roomStanding(room: String, nick: String):
        Pair<RoomOutcome, RoomStanding> =
        roomWithStanding("room_standing", room, nick)

    // Block bodies, not expression bodies. `?: return notPrepared()` inside an
    // expression body does not compile -- "Returns are prohibited for
    // functions with an expression body" -- and these two were the only pair
    // written that way. It got through the local plain-Kotlin harness because
    // that harness cannot compile this file at all (it needs Chaquopy), so CI
    // was the first compiler to see it.
    fun leaveRoom(room: String, nick: String): RoomOutcome {
        val result = call("leave_room", room, nick) ?: return notPrepared()
        return outcomeOf(result)
    }

    fun destroyRoom(room: String, reason: String = ""): RoomOutcome {
        val result = call("destroy_room", room, reason) ?: return notPrepared()
        return outcomeOf(result)
    }

    /**
     * What the server advertises about keeping [jid]'s history (our own
     * account when blank). `null` mam when it did not answer: unknown is not
     * "no archive". Asked, never acted on -- see `ChatDeletion`.
     */
    fun archiveSupport(jid: String = ""): Pair<RoomOutcome, Boolean?> {
        val result = call("archive_support", jid) ?: return notPrepared() to null
        val outcome = outcomeOf(result)
        if (!outcome.ok) return outcome to null
        val mam = runCatching {
            listValue(result)?.callAttr("get", "mam")?.toBoolean()
        }.getOrNull()
        return outcome to mam
    }

    /** The Welcome room's state and discoverable people. No network. */
    fun welcomeDirectory(): WelcomeView {
        val v = call("welcome_directory") ?: return WelcomeView.NONE
        return runCatching {
            WelcomeView(
                state = entry(v, "state").ifBlank { WelcomeView.NOT_CONNECTED },
                room = entry(v, "room"),
                anonymity = entry(v, "anonymity").ifBlank { "unknown" },
                people = v.callAttr("get", "people")?.asList()
                    ?.map { it.toString() } ?: emptyList(),
                hidden = v.callAttr("get", "hidden")?.toInt() ?: 0,
            )
        }.getOrDefault(WelcomeView.NONE)
    }

    /**
     * Ask the server who is online (XEP-0133), if it offers that to us.
     * Null value on failure; see [OnlineDiscovery] for what "none" means.
     */
    fun discoverOnlineUsers(): Pair<RoomOutcome, OnlineDiscovery?> {
        val result = call("discover_online_users") ?: return notPrepared() to null
        val outcome = outcomeOf(result)
        if (!outcome.ok) return outcome to null
        val value = listValue(result) ?: return outcome to null
        val mechanism = entry(value, "mechanism").ifBlank { OnlineDiscovery.NONE }
        val users = runCatching {
            value.callAttr("get", "users")?.asList()?.map { it.toString() }
        }.getOrNull() ?: emptyList()
        return outcome to OnlineDiscovery(mechanism, users)
    }

    /** Who is in [room]. Moderators first, as the bridge orders them. */
    fun roomOccupants(room: String): Pair<RoomOutcome, List<RoomOccupant>> {
        val result = call("room_occupants", room) ?: return notPrepared() to emptyList()
        val people = listValue(result)?.asList()?.map {
            RoomOccupant(entry(it, "nick"), entry(it, "role"), entry(it, "affiliation"))
        } ?: emptyList()
        return outcomeOf(result) to people
    }

    fun joinedRooms(): Pair<RoomOutcome, List<String>> {
        val result = call("joined_rooms") ?: return notPrepared() to emptyList()
        val rooms = listValue(result)?.asList()?.map { it.toString() }
            ?: emptyList()
        return outcomeOf(result) to rooms
    }

    private fun roomWithStanding(name: String, vararg args: Any):
        Pair<RoomOutcome, RoomStanding> {
        val result = call(name, *args) ?: return notPrepared() to RoomStanding()
        val value = result.callAttr("get", "value")
        val standing = if (value == null) RoomStanding() else RoomStanding(
            room = entry(value, "room"),
            nick = entry(value, "nick"),
            affiliation = entry(value, "affiliation").ifBlank { "none" },
            role = entry(value, "role").ifBlank { "none" },
            speak = flag(value, "speak"),
            changeSubject = flag(value, "change_subject"),
            invite = flag(value, "invite"),
            kick = flag(value, "kick"),
            ban = flag(value, "ban"),
            configure = flag(value, "configure"),
            destroy = flag(value, "destroy"),
            grantMembership = flag(value, "grant_membership"),
        )
        return outcomeOf(result) to standing
    }

    /**
     * A controller call that answers rather than throws.
     *
     * WRAPPED, and it was not. This returned `controller?.callAttr(...)` bare,
     * so anything the Python side raised -- a `TransportError` from a room
     * join, a malformed JID, a timeout -- crossed Chaquopy as a PyException
     * and propagated out of `createRoom` into `RoomsViewModel`'s coroutine.
     * That coroutine had no `finally`, so `busy` was never cleared and the
     * Rooms screen sat on "Creating the room..." for good.
     *
     * The roster calls have answered this way since `addContact` was fixed
     * for the same reason; the room calls were the ones still throwing.
     * Returning null means "no answer", which every caller here already
     * handles as `notPrepared()`.
     *
     * The exception TYPE is not propagated and its message is never read: a
     * PyException carries the engine's own text, which can quote what it was
     * handling. The caller's own `RoomOutcome` carries the reportable code,
     * which Python wrote for a person.
     */
    private fun call(name: String, vararg args: Any): PyObject? =
        try {
            controller?.callAttr(name, *args)
        } catch (t: Throwable) {
            null
        }

    private fun outcomeOf(result: PyObject): RoomOutcome = RoomOutcome(
        ok = result.callAttr("get", "ok")?.toBoolean() ?: false,
        code = result.callAttr("get", "code")?.toString()?.ifBlank { "unknown" }
            ?: "unknown",
        detail = result.callAttr("get", "detail")?.toString() ?: "",
    )

    private fun listValue(result: PyObject): PyObject? =
        result.callAttr("get", "value")

    private fun entry(item: PyObject, key: String): String =
        runCatching { item.callAttr("get", key)?.toString() }.getOrNull()
            ?: ""

    private fun flag(item: PyObject, key: String): Boolean =
        runCatching { item.callAttr("get", key)?.toBoolean() }.getOrNull()
            ?: false

    /**
     * No controller yet, which is not the same as a failure to do the thing.
     *
     * Reported as `network` because from the user's side it is the same
     * situation — nothing has connected — and it is the code the rooms screen
     * already knows how to render.
     */
    private fun notPrepared(): RoomOutcome = RoomOutcome(
        ok = false, code = "network",
        detail = "Connect before using rooms.")

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

    /**
     * Wipe & Exit, engine side. NOT `shutdown` with extra steps.
     *
     * Through the CONTROLLER when there is one: it cancels an attempt in
     * flight, refuses to connect again, and hands its transport to
     * `OtrApp.wipe`, which destroys every secret on the transport's loop
     * thread before closing it. Straight to the app when there is only an
     * app. And when this process never started the engine at all, the
     * Python-side files are still destroyed -- a wipe after a cold start must
     * not leave the previous run's device seed and received files behind.
     *
     * Every reference is dropped afterwards, `initResult` included, so the
     * core cannot answer as though a wiped engine were alive.
     */
    override fun wipe(): WipeReport {
        val report: PyObject? = try {
            val ctl = controller
            val a = app
            when {
                ctl != null -> ctl.callAttr("wipe")
                a != null -> a.callAttr("wipe")
                else -> python.getModule("android_bridge.wipe").callAttr("wipe_disk")
            }
        } catch (_: Throwable) {
            null
        } finally {
            controller = null
            app = null
            initResult = null
        }
        if (report == null) return WipeReport.UNREACHABLE
        fun int(key: String): Int =
            runCatching { report.callAttr("get", key, 0)?.toInt() ?: 0 }.getOrDefault(0)
        val errors = runCatching {
            report.callAttr("get", "errors")?.asList()?.map { it.toString() }
        }.getOrNull() ?: emptyList()
        return WipeReport(
            sessions = int("sessions"),
            handshakes = int("handshakes"),
            identityKeys = int("identity_keys"),
            filesDestroyed = int("files_destroyed"),
            filesUnlinkedOnly = int("files_unlinked_only"),
            errors = errors,
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
            // With the engine gone the cached report describes a stack that
            // no longer exists. Cleared so the next `initialize` genuinely
            // re-runs rather than answering from a stale success.
            initResult = null
        }
    }

    override fun localFingerprint(): String =
        requireApp().callAttr("local_fingerprint").toString()

    override fun securityState(peer: String): SecurityState =
        SecurityState.fromLevel(requireApp().callAttr("security_state", peer).toInt())

    override fun smpState(peer: String): SmpState =
        SmpState.fromName(
            requireApp().callAttr("smp_state", peer).get("name")?.toString() ?: "NOT_VERIFIED"
        )

    override fun smpProgress(peer: String): SmpProgress {
        val p = requireApp().callAttr("smp_progress", peer)
        return SmpProgress(
            step = p.get("step")?.toInt() ?: 0,
            total = p.get("total")?.toInt() ?: 4,
            state = SmpState.fromName(p.get("state")?.get("name")?.toString() ?: "NOT_VERIFIED"),
        )
    }

    override fun securityDetails(peer: String): SecurityDetails {
        val d = requireApp().callAttr("security_details", peer)
        return SecurityDetails(
            peer = peer,
            security = SecurityState.fromLevel(d.get("security")?.toInt() ?: 0),
            smp = SmpState.fromName(d.get("smp")?.get("name")?.toString() ?: "NOT_VERIFIED"),
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
                presence = PeerPresence.of(
                    c.get("presence")?.toString() ?: ""),
                presenceShow = c.get("presence_show")?.toString() ?: "",
                security = SecurityState.fromLevel(c.get("security")?.toInt() ?: 0),
                smp = SmpState.fromName(c.get("smp")?.get("name")?.toString() ?: "NOT_VERIFIED"),
                callAvailable = c.get("call_available")?.toBoolean() ?: false,
                subscription = Subscription.of(
                    c.get("subscription")?.toString() ?: "",
                    c.get("pending")?.toBoolean() ?: false),
            )
        }

    override fun startSession(peer: String) {
        wrap { requireApp().callAttr("start_session", peer) }
    }

    /**
     * Automatic OTRv4+ for an open private conversation: starts a DAKE only
     * if a resource of [peer] is confirmed OTRv4Plus-capable. Returns
     * "established", "started", "in_progress", or the capability state.
     */
    fun ensureOtr(peer: String): String =
        runCatching { requireApp().callAttr("ensure_otr", peer).toString() }
            .getOrDefault("unknown")

    /** unknown / offline / checking / available / unavailable. */
    fun otrCapability(peer: String): String =
        runCatching { requireApp().callAttr("otr_capability", peer).toString() }
            .getOrDefault("unknown")

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

    override fun smpSecretRequired(peer: String): Boolean =
        runCatching {
            requireApp().callAttr("smp_secret_required", peer).toBoolean()
        }.getOrDefault(false)

    override fun smpAbort(peer: String) {
        wrap { requireApp().callAttr("smp_abort", peer) }
    }

    // ── Calls ─────────────────────────────────────────────────────────────
    //
    // Thin, like everything else here: each of these is one `callAttr` onto
    // `OtrApp`, which delegates to `android_bridge.voice.CallBridge`, which
    // delegates to `otrv4plus_voice.VoiceCallManager` -- the same state
    // machine, signalling and SMP gate the terminal client has always used.
    //
    // NOTHING ON THIS SIDE DECIDES WHETHER A CALL MAY HAPPEN. The gate is
    // `VoiceCallManager`'s, read from the engine's own verification
    // predicate. A second check in Kotlin would be a second answer that
    // could disagree with the one that actually refuses, and the UI would
    // be showing the wrong one.
    //
    // BLOCKING, so every one of these belongs on a worker thread -- the same
    // rule as the rest of this class. None of them waits for a call to
    // connect, though: placing a call builds I2P tunnels, and the Python
    // side returns as soon as the request is handed over.

    /**
     * Place a call to [peer]. Returns a `CallOutcome` code, never a sentence.
     *
     * "started" means the request reached the call manager, NOT that anything
     * is ringing. Building the tunnels takes 30-120 s, so the screen follows
     * [callState] and the events that arrive through [drainEvents].
     */
    fun startCall(peer: String): String =
        runCatching {
            requireApp().callAttr("start_call", peer).toString()
        }.getOrDefault(CallOutcome.UNAVAILABLE)

    /** Answer a ringing call. Returns a `CallOutcome` code. */
    fun answerCall(peer: String): String =
        runCatching {
            requireApp().callAttr("answer_call", peer).toString()
        }.getOrDefault(CallOutcome.UNAVAILABLE)

    /**
     * End an active call, or reject a ringing one.
     *
     * One verb for both because the state machine has one: rejecting and
     * hanging up are the same transition, and splitting them here would
     * invent a distinction the protocol does not have.
     */
    fun endCall(peer: String): String =
        runCatching {
            requireApp().callAttr("end_call", peer).toString()
        }.getOrDefault(CallOutcome.UNAVAILABLE)

    /** This peer's call state, read from the live session. */
    fun callState(peer: String): CallState =
        runCatching {
            CallState.fromName(
                requireApp().callAttr("call_state", peer)
                    .get("name")?.toString() ?: "IDLE")
        }.getOrDefault(CallState.IDLE)

    /**
     * Seconds since the call became ACTIVE, or 0.
     *
     * Never counts the tunnel build. A timer that started when the user
     * pressed Call would show a minute and a half of conversation that had
     * not happened yet.
     */
    fun callDurationSeconds(peer: String): Int =
        runCatching {
            requireApp().callAttr("call_duration_seconds", peer).toInt()
        }.getOrDefault(0)

    /**
     * Why voice cannot run on this device, or "" when it can.
     *
     * Asked of Python, which asks `otrv4plus_voice`'s own host hook -- the
     * same question the call manager asks before doing anything. A separate
     * answer here could tell the user something the engine would contradict.
     */
    /**
     * Whether a call may be offered to [peer], from the engine: the code and,
     * for "voice_unavailable", the host hook's reason. Null when the bridge
     * could not be asked -- the caller then decides from what it has, and
     * never towards "available". See `OtrApp.call_gate`.
     */
    fun callGate(peer: String): Pair<String, String>? =
        runCatching {
            val d = requireApp().callAttr("call_gate", peer)
            (d.callAttr("get", "gate")?.toString() ?: return@runCatching null) to
                (d.callAttr("get", "reason")?.toString() ?: "")
        }.getOrNull()

    fun voiceUnavailableReason(): String =
        runCatching {
            requireApp().callAttr("voice_unavailable_reason").toString()
        }.getOrDefault("Voice is not available on this device.")

    // ── File transfer ─────────────────────────────────────────────────────
    //
    // Thin, like the calls. `otrv4plus_filetransfer` owns the FileKey, the
    // AEAD, the chunk format, the hashes, the offer semantics, the filename
    // rules, the size limit and the atomic commit -- and the SMP gate on
    // BOTH sides. None of that is restated here.
    //
    // THE PATH COMES FROM SAF. Android picks through the Storage Access
    // Framework and hands down a path it has already resolved; the Termux
    // picker `otrv4plus_filetransfer.pick_file` shells out to is never
    // reached from an APK.

    /**
     * Offer a file to [peer]. Returns a `FileOutcome` code, never a sentence.
     *
     * "started" means the engine accepted the offer and it is on its way,
     * NOT that the peer has it -- the peer has to accept, and then every
     * chunk crosses I2P.
     */
    fun sendFile(peer: String, path: String,
                 stripMetadata: Boolean = false): String =
        runCatching {
            requireApp().callAttr("send_file", peer, path, stripMetadata)
                .toString()
        }.getOrDefault(FileOutcome.UNAVAILABLE)

    /**
     * What [path] carries before it is sent, so the user can choose.
     *
     * Examined in Python, where `android_bridge.metadata` is driven against
     * real files in the test suite. A failure to ask is reported as UNKNOWN
     * -- "the app cannot check" -- never as clean.
     */
    fun inspectFile(path: String): MetadataFinding =
        runCatching {
            val d = requireApp().callAttr("inspect_file", path)
            MetadataFinding(
                kind = d.get("kind")?.toString() ?: "unknown",
                carriesMetadata = d.get("carries_metadata")?.toBoolean() ?: false,
                metadataBytes = d.get("metadata_bytes")?.toInt() ?: 0,
                canScrub = d.get("can_scrub")?.toBoolean() ?: false,
            )
        }.getOrDefault(MetadataFinding.UNKNOWN)

    /** Accept an offered transfer, by the id [transfers] reported. */
    fun acceptFile(transferId: String): String =
        runCatching {
            requireApp().callAttr("accept_file", transferId).toString()
        }.getOrDefault(FileOutcome.UNAVAILABLE)

    /** Stop a transfer under way: ours, or one we accepted. */
    fun cancelFile(transferId: String): String =
        runCatching {
            requireApp().callAttr("cancel_file", transferId).toString()
        }.getOrDefault(FileOutcome.UNAVAILABLE)

    /** Decline an offered transfer. */
    fun declineFile(transferId: String): String =
        runCatching {
            requireApp().callAttr("decline_file", transferId).toString()
        }.getOrDefault(FileOutcome.UNAVAILABLE)

    /**
     * Every live transfer, structured.
     *
     * Structured rather than the engine's own progress lines: those are
     * written for a terminal, name files and embed transfer ids. The
     * filename here has already been through the engine's
     * `sanitise_filename`, which matters because it was chosen by somebody
     * else and is about to be rendered.
     */
    fun transfers(): List<FileTransferView> =
        runCatching {
            requireApp().callAttr("transfers").asList().map { row ->
                FileTransferView(
                    id = row.get("id")?.toString().orEmpty(),
                    peer = row.get("peer")?.toString().orEmpty(),
                    filename = row.get("filename")?.toString().orEmpty(),
                    sizeBytes = row.get("size")?.toLong() ?: 0L,
                    outgoing = row.get("outgoing")?.toBoolean() ?: false,
                    accepted = row.get("accepted")?.toBoolean() ?: false,
                    cancelled = row.get("cancelled")?.toBoolean() ?: false,
                    progress = row.get("progress")?.toFloat() ?: 0f,
                    state = row.get("state")?.toString().orEmpty(),
                    reason = row.get("reason")?.toString().orEmpty(),
                    path = row.get("path")?.toString().orEmpty(),
                )
            }
        }.getOrDefault(emptyList())

    /**
     * Where a FINISHED file lands.
     *
     * Not the partial-work directory: the engine keeps the two apart so a
     * partial file can never be mistaken for a complete one, and pointing
     * the user at that one would point them at the files that are not
     * theirs yet.
     */
    fun receivedFileDir(): String =
        runCatching {
            requireApp().callAttr("received_file_dir").toString()
        }.getOrDefault("")

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
     * Drop [jid] from the roster and revoke both directions of subscription.
     *
     * The remedy the subscription banner offers under ACCEPT, where the grant
     * has already happened and declining is not on the table. Nothing called
     * this before, so presence could be granted automatically and never taken
     * back from the handset.
     *
     * RETURNS THE ANSWER, like [addContact], and REPLACES a version that threw
     * `OtrBridgeException` and returned Unit. `ConnectionController.remove_
     * contact` has always answered `{ok, code, detail}` -- including
     * `not_connected` with a sentence written for a person -- and the throwing
     * version discarded all of it. That is the same defect [addContact] was
     * fixed for: Python declined, said why, and nobody looked.
     */
    fun removeContact(jid: String): RosterResult {
        val ctl = controller
            ?: return RosterResult(false, "not_prepared",
                                   "The connection is not ready yet.")
        return rosterResult { ctl.callAttr("remove_contact", jid) }
    }

    /**
     * Answer a pending subscription request.
     *
     * ONLY MEANINGFUL UNDER [SubscriptionPolicy.ASK]. Under ACCEPT slixmpp
     * answered before the event was raised, and sending a second `subscribed`
     * would be a stanza with nothing to do; under REJECT the same in reverse.
     * The screen decides using [OtrEvent.SubscriptionRequested.isQuestion]
     * rather than this method guessing, because the policy the transport
     * actually applied is the only authority on it and it lives in Python.
     *
     * THIS HAD NO KOTLIN CALLER AT ALL. `answer_subscription` has been in the
     * transport and the controller since rooms were added, so ASK was a policy
     * that could be set and then never answered: the asker waited forever and
     * the user was never shown the question.
     */
    fun answerSubscription(jid: String, approve: Boolean): RosterResult {
        val ctl = controller
            ?: return RosterResult(false, "not_prepared",
                                   "The connection is not ready yet.")
        return rosterResult {
            ctl.callAttr("answer_subscription", jid, approve)
        }
    }

    /**
     * The policy the transport actually applied.
     *
     * [SubscriptionPolicy.UNKNOWN] when the controller is not up, rather than
     * ACCEPT: "not connected yet" and "this build grants presence to anyone
     * who asks" are different statements and only one of them is true here.
     */
    fun subscriptionPolicy(): SubscriptionPolicy {
        val ctl = controller ?: return SubscriptionPolicy.UNKNOWN
        val name = runCatching {
            ctl.callAttr("subscription_policy")?.toString()
        }.getOrNull() ?: return SubscriptionPolicy.UNKNOWN
        return SubscriptionPolicy.of(name)
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

            "RoomMessageReceived" ->
                OtrEvent.RoomMessageReceived(
                    str("peer"), str("sender"), str("body"), num("timestamp"))

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

            // Was dropped here for a real reason that has since been fixed:
            // the controller used to log this and never queue it, because a
            // plain dict arrives from `EventQueue._describe` as
            // `{"type": "dict"}` with no fields. It is a dataclass now, so
            // there is something to map.
            "SubscriptionRequested" ->
                OtrEvent.SubscriptionRequested(
                    str("peer"), SubscriptionPolicy.of(str("policy")))

            "OtrCapabilityChanged" ->
                OtrEvent.CapabilityChanged(str("peer"), str("state"))

            "FileTransferChanged" ->
                OtrEvent.FileTransferChanged(
                    str("peer"), str("transfer_id"), str("filename"),
                    item.callAttr("get", "size")?.toLong() ?: 0L,
                    item.callAttr("get", "outgoing")?.toBoolean() ?: false,
                    str("state"), str("reason"))

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

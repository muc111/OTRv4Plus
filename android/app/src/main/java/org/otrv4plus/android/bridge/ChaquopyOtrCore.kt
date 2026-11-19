package org.otrv4plus.android.bridge

import android.content.Context
import android.os.Build
import com.chaquo.python.PyObject
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import org.otrv4plus.android.BuildConfig
import org.otrv4plus.android.security.KeystoreVault

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
class ChaquopyOtrCore private constructor(
    private val appContext: Context,
    private val handles: BridgeHandles,
) : OtrCore,
    SecureGroupsApi by ChaquopyGroups(handles),
    AccountAdminApi by ChaquopyAccountAdmin(handles),
    MediaApi by ChaquopyMedia(handles) {

    constructor(appContext: Context) : this(appContext, BridgeHandles())

    /** The engine's `OtrApp`; null before [initialize] and after [shutdown]. */
    private var app: PyObject?
        get() = handles.app
        set(value) { handles.app = value }

    private fun requireApp(): PyObject = handles.requireApp()

    private fun call(name: String, vararg args: Any): PyObject? = handles.call(name, *args)

    private fun roomWithStanding(name: String, vararg args: Any): Pair<RoomOutcome, RoomStanding> =
        handles.roomWithStanding(name, *args)

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
            // F3: each account's identity, kept between runs. The records are
            // sealed inside Rust before they reach the vault; the vault seals
            // them again under the AndroidKeyStore. Its own directory, so
            // clearing chat history never removes an identity.
            // Without it (no Keystore, no storage) every account still gets
            // its own identity, made new each run (F2).
            runCatching {
                app?.callAttr("use_identity_store",
                    py.getModule("android_bridge.account_identity").callAttr(
                        "for_android", KeystoreVault.open(appContext, KeystoreVault.IDENTITY)))
            }
            // P1: each account's contact pins (fingerprints, ML-DSA keys,
            // "They match"), kept between runs in the vault's own trust
            // section -- apart from identities and from chat history. Only a
            // real KeystoreVault keeps them: on the in-memory fallback Python
            // gets no trust store, and the pins last one run, as before.
            runCatching {
                val trust = KeystoreVault.open(appContext, KeystoreVault.TRUST)
                app?.callAttr("use_trust_store",
                    py.getModule("android_bridge.account_trust").callAttr(
                        "for_android", trust, KeystoreVault.isKeystore(trust)))
            }

            // Debug builds turn on the voice engine's verbose setup log, so a
            // bad call's capture/playout rates, codec rate and echo-route reach
            // both logcat and the shareable diagnostic report. A no-op in
            // release (BuildConfig.DEBUG is a compile-time constant), and it
            // does not force the voice stack to load -- it only sets the flag
            // the module reads when the first call imports it.
            runCatching { app?.callAttr("set_debug_logging", BuildConfig.DEBUG) }
            // "Mask my voice", as the user left it (VoiceMaskPref).
            runCatching { app?.callAttr("set_voice_mask", VoiceMaskPref.on(appContext)) }

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

    /**
     * P1: the user, told what it costs, discards [jid]'s saved contact keys
     * after they would not open (`trust_unavailable`). Every contact of the
     * account is a first contact again. Only ever on that explicit request.
     */
    fun forgetAccountTrust(jid: String): Boolean =
        runCatching {
            requireApp().callAttr("forget_account_trust", jid)?.toBoolean() ?: false
        }.onFailure {
            // The Python side traces its own outcomes; a failure before it
            // (no engine, the call itself) is traced here, by type only.
            runCatching { note("identity", "forget_trust_call_failed", "warning",
                               OtrBridgeException.reportableCode(it) ?: it.javaClass.simpleName) }
        }.getOrDefault(false)

    /** Whether the engine is up: false before [initialize] and after
     *  [shutdown], which Sign out runs. */
    val isInitialized: Boolean get() = app != null

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

    private var controller: PyObject?
        get() = handles.controller
        set(value) { handles.controller = value }

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
        // The active network's DNS servers, for the clearnet SRV lookup
        // (android_bridge.dns_srv): Android has no /etc/resolv.conf, and
        // without SRV an account on yax.im is dialled at the wrong machine.
        // IP literals only; nothing about the account goes with them.
        runCatching {
            python.getModule("android_bridge.dns_srv")
                .callAttr("set_system_resolvers", activeDnsServers().toTypedArray())
        }
        val module = python.getModule("android_bridge.connection")
        // The old controller first: its dead transport is closed, and nothing
        // it reports later may touch the app the new one is about to use.
        controller?.let { old -> runCatching { old.callAttr("retire") } }
        controller = module.callAttr(
            "controller_for", requireApp(), jid, server, samHost, samPort)
        return connectionStatus()
    }

    private fun activeDnsServers(): List<String> = runCatching {
        val cm = appContext.getSystemService(android.net.ConnectivityManager::class.java)
        val lp = cm?.getLinkProperties(cm.activeNetwork)
        lp?.dnsServers?.mapNotNull { it.hostAddress } ?: emptyList()
    }.getOrDefault(emptyList())

    /**
     * Reach the prepared server and stop: DNS (SRV first), TCP, TLS with the
     * certificate verified, the XMPP stream, and registration discovery. No
     * sign-in, no account creation, no password. Never throws.
     */
    fun testServer(): ServerCheck {
        val ctl = controller ?: throw OtrBridgeException("not_prepared")
        val r = ctl.callAttr("test_server")
        fun str(k: String) = r?.callAttr("get", k)?.toString() ?: ""
        return ServerCheck(
            ok = r?.callAttr("get", "ok")?.toBoolean() ?: false,
            code = str("code").ifBlank { "unknown" },
            detail = str("detail"),
            reached = str("reached"),
        )
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
    /**
     * Said once after the last successful [register], not blocking: an
     * earlier account's contact keys under that username were discarded.
     * Blank otherwise. Kept beside the outcome, which stays ok/code/detail.
     */
    @Volatile
    var lastRegistrationNotice: String = ""
        private set

    fun register(password: String): RegistrationOutcome {
        lastRegistrationNotice = ""
        val ctl = controller ?: throw OtrBridgeException("not_prepared")
        return outcomeFrom(ctl.callAttr("register", password))
    }

    /**
     * Answer the CAPTCHA the last [register] reported, over the stream it left
     * open. Returns the same shape [register] does. Only meaningful after a
     * `captcha_required` outcome; otherwise the bridge answers a protocol
     * error.
     */
    fun submitCaptcha(answer: String): RegistrationOutcome {
        lastRegistrationNotice = ""
        val ctl = controller ?: throw OtrBridgeException("not_prepared")
        return outcomeFrom(ctl.callAttr("submit_captcha", answer))
    }

    private fun outcomeFrom(result: com.chaquo.python.PyObject?): RegistrationOutcome {
        fun str(k: String) = result?.callAttr("get", k)?.toString() ?: ""
        lastRegistrationNotice = str("notice")
        val cap = result?.callAttr("get", "captcha")
        val captcha = if (cap != null && !cap.toString().isNullOrBlank() &&
                          cap.toString() != "{}") {
            fun capStr(k: String) = cap.callAttr("get", k)?.toString() ?: ""
            val img = capStr("image_base64")
            if (img.isNotBlank())
                RegistrationCaptcha(
                    imageBase64 = img,
                    imageMime = capStr("image_mime").ifBlank { "image/png" },
                    instructions = capStr("instructions"),
                    answerVar = capStr("answer_var").ifBlank { "ocr" },
                )
            else null
        } else null
        return RegistrationOutcome(
            ok = result?.callAttr("get", "ok")?.toBoolean() ?: false,
            code = str("code").ifBlank { "unknown" },
            detail = str("detail"),
            captcha = captcha,
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

    /**
     * The refused I2P destination change for the prepared server, if any
     * (SECURITY_ISSUES X1). Null when there is none, or nothing prepared.
     */
    fun destinationChange(): ServerIdentityChange? {
        val ctl = controller ?: return null
        val d = ctl.callAttr("destination_change")
        fun str(k: String) = d?.callAttr("get", k)?.toString() ?: ""
        if (str("seen").isBlank() && str("unreadable").isBlank()) return null
        return ServerIdentityChange(str("server"), str("trusted"), str("seen"),
            unreadable = str("unreadable"))
    }

    /**
     * The user, shown both addresses, explicitly trusts [seen] for the
     * prepared server. Nothing connects here; the next Log in or Create
     * account uses it, and it becomes the pin only if that succeeds. Only the
     * destination that was actually refused can be approved (Python checks).
     * Returns null on success, or a sentence saying why not.
     */
    fun approveServerDestination(seen: String): String? {
        val ctl = controller ?: return "not_prepared"
        val r = ctl.callAttr("approve_server_destination", seen)
        val ok = r?.callAttr("get", "ok")?.toBoolean() ?: false
        return if (ok) null
               else r?.callAttr("get", "detail")?.toString() ?: "unknown"
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
                rooms += RoomSummary(entry(item, "jid"), entry(item, "name"),
                                     entry(item, "occupants").toIntOrNull(),
                                     secure = flag(item, "secure"),
                                     claimsSecure = flag(item, "claims_secure"),
                                     password = flag(item, "password"),
                                     hidden = flag(item, "hidden"))
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
    // -- blocking (XEP-0191) and spam reports (XEP-0377) ------------------------

    /** Block [jid] on the server (every device); [report] "spam"/"abuse" or "". */
    fun blockContact(jid: String, report: String = ""): RoomOutcome {
        val result = call("block_contact", jid, report) ?: return notPrepared()
        return outcomeOf(result)
    }

    fun unblockContact(jid: String): RoomOutcome {
        val result = call("unblock_contact", jid) ?: return notPrepared()
        return outcomeOf(result)
    }

    /** The server's block list, and whether the server can block at all. */
    fun blockedContacts(): Pair<List<String>, Boolean> {
        val result = call("blocked_contacts") ?: return emptyList<String>() to false
        val list = runCatching {
            listValue(result)?.asList()?.map { it.toString() }
        }.getOrNull() ?: emptyList()
        val supported = runCatching { result.callAttr("get", "supported")?.toBoolean() }
            .getOrNull() ?: false
        return list to supported
    }

    fun leaveRoom(room: String, nick: String): RoomOutcome {
        val result = call("leave_room", room, nick) ?: return notPrepared()
        return outcomeOf(result)
    }

    // ── avatars ──────────────────────────────────────────────────────────

    /**
     * Bare JID -> avatar id for every avatar the bridge holds. Cheap: no
     * network. Lines of "jid<TAB>id", parsed by [AvatarPixels.index].
     */
    fun avatarIndex(): Map<String, String> {
        val v = call("avatar_index") ?: return emptyMap()
        return runCatching {
            org.otrv4plus.android.chat.AvatarPixels.index(
                v.asList().map { it.toString() })
        }.getOrDefault(emptyMap())
    }

    /**
     * A contact's avatar as decoded PIXELS (RGBA), never the file they sent:
     * `android_bridge/avatar.py` validated and decoded it in bounded Python.
     * The base64 here is text decoding, not image decoding.
     */
    fun avatarImage(jid: String): AvatarImage? {
        val v = call("avatar_pixels", jid) ?: return null
        return runCatching {
            val rgba = android.util.Base64.decode(
                entry(v, "rgba_b64"), android.util.Base64.DEFAULT)
            AvatarImage(
                id = entry(v, "id"),
                width = v.callAttr("get", "width")?.toInt() ?: 0,
                height = v.callAttr("get", "height")?.toInt() ?: 0,
                rgba = rgba,
            )
        }.getOrNull()
    }

    /**
     * Publish our avatar: PNG bytes the app made by scaling and re-encoding
     * the user's own picture. The bridge checks it like anybody's.
     */
    fun setAvatar(png: ByteArray): RoomOutcome {
        val b64 = android.util.Base64.encodeToString(png, android.util.Base64.NO_WRAP)
        val result = call("set_avatar_b64", b64) ?: return notPrepared()
        return outcomeOf(result)
    }

    // ── the XMPP profile (vcard-temp) ────────────────────────────────────

    /** The editable fields, defined once, in `android_bridge/profile.py`. */
    fun profileFields(): List<ProfileField> {
        val v = call("profile_fields") ?: return emptyList()
        return runCatching {
            v.asList().mapNotNull { item ->
                val parts = item.toString().split('\t')
                if (parts.size != 4) null
                else ProfileField(parts[0], parts[1], parts[2].toIntOrNull() ?: 0,
                                  parts[3] == "1")
            }
        }.getOrDefault(emptyList())
    }

    /** A profile (ours when [jid] is blank), already sanitised by the bridge. */
    fun profileGet(jid: String = ""): Pair<RoomOutcome, Map<String, String>> {
        val result = call("profile_get_json", jid) ?: return notPrepared() to emptyMap()
        return outcomeOf(result) to jsonMap(entry(result, "value"))
    }

    /** Publish our profile. Returns what was actually published. */
    fun profileSet(values: Map<String, String>): Pair<RoomOutcome, Map<String, String>> {
        val json = org.json.JSONObject(values as Map<*, *>).toString()
        val result = call("profile_set_json", json) ?: return notPrepared() to emptyMap()
        return outcomeOf(result) to jsonMap(entry(result, "value"))
    }

    fun removeAvatar(): RoomOutcome {
        val result = call("remove_avatar") ?: return notPrepared()
        return outcomeOf(result)
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
            RoomOccupant(entry(it, "nick"), entry(it, "role"), entry(it, "affiliation"),
                         entry(it, "jid"))
        } ?: emptyList()
        return outcomeOf(result) to people
    }

    fun joinedRooms(): Pair<RoomOutcome, List<String>> {
        val result = call("joined_rooms") ?: return notPrepared() to emptyList()
        val rooms = listValue(result)?.asList()?.map { it.toString() }
            ?: emptyList()
        return outcomeOf(result) to rooms
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
        val wait = s.callAttr("get", "router_wait")
        fun waitInt(k: String) = wait?.callAttr("get", k)?.toInt()
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
            routerWaitedS = runCatching { waitInt("waited_s") }.getOrNull() ?: -1,
            routerWaitLimitS = runCatching { waitInt("limit_s") }.getOrNull() ?: 0,
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
    override fun wipeCrypto(): Boolean = try {
        val ctl = controller
        val a = app
        val report: PyObject? = when {
            ctl != null -> ctl.callAttr("wipe_crypto")
            a != null -> a.callAttr("wipe_crypto")
            else -> null
        }
        report == null || (report.callAttr("get", "errors")?.asList()?.isEmpty() ?: true)
    } catch (_: Throwable) {
        false
    }

    override fun deleteServerAccount(): String = try {
        val ctl = controller
        val a = app
        when {
            ctl != null -> ctl.callAttr("delete_server_account").toString()
            a != null -> a.callAttr("delete_server_account").toString()
            else -> "offline"
        }
    } catch (_: Throwable) {
        "unconfirmed"
    }

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
            verified = runCatching {
                report.callAttr("get", "verified", false)?.toBoolean() ?: false
            }.getOrDefault(false),
            survivors = int("survivors"),
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

    /** "Fingerprints match": the engine checks [fingerprint] is the session's
     *  key (constant time) and records it as confirmed (TrustDatabase). */
    fun trustPeer(peer: String, fingerprint: String): Boolean =
        runCatching { requireApp().callAttr("trust_peer", peer, fingerprint).toBoolean() }
            .getOrDefault(false)

    /** Forget the contact's pinned keys (fingerprint and post-quantum), so
     *  the next handshake pins what it sees. Asked for on the profile screen. */
    fun resetTrust(peer: String): Boolean =
        runCatching { requireApp().callAttr("reset_trust", peer).toBoolean() }
            .getOrDefault(false)

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

    /**
     * "Make Chat Deniable" (L1, SPEC §5.8): publish every MAC key of the
     * session with [peer], end it, and start a fresh one. "made_deniable" or
     * "no_session". No key material crosses: the engine sends the closing
     * messages itself.
     */
    fun makeChatDeniable(peer: String): String =
        runCatching { requireApp().callAttr("make_chat_deniable", peer).toString() }
            .getOrDefault("no_session")

    /** Where an OTRv4+ handshake with [peer] has got to. No key material. */
    fun handshakeStatus(peer: String): org.otrv4plus.android.crypto.HandshakeUi.Status =
        runCatching {
            val v = requireApp().callAttr("handshake_status", peer)
            fun int(k: String) = v.callAttr("get", k)?.toInt() ?: 0
            org.otrv4plus.android.crypto.HandshakeUi.Status(
                stage = v.callAttr("get", "stage")?.toString() ?: "idle",
                step = int("step"), steps = int("steps").takeIf { it > 0 } ?: 3,
                have = int("have"), of = int("of"), elapsed = int("elapsed"),
                eta = int("eta"), queued = int("queued"),
            )
        }.getOrDefault(org.otrv4plus.android.crypto.HandshakeUi.Status.IDLE)

    /** unknown / offline / checking / available / unavailable. */
    fun otrCapability(peer: String): String =
        runCatching { requireApp().callAttr("otr_capability", peer).toString() }
            .getOrDefault("unknown")

    override fun sendUserText(peer: String, body: String): SendOutcome = wrap {
        SendOutcome.fromName(
            requireApp().callAttr("send_user_text", peer, body).toString())
    }

    override fun sendUserText(peer: String, body: String, messageId: String): SendOutcome = wrap {
        SendOutcome.fromName(
            requireApp().callAttr("send_user_text", peer, body, messageId).toString())
    }

    override fun sendReply(peer: String, body: String, messageId: String, replyTo: String): SendOutcome = wrap {
        SendOutcome.fromName(
            requireApp().callAttr("send_user_text", peer, body, messageId, replyTo).toString())
    }

    override fun sendAction(peer: String, action: String, targetId: String, body: String,
                            emojis: List<String>, messageId: String): SendOutcome =
        runCatching {
            SendOutcome.fromName(requireApp().callAttr(
                "send_action", peer, action, targetId, body, emojis.toTypedArray(), messageId).toString())
        }.getOrDefault(SendOutcome.FAILED)

    override fun markDisplayed(peer: String) {
        runCatching { requireApp().callAttr("mark_displayed", peer) }
    }

    override fun sendChatStateTo(peer: String, state: String) {
        runCatching { requireApp().callAttr("set_chat_state", peer, state) }
    }

    override fun setPrivacy(chatStates: Boolean, readMarkers: Boolean) {
        runCatching { requireApp().callAttr("set_privacy", chatStates, readMarkers) }
    }

    override fun setClientActive(active: Boolean) {
        runCatching { requireApp().callAttr("set_client_active", active) }
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
            val event = runCatching { ChaquopyEvents.from(item) }.getOrNull() ?: continue
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
        OtrBridgeException.codeFromMessage(t.message)?.let { return it }
        val name = t.javaClass.simpleName
        return if (name.isBlank()) "bridge_error" else name
    }
}

/**
 * The "Mask my voice" choice, remembered between runs: one boolean in the
 * app's private preferences, nothing about any call or contact.
 */
object VoiceMaskPref {
    private const val PREFS = "voice_mask"
    private const val KEY = "on"

    fun on(context: android.content.Context): Boolean =
        context.getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE).getBoolean(KEY, false)

    fun set(context: android.content.Context, on: Boolean) {
        context.getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE)
            .edit().putBoolean(KEY, on).apply()
    }
}

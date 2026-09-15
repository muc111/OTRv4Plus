plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.chaquo.python")
}

// The Rust core's version, read rather than restated. versionName carried
// "core.10.14.0" while Rust/Cargo.toml said 0.10.28.
val rustCoreVersion: String = rootProject.projectDir.parentFile
    .resolve("Rust/Cargo.toml").readLines()
    .first { it.trimStart().startsWith("version") }
    .substringAfter('"').substringBefore('"')

// Where the generated copy of NOTICE lands before it is packaged as an asset.
// Declared here because the `android { sourceSets }` block below reads it.
val noticeAssetDir: Provider<Directory> =
    layout.buildDirectory.dir("generated/notice/assets")

android {
    namespace = "org.otrv4plus.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.otrv4plus.android"

        // minSdk is set by an actual requirement, not preference:
        //   * AAudio (otrv4plus_audio.py's Android backend) needs API 26.
        //   * BiometricPrompt with a CryptoObject, and StrongBox detection,
        //     are usable from API 28.
        //   * Chaquopy itself supports API 24+.
        // 26 is the floor the audio backend imposes; raising it to 28 would buy
        // simpler biometric/StrongBox handling at the cost of Android 8.0
        // devices. Left at 26, with the biometric path feature-detected.
        minSdk = 26
        targetSdk = 35
        versionCode = 7
        // core.10.14.0 was wrong for sixteen releases; the Rust core is read
        // from Rust/Cargo.toml so it cannot drift again.
        versionName = "0.3.0-phase2+core.$rustCoreVersion"

        // Which build this is, surfaced in the diagnostic report.
        //
        // Three reports in a row arrived byte-identical and there was no way
        // to tell whether the fix under test had actually been installed or
        // whether the previous APK had been re-run. A report that cannot
        // identify its own build wastes a round trip every time, and the
        // round trip is a person reinstalling an app by hand.
        //
        // CI sets OTRV4PLUS_BUILD_ID to the short commit; a local build says
        // so rather than inventing a number.
        buildConfigField("String", "BUILD_ID",
            "\"" + (System.getenv("OTRV4PLUS_BUILD_ID") ?: "local") + "\"")

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            // arm64-v8a is the production target. x86_64 is kept for emulator
            // work. armeabi-v7a is deliberately NOT enabled yet: the Rust core
            // pins pqcrypto-mlkem/mldsa to the portable C reference to avoid
            // SIGILL on some aarch64 NEON paths, and the 32-bit build has never
            // been exercised. Adding it is a Phase 3 task with its own testing.
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    // Per-ABI APK splits are OFF, and this is a forced choice rather than a
    // preference.
    //
    // AGP refuses both at once:
    //
    //   Conflicting configuration : 'arm64-v8a,x86_64' in ndk abiFilters
    //   cannot be present when splits abi filters are set : x86_64,arm64-v8a
    //
    // Found by the first CI run that ever configured this project. The two
    // blocks named the same two ABIs, so nothing was ambiguous about the
    // INTENT -- AGP simply will not take both.
    //
    // abiFilters wins because the two are not equally important. Splitting is
    // a download-size optimisation: with an embedded interpreter it saves
    // tens of megabytes per install, which matters and is recoverable later.
    // abiFilters is the guard that keeps armeabi-v7a out of a build, and the
    // reason for that guard is in the block below: the 32-bit build has never
    // been exercised and the pqcrypto pin exists to avoid SIGILL. Trading a
    // safety property for an install-size win is the wrong way round.
    //
    // Revisit in Phase 3, when armeabi-v7a is decided either way: at that
    // point the ABI set is settled and splits can express it alone.
    //
    // splits { abi { ... } }  -- see above

    buildTypes {
        debug {
            isMinifyEnabled = false
            // Gates the developer diagnostics screen. Release has no such field
            // set to true, and the screen's source lives in src/debug/ so it is
            // not merely hidden -- it is not compiled into release at all.
            buildConfigField("boolean", "DEV_DIAGNOSTICS", "true")
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            buildConfigField("boolean", "DEV_DIAGNOSTICS", "false")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    // No composeOptions block. `kotlinCompilerExtensionVersion` selected the
    // old standalone Compose compiler and is ignored from Kotlin 2.0 -- the
    // version now comes from the Compose plugin applied above. Leaving the
    // old 1.5.15 pin here would be a number nothing reads.

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        // WHAT THIS DOES NOT DO: remove anyone's attribution.
        //
        // `AL2.0` and `LGPL2.1` under META-INF are zero-byte MARKER STUBS that
        // kotlinx-coroutines ships to declare which of its dual-licence options
        // a consumer took. They carry no licence text and no copyright line.
        // Several dependencies ship the same two paths, so the APK packager
        // hits a duplicate-resource conflict and the build fails; excluding
        // them is the standard fix and is what every AGP template does.
        //
        // Actual attribution is NOT in those stubs and is not affected by this
        // line. It lives in the repository's NOTICE file, which is copied into
        // the APK's assets by :app:syncNoticeAsset below and rendered by the
        // licences screen (ui/AboutScreen.kt). Removing a real notice would be
        // a distribution defect; removing a duplicate empty marker is not.
        resources.excludes += setOf("/META-INF/{AL2.0,LGPL2.1}")
    }

    sourceSets {
        getByName("main") {
            // NOTICE reaches the APK from here. Generated rather than
            // committed under src/, for the same reason the Python sources
            // are: a second copy in the tree goes stale and nothing fails.
            assets.srcDir(noticeAssetDir)
        }
    }
}

chaquopy {
    defaultConfig {
        // HARD REQUIREMENT, not a preference: otrv4+.py uses PEP 701 f-string
        // syntax (f"{x !r }") that does not parse on 3.11 or earlier. Lowering
        // this to make the build easier will fail at import with a SyntaxError.
        version = "3.12"

        pip {
            // WHY --no-deps, AND WHY EVERY DISTRIBUTION IS NAMED BELOW
            // --------------------------------------------------------
            // slixmpp declares `aiodns>=3.2.0` as a hard requirement -- not an
            // extra, in every release from 1.9.0 onwards -- and aiodns pulls
            // pycares, which compiles c-ares from source with cmake. Chaquopy
            // has no wheel for it and cannot compile native code, so the build
            // dies during requirement resolution:
            //
            //   ERROR: Failed to install pycares<6,>=5.0.0 (from aiodns>=3.2.0
            //          ->slixmpp)
            //   CMake Error: Chaquopy_cannot_compile_native_code.
            //
            // Removing an `install("aiodns")` line does not help: the request
            // comes from slixmpp's own metadata. pip has no way to drop a
            // single dependency, and `install()` takes one requirement, so
            // --no-deps is the only lever and it is necessarily global.
            //
            // The cost of --no-deps is that a dependency we fail to name is no
            // longer a build error -- it is an ImportError on a handset. So
            // the list below is the FULL closure, and `verify-python-closure`
            // in .github/workflows/android.yml re-resolves it on every CI run
            // and fails if anything is missing.
            //
            // The compensation is that this is now an exact manifest: nothing
            // reaches the APK without being written down here, which for this
            // app is worth more than the convenience it costs.
            options("--no-deps")

            // Where the Rust core comes from. It is not on any index: it is
            // built from Rust/ for each ABI by the `rust` job in
            // .github/workflows/android.yml, or locally with
            //
            //     maturin build --release --target aarch64-linux-android \
            //       --features pyo3/extension-module --interpreter python3.12
            //
            // and the resulting wheels dropped in android/app/wheels/.
            //
            // The tags line up without any retagging, which is worth writing
            // down because it looks like it should not: maturin emits
            // `otrv4_core-0.10.28-cp39-abi3-android_26_arm64_v8a.whl`, and
            // Chaquopy asks pip for `--platform android_26_arm64_v8a` because
            // minSdk is 26. abi3 covers the cp39-vs-3.12 half.
            //
            // If the directory is empty, pip fails with "Could not find a
            // version that satisfies the requirement otrv4_core". That is the
            // correct outcome -- an APK without the crypto core is not this
            // app -- but it is an unhelpful sentence, so: build the wheels.
            options("--find-links", project.file("wheels").absolutePath)

            // -- asked for directly ------------------------------------------
            //
            // otrv4_core: the Rust core. Every cryptographic operation in the
            // app is behind it; there is no Python fallback and has not been
            // since v10.13.2.
            install("otrv4_core")
            // PySocks: imported at module scope by otrv4+.py. Pure Python.
            install("PySocks")
            // slixmpp: the XMPP transport. Pure Python, built from an sdist.
            install("slixmpp")
            // argon2-cffi: the at-rest KDF. Without it the engine falls back
            // to scrypt and warns. Chaquopy has prebuilt android wheels for
            // the whole cffi chain, so a resolution failure here is a real
            // finding rather than a reason to drop it.
            install("argon2-cffi")

            // -- required by the above, and now named because of --no-deps ---
            //
            // slixmpp -> pyasn1, pyasn1-modules (both pure Python).
            install("pyasn1")
            install("pyasn1-modules")
            // argon2-cffi -> argon2-cffi-bindings -> cffi -> pycparser, and
            // cffi's android wheel -> chaquopy-libffi. The last of those is
            // Chaquopy's own packaging of libffi; it is named here only
            // because --no-deps stops cffi asking for it. If Chaquopy ever
            // renames it the build fails loudly at this line, which is the
            // failure mode to want.
            install("argon2-cffi-bindings")
            install("cffi")
            install("pycparser")
            install("chaquopy-libffi")

            // -- deliberately absent -----------------------------------------
            //
            // aiodns / pycares. Dropping them costs nothing HERE:
            //   * slixmpp treats aiodns as optional at RUNTIME. resolver.py
            //     sets AIODNS_AVAILABLE = False and logs "Could not find
            //     aiodns package" before falling back to getaddrinfo without
            //     SRV support.
            //   * this client never resolves a name anyway. An .i2p address is
            //     reached through the local SAM bridge -- the connection is to
            //     127.0.0.1 on a port the bridge picked -- so there is no SRV
            //     lookup to lose.
            //
            // If a clearnet XMPP transport is ever added, SRV resolution
            // becomes real and this decision needs revisiting.
        }

        // otrv4_core is NOT installed from an index. It is the Rust wheel built
        // from Rust/ for this ABI:
        //     maturin build --release --target aarch64-linux-android
        // and placed where staticProxy/pip can see it. Building it needs the
        // Android NDK, because pqcrypto-mlkem/mldsa compile C reference code.
    }

    sourceSets {
        getByName("main") {
            // The orchestration layer and the bridge package are copied here by
            // the :app:syncPythonSources task below rather than duplicated in
            // the repository, so there is exactly one copy of otrv4+.py.
            srcDir("src/main/python")
        }
    }
}

// Keep the APK's Python sources in step with the repository root instead of
// maintaining a second copy that can silently drift.
val syncPythonSources by tasks.registering(Copy::class) {
    description = "Copy the OTRv4+ orchestration layer and bridge into the APK source set."
    group = "build"

    val repoRoot = rootProject.projectDir.parentFile

    from(repoRoot) {
        include(
            "otrv4+.py",
            "otrv4plus_xmpp.py",
            // The rest is the module-scope import closure of otrv4+.py and
            // otrv4plus_xmpp.py, computed rather than remembered.
            //
            // It had drifted badly: seven of these were missing, including
            // otrv4plus_coreapi and otrv4plus_smpflow, which the XMPP client
            // imports on its first two lines. Every one of them is an
            // ImportError at launch rather than a missing feature, and no
            // test could catch it because nothing here has ever built an APK.
            // Re-derive with:
            //   python3 - <<'EOF'
            //   import ast, os
            //   seen, q = set(), ["otrv4plus_xmpp.py", "otrv4+.py"]
            //   while q:
            //       f = q.pop()
            //       if f in seen or not os.path.exists(f): continue
            //       seen.add(f)
            //       for n in ast.walk(ast.parse(open(f).read())):
            //           ms = ([a.name for a in n.names] if isinstance(n, ast.Import)
            //                 else [n.module] if isinstance(n, ast.ImportFrom) and n.module
            //                 else [])
            //           q += [m + ".py" for m in ms if m.startswith("otrv4plus_")]
            //   print(sorted(seen))
            //   EOF
            "otrv4plus_address.py",
            "otrv4plus_admin.py",
            "otrv4plus_audio.py",
            "otrv4plus_coreapi.py",
            "otrv4plus_filetransfer.py",
            "otrv4plus_identity.py",
            "otrv4plus_log.py",
            "otrv4plus_smpflow.py",
            "otrv4plus_tip.py",
            "otrv4plus_trade.py",
            "otrv4plus_voice.py",
        )
    }
    // The SAME file again, under a name Python can import.
    //
    // `otrv4+.py` cannot be imported by name -- `+` is not legal in an
    // identifier -- so the bridge used to locate it by probing the filesystem.
    // That cannot work inside an APK: Chaquopy packages Python sources into a
    // zip under assets/ and serves them through its own importer, so there is
    // no file for os.path.isfile() to find.
    //
    // Copying it in as `otrv4_.py` makes it an ordinary module, which
    // Chaquopy's importer serves like any other. bootstrap.load_orchestration
    // asks for it by name first and only falls back to the path probe, which
    // remains the route on desktop and under Termux where `otrv4_.py` is a
    // symlink rather than a copy.
    //
    // The repository keeps exactly one copy; the second exists only inside the
    // build output, which is why this is a rename here rather than a file.
    from(repoRoot) {
        include("otrv4+.py")
        rename { "otrv4_.py" }
    }
    from(repoRoot.resolve("android_bridge")) {
        into("android_bridge")
        include("*.py")
    }
    into(layout.projectDirectory.dir("src/main/python"))

    // Never package the TUI, the IRC clients, the WeeChat plugin or the
    // test-only SMP shim. smp_engine_compat.py in particular re-implements the
    // SMP KDF in pure Python and must not reach a device.
    exclude("otrv4plus_tui.py", "weechat_otrv4plus.py", "smp_engine_compat.py",
            "otrv4_testlib.py", "integrate_voice_v3.py")
}

tasks.named("preBuild") { dependsOn(syncPythonSources) }

// preBuild is not enough, and the reason is worth writing down because the
// symptom appears nowhere near the cause:
//
//   Task ':app:mergeDebugPythonSources' uses this output of task
//   ':app:syncPythonSources' without declaring an explicit or implicit
//   dependency.
//
// syncPythonSources WRITES src/main/python; Chaquopy's merge*PythonSources
// READS it as a source directory. Gradle 8 requires an edge between those two
// tasks specifically -- ordering them both after preBuild says nothing about
// their order relative to each other, so Gradle refuses to guess and fails the
// build. Without the edge the tasks could legitimately run in either order,
// and the losing order packages an empty source set: an APK that builds
// cleanly and has no Python in it.
//
// Matched by name rather than by variant because there is one per build type
// (mergeDebugPythonSources, mergeReleasePythonSources), and Chaquopy registers
// them from the variant API after this script is evaluated -- tasks.matching
// is a live view, so configureEach still reaches them.
tasks.matching { it.name.matches(Regex("merge[A-Z]\\w*PythonSources")) }
    .configureEach { dependsOn(syncPythonSources) }

// ─────────────────────────────────────────────────────────────────────────────
// NOTICE, into the APK
//
// Every third-party component in this build is permissive, and every one of
// them requires its notice to travel with the binary. NOTICE (generated by
// tools/generate_notice.py) is that file, and until now it existed only in the
// repository -- which discharges nothing for someone who receives an APK.
//
// Copied rather than committed under src/main/assets for the same reason
// syncPythonSources copies rather than duplicates: one copy in the repository,
// regenerated into the build output, so it cannot drift.
// ─────────────────────────────────────────────────────────────────────────────
val syncNoticeAsset by tasks.registering(Copy::class) {
    description = "Copy the third-party NOTICE into the APK's assets."
    group = "build"

    from(rootProject.projectDir.parentFile) { include("NOTICE") }
    into(noticeAssetDir)

    // Fail loudly rather than shipping an APK whose licences screen is empty.
    // A missing NOTICE is an attribution defect, and the only moment it is
    // cheap to notice is now.
    doFirst {
        val src = rootProject.projectDir.parentFile.resolve("NOTICE")
        require(src.isFile && src.length() > 0L) {
            "NOTICE is missing or empty at ${src.absolutePath}. The APK must " +
                "carry third-party attribution. Regenerate it with: " +
                "python3 tools/generate_notice.py > NOTICE"
        }
    }
}

// Same edge, same reason, as the PythonSources case above: the asset merge
// READS the directory this task WRITES, and Gradle will not infer the order.
// Matched by name because there is one merge task per variant and AGP
// registers them after this script is evaluated.
tasks.matching { it.name.matches(Regex("merge[A-Z]\\w*Assets")) }
    .configureEach { dependsOn(syncNoticeAsset) }

// ─────────────────────────────────────────────────────────────────────────────
// Dependency licence guard
//
// The Rust half of this project has had a copyleft guard since v10.17.2:
// tests/test_licence_declarations_agree.py walks `cargo metadata` and fails if
// a crate with no permissive option enters the graph. The Android half had
// nothing equivalent, so an `implementation("...")` of an LGPL or EPL library
// would have passed every check in the repository.
//
// That matters more here than it looks. One copyleft dependency in the shipped
// graph does not merely add an obligation: it makes the COMMERCIAL half of the
// dual licence unsellable, because the project could no longer license every
// line it distributes under both halves. The audit that chose AGPL-3.0 turned
// on the finding that nothing in the tree imposed copyleft except the
// project's own licence. This task is what keeps that finding true.
//
// METHOD -- and why it is not a grep over build.gradle.kts:
//
//   1. Ask Gradle for the RESOLVED graph of the runtime classpaths, via
//      `incoming.resolutionResult`. That is the post-conflict-resolution set
//      of components actually on the classpath, so it includes transitive
//      dependencies nothing in this file names, and it reflects the versions
//      Gradle really chose rather than the ones written down.
//   2. Fetch each module's POM through a detached configuration and read
//      <licenses><license><name>. Where a POM declares none, walk <parent>,
//      because Maven licence declarations are commonly inherited.
//   3. Classify. Multiple <license> entries are a CHOICE, exactly as an SPDX
//      `OR` is in the cargo check -- if any option is permissive the module is
//      fine, and only a module with no permissive option is an offender.
//   4. Fail closed. A module whose licence cannot be determined is an
//      offender, not a pass: "we could not tell" is the state this guard
//      exists to surface.
//
// Test-only dependencies are NOT checked, and deliberately so. JUnit is
// Eclipse Public License -- weak copyleft -- and is perfectly fine, because it
// is not in the artifact anyone receives. The distinction is made by asking
// Gradle for the runtime classpaths only; it is not a hand-maintained list.
// ─────────────────────────────────────────────────────────────────────────────

/** Licence names that grant what this project needs, with no reciprocity. */
// `\b` around the short ones is load-bearing: without it `mit` matches
// "permit" and `isc` matches "miscellaneous", and an over-broad permissive
// pattern is how a guard like this silently stops guarding.
//
// Proprietary vendor terms are deliberately NOT listed here, including the
// Android SDK licence. They are not permissive, and a module carrying them
// should reach a person as `unknown` rather than be waved through.
val permissiveLicence = Regex(
    """apache|\bmit\b|\bbsd|\bisc\b|python software foundation|\bpsf\b|""" +
        """\bzlib\b|unicode|public domain|\bcc0\b|bouncy castle|\bw3c\b|""" +
        """universal permissive|\bupl\b""",
    RegexOption.IGNORE_CASE,
)

/** Licence names that impose reciprocity, weak or strong. */
val copyleftLicence = Regex(
    """\bgpl\b|\blgpl\b|\bagpl\b|gnu general|gnu lesser|gnu affero|affero|""" +
        """mozilla public|\bmpl\b|eclipse public|\bepl\b|\bcddl\b|""" +
        """common development and distribution|european union public|""" +
        """\beupl\b|\bsspl\b|server side public|business source|\bbusl\b""",
    RegexOption.IGNORE_CASE,
)

/** `permissive`, `copyleft`, or `unknown` for one module's declared names. */
fun classifyLicences(names: List<String>): String {
    val declared = names.map { it.trim() }.filter { it.isNotEmpty() }
    if (declared.isEmpty()) return "unknown"
    // A disjunction is a choice and we take the permissive branch -- the same
    // rule TestNoCopyleftDependencyCreepsIn applies to an SPDX `OR`.
    if (declared.any { permissiveLicence.containsMatchIn(it) &&
            !copyleftLicence.containsMatchIn(it) }) return "permissive"
    if (declared.any { copyleftLicence.containsMatchIn(it) }) return "copyleft"
    return "unknown"
}

tasks.register("checkRuntimeDependencyLicences") {
    description = "Fail if a copyleft dependency enters the shipped Android graph."
    group = "verification"

    doLast {
        // The classifier, checked against known answers before it is trusted.
        // A guard that has been quietly neutered -- an over-broad permissive
        // pattern, an inverted test -- passes everything and reads as green,
        // which is the failure mode that matters for this kind of check.
        val selfTest = listOf(
            listOf("Apache License, Version 2.0") to "permissive",
            listOf("The Apache Software License, Version 2.0") to "permissive",
            listOf("MIT License") to "permissive",
            listOf("BSD 3-Clause License") to "permissive",
            listOf("GNU General Public License, version 3") to "copyleft",
            listOf("GNU Lesser General Public License v2.1") to "copyleft",
            listOf("GNU Affero General Public License v3.0") to "copyleft",
            listOf("Eclipse Public License 2.0") to "copyleft",
            listOf("Mozilla Public License 2.0") to "copyleft",
            // The disjunction rule, both ways round.
            listOf("GPL-2.0-with-classpath-exception", "Apache License 2.0")
                to "permissive",
            emptyList<String>() to "unknown",
            listOf("Some Bespoke Vendor Terms") to "unknown",
        )
        val wrong = selfTest.filter { (names, want) ->
            classifyLicences(names) != want
        }
        require(wrong.isEmpty()) {
            "the licence classifier itself is wrong, so its verdict on the " +
                "real graph means nothing: " + wrong.joinToString { (n, want) ->
                    "$n -> ${classifyLicences(n)}, expected $want"
                }
        }

        // Both runtime classpaths. `release` is the product; `debug` matters
        // too, because the debug APK is what the release job publishes as the
        // rolling experimental build, and debugImplementation adds ui-tooling
        // to it.
        val classpaths = listOf("debugRuntimeClasspath", "releaseRuntimeClasspath")
            .mapNotNull { configurations.findByName(it) }
        require(classpaths.isNotEmpty()) {
            "no runtime classpath found to check -- the guard would pass " +
                "vacuously, which is worse than failing"
        }

        // The ARTIFACT set, not the component set. A BOM (compose-bom) is a
        // resolved component that contributes no code, and asking it for a
        // licence would produce an `unknown` verdict about a file nobody
        // receives. Iterating artifacts keeps the question to "what is
        // actually in the APK".
        val modules = linkedMapOf<String, String>()
        for (cfg in classpaths) {
            for (artifact in cfg.incoming.artifacts.artifacts) {
                val id = artifact.id.componentIdentifier
                if (id is org.gradle.api.artifacts.component.ModuleComponentIdentifier) {
                    val coord = "${id.group}:${id.module}:${id.version}"
                    modules[coord] = cfg.name
                }
            }
        }

        /** Resolve `group:name:version@pom` files, keyed by coordinate. */
        fun pomFiles(coords: Collection<String>): Map<String, java.io.File> {
            if (coords.isEmpty()) return emptyMap()
            val deps = coords
                .map { dependencies.create("$it@pom") }
                .toTypedArray()
            val cfg = configurations.detachedConfiguration(*deps)
            cfg.isTransitive = false
            // Lenient: one unpublished POM must not abort the whole check.
            // The module it belonged to then has no readable licence and is
            // reported as `unknown`, which fails the guard anyway -- but it
            // fails naming that module rather than as a resolution error.
            val found = cfg.resolvedConfiguration.lenientConfiguration.artifacts
            return found.associate {
                val m = it.moduleVersion.id
                "${m.group}:${m.name}:${m.version}" to it.file
            }
        }

        fun textOf(node: org.w3c.dom.Element, tag: String): String? =
            node.getElementsByTagName(tag).item(0)?.textContent?.trim()

        val builder = javax.xml.parsers.DocumentBuilderFactory.newInstance()
            .also { it.isNamespaceAware = false }
            .newDocumentBuilder()

        /** Declared licence names, following <parent> when a POM declares none. */
        fun licencesFor(
            coord: String,
            pomsByCoord: MutableMap<String, java.io.File>,
        ): List<String> {
            var current: String? = coord
            var hops = 0
            while (hops < 5) {
                // Pulled into a non-null local: `current` is a captured var,
                // so it does not smart-cast, and Map<String, _> will not take
                // a String? key.
                val at: String = current ?: return emptyList()
                val file = pomsByCoord[at]
                    ?: pomFiles(listOf(at))[at]?.also { pomsByCoord[at] = it }
                    ?: return emptyList()
                val doc = builder.parse(file)
                val names = mutableListOf<String>()
                val entries = doc.getElementsByTagName("license")
                for (i in 0 until entries.length) {
                    val el = entries.item(i) as? org.w3c.dom.Element ?: continue
                    val name = textOf(el, "name") ?: textOf(el, "url")
                    if (!name.isNullOrBlank()) names.add(name)
                }
                if (names.isNotEmpty()) return names
                // None here; inherit from the parent POM if there is one.
                val parents = doc.getElementsByTagName("parent")
                val parent = parents.item(0) as? org.w3c.dom.Element
                    ?: return emptyList()
                val g = textOf(parent, "groupId")
                val a = textOf(parent, "artifactId")
                val v = textOf(parent, "version")
                current = if (g != null && a != null && v != null) "$g:$a:$v" else null
                hops++
            }
            return emptyList()
        }

        val poms = pomFiles(modules.keys).toMutableMap()
        val verdicts = linkedMapOf<String, Pair<String, List<String>>>()
        for (coord in modules.keys) {
            val names = try {
                licencesFor(coord, poms)
            } catch (e: Exception) {
                logger.warn("could not read the POM for $coord: ${e.message}")
                emptyList()
            }
            verdicts[coord] = classifyLicences(names) to names
        }

        val report = layout.buildDirectory
            .file("reports/licences/runtime-dependencies.txt").get().asFile
        report.parentFile.mkdirs()
        report.writeText(buildString {
            appendLine("Resolved Android runtime dependency licences")
            appendLine("Classpaths: " + classpaths.joinToString { it.name })
            appendLine("Modules: ${verdicts.size}")
            appendLine()
            verdicts.entries.sortedBy { it.key }.forEach { (coord, v) ->
                appendLine("%-11s %s".format(v.first, coord))
                v.second.forEach { appendLine("            $it") }
            }
        })

        val offenders = verdicts.filterValues { it.first != "permissive" }
        if (offenders.isNotEmpty()) {
            throw GradleException(buildString {
                appendLine(
                    "Dependency licence guard failed. The shipped Android " +
                        "graph must contain only permissive third-party code: " +
                        "one copyleft dependency here makes the commercial " +
                        "half of the dual licence unsellable.")
                appendLine()
                offenders.forEach { (coord, v) ->
                    appendLine("  ${v.first}: $coord  ${v.second}")
                }
                appendLine()
                appendLine("An `unknown` verdict is NOT a pass: it means the " +
                    "POM declared no licence this guard could read. Check it " +
                    "by hand and, if it is genuinely permissive, add the " +
                    "licence name to permissiveLicence in this file with a " +
                    "comment saying what was checked.")
                appendLine("Full report: $report")
            })
        }
        logger.lifecycle(
            "Dependency licence guard: ${verdicts.size} resolved modules, " +
                "all permissive. Report: $report")
    }
}

// Part of `check`, so it runs with the tests rather than only when someone
// remembers it exists.
tasks.named("check") { dependsOn("checkRuntimeDependencyLicences") }

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.10.01")
    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.navigation:navigation-compose:2.8.4")

    debugImplementation("androidx.compose.ui:ui-tooling")

    testImplementation("junit:junit:4.13.2")
    // The security layer (AppLockManager, AttemptThrottle, LockState) imports
    // nothing from Android, so its tests run as plain JVM unit tests.
    testImplementation("org.jetbrains.kotlin:kotlin-test")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
}

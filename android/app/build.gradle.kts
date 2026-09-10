plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.chaquo.python")
}

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
        versionName = "0.3.0-phase2+core.10.14.0"

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
        resources.excludes += setOf("/META-INF/{AL2.0,LGPL2.1}")
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

            // -- asked for directly ------------------------------------------
            //
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

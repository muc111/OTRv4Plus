plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
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
        versionCode = 5
        versionName = "0.3.0-phase2+core.10.13.2"

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

    // Ship per-ABI APKs rather than one fat artifact carrying every CPython and
    // every otrv4_core .so. With an embedded interpreter the difference is tens
    // of megabytes per install.
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "x86_64")
            isUniversalApk = false
        }
    }

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

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.15"
    }

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
            // PySocks: imported at module scope by otrv4+.py. Pure Python.
            install("PySocks")
            // slixmpp + aiodns: the XMPP transport. Verify these resolve for
            // every enabled ABI early -- this is the dependency most likely to
            // need a native build.
            install("slixmpp")
            install("aiodns")
            // argon2-cffi: optional. Without it the engine falls back to
            // scrypt and warns. Wanted on Android for the at-rest KDF; needs a
            // native build, so treat a resolution failure here as a real
            // finding rather than dropping the dependency.
            install("argon2-cffi")
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
            "otrv4plus_log.py",
            "otrv4plus_voice.py",
            "otrv4plus_audio.py",
            "otrv4plus_xmpp.py",
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

// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
import org.jetbrains.compose.desktop.application.dsl.TargetFormat
import org.jetbrains.kotlin.compose.compiler.gradle.ComposeFeatureFlag

plugins {
    kotlin("jvm") version "2.0.21"
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21"
    id("org.jetbrains.compose") version "1.7.3"
}

group = "org.otrv4plus"
// The desktop app's own version (docs/VERSIONING.md). Not the Rust core's: it
// started at the core's 0.13.1 only so packages already installed upgrade.
// The README badge is tested against this line.
version = "0.14.2"

dependencies {
    implementation(compose.desktop.currentOs)
    implementation(compose.material3)
    implementation(compose.materialIconsExtended)
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-swing:1.9.0")
    testImplementation(kotlin("test"))
}

kotlin { jvmToolchain(21) }

// STRONG SKIPPING OFF. Kotlin 2.0.20+ turns it on by default, and then a
// composable whose arguments look unchanged is skipped. This UI reads the
// model's plain fields (drafts, the open chat, the chat list) and is
// redrawn by `AppModel.revision`, which only the top of each screen reads:
// skipped children never saw the change. Device report, 2026-10-20: typed
// text never appeared in the message box, and clicking another chat did
// nothing. With it off, every composable taking the (unstable) AppModel is
// redrawn with its parent, as the screens were written for.
composeCompiler {
    featureFlags.add(ComposeFeatureFlag.StrongSkipping.disabled())
}

// Shared with the Android app, compiled from ITS tree: the engine models and
// events (bridge/OtrCore.kt), the chat state machine, the security wording,
// the connection rules and the theme. Plain Kotlin -- none of these import
// Android -- so the two apps cannot drift apart on what a state means.
// tests/test_desktop_shared_sources.py checks the list stays Android-free.
val sharedFromAndroid = listOf(
    "org/otrv4plus/android/bridge/OtrCore.kt",
    "org/otrv4plus/android/chat/AccountScope.kt",
    "org/otrv4plus/android/chat/Attention.kt",
    "org/otrv4plus/android/chat/AccountSessions.kt",
    "org/otrv4plus/android/chat/AvatarPixels.kt",
    "org/otrv4plus/android/chat/ChatDeletion.kt",
    "org/otrv4plus/android/chat/ChatKinds.kt",
    "org/otrv4plus/android/chat/ChatModels.kt",
    "org/otrv4plus/android/chat/ChatState.kt",
    "org/otrv4plus/android/chat/DeletedConversations.kt",
    "org/otrv4plus/android/chat/FailureText.kt",
    "org/otrv4plus/android/chat/GroupInvitePicker.kt",
    "org/otrv4plus/android/chat/GroupText.kt",
    "org/otrv4plus/android/chat/InboundAlerts.kt",
    "org/otrv4plus/android/chat/Location.kt",
    "org/otrv4plus/android/chat/MessageCodec.kt",
    "org/otrv4plus/android/chat/MessageStore.kt",
    "org/otrv4plus/android/chat/OnlineUsers.kt",
    "org/otrv4plus/android/chat/PersistentMessageStore.kt",
    "org/otrv4plus/android/chat/PostLogin.kt",
    "org/otrv4plus/android/chat/ProfileIdentity.kt",
    "org/otrv4plus/android/chat/ProfileText.kt",
    "org/otrv4plus/android/chat/RoomAddress.kt",
    "org/otrv4plus/android/chat/RoomDeletion.kt",
    "org/otrv4plus/android/chat/RoomPassword.kt",
    "org/otrv4plus/android/chat/RoomPeople.kt",
    "org/otrv4plus/android/chat/RowSecurity.kt",
    "org/otrv4plus/android/chat/SavedContacts.kt",
    "org/otrv4plus/android/chat/SoundPolicy.kt",
    "org/otrv4plus/android/chat/VoiceNotes.kt",
    "org/otrv4plus/android/connection/ConnectProblem.kt",
    "org/otrv4plus/android/connection/LinkPhase.kt",
    "org/otrv4plus/android/connection/LoginProgress.kt",
    "org/otrv4plus/android/connection/PasswordChange.kt",
    "org/otrv4plus/android/connection/ReconnectPolicy.kt",
    "org/otrv4plus/android/connection/RouterChoice.kt",
    "org/otrv4plus/android/connection/SignIn.kt",
    "org/otrv4plus/android/connection/Startup.kt",
    "org/otrv4plus/android/crypto/CallAlert.kt",
    "org/otrv4plus/android/crypto/CallUi.kt",
    "org/otrv4plus/android/crypto/EncryptionLauncher.kt",
    "org/otrv4plus/android/crypto/EncryptionProvider.kt",
    "org/otrv4plus/android/crypto/EncryptionSelector.kt",
    "org/otrv4plus/android/crypto/ExifReader.kt",
    "org/otrv4plus/android/crypto/FileExport.kt",
    "org/otrv4plus/android/crypto/FileFacts.kt",
    "org/otrv4plus/android/crypto/HandshakeUi.kt",
    "org/otrv4plus/android/crypto/HiddenData.kt",
    "org/otrv4plus/android/crypto/MetadataChoice.kt",
    "org/otrv4plus/android/crypto/MicPermission.kt",
    "org/otrv4plus/android/crypto/MlsProvider.kt",
    "org/otrv4plus/android/crypto/MlsTransport.kt",
    "org/otrv4plus/android/crypto/Omemo2Provider.kt",
    "org/otrv4plus/android/crypto/OtrAvailability.kt",
    "org/otrv4plus/android/crypto/OtrV4PlusProvider.kt",
    "org/otrv4plus/android/crypto/PdfScan.kt",
    "org/otrv4plus/android/crypto/SafeView.kt",
    "org/otrv4plus/android/crypto/SecurityLevel.kt",
    "org/otrv4plus/android/crypto/TransferUi.kt",
    "org/otrv4plus/android/crypto/Verification.kt",
    "org/otrv4plus/android/security/AppDataWipe.kt",
    "org/otrv4plus/android/security/AppLockManager.kt",
    "org/otrv4plus/android/security/AttemptThrottle.kt",
    "org/otrv4plus/android/security/CredentialStore.kt",
    "org/otrv4plus/android/security/KeystoreManager.kt",
    "org/otrv4plus/android/security/LatchedVault.kt",
    "org/otrv4plus/android/security/LockState.kt",
    "org/otrv4plus/android/security/SecureStore.kt",
    "org/otrv4plus/android/security/UnlockCredentialService.kt",
    "org/otrv4plus/android/security/Vault.kt",
    "org/otrv4plus/android/security/WipeAndExit.kt",
    "org/otrv4plus/android/theme/ThemeTokens.kt"
)
val syncShared = tasks.register<Sync>("syncSharedFromAndroid") {
    from("../android/app/src/main/java") { include(sharedFromAndroid) }
    into(layout.buildDirectory.dir("shared-src"))
}
kotlin.sourceSets["main"].kotlin.srcDir(syncShared)

// The window's icon is the Android launcher icon (one file, one licence entry
// in REUSE.toml), copied into the jar as /otrv4plus.png.
tasks.named<ProcessResources>("processResources") {
    from("../android/app/src/main/res/mipmap-xxxhdpi") {
        include("ic_launcher.png")
        rename { "otrv4plus.png" }
    }
}


compose.desktop {
    application {
        mainClass = "org.otrv4plus.desktop.MainKt"
        nativeDistributions {
            targetFormats(TargetFormat.Deb, TargetFormat.Rpm)
            packageName = "otrv4plus-desktop"
            packageVersion = project.version.toString()
        }
    }
}

// The GUI's jars, for the otrv4plus-desktop package (qubes/packaging/
// build-desktop.sh): this project's jar and its runtime classpath, run on the
// template's own JRE. No bundled runtime, no jpackage.
tasks.register<Sync>("desktopLib") {
    from(tasks.named("jar"))
    from(configurations.named("runtimeClasspath"))
    into(layout.buildDirectory.dir("desktop-lib"))
}

// Read back by the window title (Main.kt), so the running app says which
// version it is.
tasks.named<Jar>("jar") {
    manifest { attributes("Implementation-Version" to project.version.toString()) }
}

tasks.withType<AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

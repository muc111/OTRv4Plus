plugins {
    id("com.android.application") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    // REQUIRED from Kotlin 2.0: the Compose compiler moved out of AGP and
    // into its own Kotlin plugin. Without it, `buildFeatures { compose = true }`
    // fails at CONFIGURATION time -- which is why `./gradlew tasks` never got
    // as far as compiling anything. Its version must track the Kotlin one.
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
    // Chaquopy embeds CPython. The Python requirement is 3.12+ (PEP 701
    // f-strings in otrv4+.py) -- see android_bridge/bootstrap.py.
    id("com.chaquo.python") version "16.0.0" apply false
}

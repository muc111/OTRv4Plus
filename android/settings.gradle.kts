pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
        // Chaquopy is mirrored on Maven Central (16.0.0 present, 17.0.0 latest),
        // which mavenCentral() above already covers. chaquo.com is kept as a
        // fallback only -- it is NOT required, and in restricted-egress
        // environments it may be unreachable without blocking the build.
        maven("https://chaquo.com/maven")
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()          // AGP + AndroidX -- dl.google.com, the one hard requirement
        mavenCentral()    // Kotlin, kotlinx, JUnit, and Chaquopy
        maven("https://chaquo.com/maven")   // fallback only; see pluginManagement
    }
}

rootProject.name = "OTRv4Plus"
include(":app")

// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}
dependencyResolutionManagement {
    repositories {
        mavenCentral()
        // Compose for Desktop's JVM builds of androidx.collection,
        // androidx.annotation and androidx.lifecycle are published here only.
        google {
            content { includeGroupByRegex("androidx\\..*") }
        }
    }
}
rootProject.name = "otrv4plus-desktop"

// 0trust VPN — Android app settings

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // WireGuard for Android lives on Maven Central these days; jitpack
        // mirror is a fallback for some older releases.
        maven { url = uri("https://jitpack.io") }
    }
}

rootProject.name = "0trust"
include(":app")

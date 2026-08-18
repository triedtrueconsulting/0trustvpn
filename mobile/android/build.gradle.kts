// 0trust VPN — Android app, root build.gradle.kts
//
// Plugin versions are declared once here and resolved by Gradle plugin DSL.
// We use kotlin-compose-multiplatform's compiler plugin syntax (introduced
// with Kotlin 2.0) so we don't have to pin a separate Compose Compiler
// version against Kotlin.

plugins {
    id("com.android.application") version "8.5.2" apply false
    id("org.jetbrains.kotlin.android") version "2.0.20" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.20" apply false
    id("org.jetbrains.kotlin.plugin.serialization") version "2.0.20" apply false
}

// 0trust VPN — Android app module
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
}

// Load signing config from keystore.properties (gitignored).
// Build still works without it — release builds will be unsigned and only
// installable via `adb install -r`.
val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties().apply {
    if (keystorePropertiesFile.exists()) {
        load(keystorePropertiesFile.inputStream())
    }
}

android {
    namespace = "vpn.zerotrust.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "vpn.zerotrust.app"
        minSdk = 26          // Android 8.0 — covers ~95% of in-use devices
        targetSdk = 34       // Android 14
        versionCode = 1
        versionName = "0.1.0"

        vectorDrawables { useSupportLibrary = true }

        // Default control plane. Customers running their own self-hosted
        // 0trust deployment can override at runtime in Settings.
        buildConfigField("String", "DEFAULT_API_BASE",
                         "\"https://0trustvpn.com\"")
    }

    signingConfigs {
        if (keystoreProperties.isNotEmpty()) {
            create("release") {
                storeFile = file(keystoreProperties["storeFile"] as String)
                storePassword = keystoreProperties["storePassword"] as String
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["keyPassword"] as String
            }
        }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
            isDebuggable = true
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            if (keystoreProperties.isNotEmpty()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    // --- Core Kotlin ---
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.1")

    // --- AndroidX ---
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.4")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.4")

    // --- Jetpack Compose (Material 3) ---
    val composeBom = platform("androidx.compose:compose-bom:2024.08.00")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")

    // --- Encrypted preferences for the account token ---
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // --- HTTP ---
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // --- WireGuard ---
    // The official wireguard-android library. Provides the WireGuard
    // GoBackend (userspace) and Tunnel abstractions we use from VpnService.
    implementation("com.wireguard.android:tunnel:1.0.20230706")
}

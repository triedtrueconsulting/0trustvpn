# 0trust VPN — ProGuard rules

# Keep WireGuard JNI entry points
-keep class com.wireguard.android.backend.** { *; }
-keep class com.wireguard.config.** { *; }
-keep class com.wireguard.crypto.** { *; }

# kotlinx.serialization needs generated classes
-keepattributes RuntimeVisibleAnnotations,AnnotationDefault
-keep class kotlinx.serialization.** { *; }
-keepclasseswithmembers class * {
    @kotlinx.serialization.Serializable <methods>;
}

# OkHttp / Okio internal
-dontwarn org.codehaus.mojo.animal_sniffer.*
-dontwarn okhttp3.internal.platform.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**

# --- Tink, behind androidx.security's encrypted preferences ----------------
#
# The device keypair lives in EncryptedSharedPreferences, which is Tink, and
# Tink's API is annotated with Error Prone annotations that exist only at
# compile time. R8 treats every one as a missing class and REFUSES TO RUN:
#
#   ERROR: Missing class com.google.errorprone.annotations.Immutable
#          (referenced from: com.google.crypto.tink.InsecureSecretKeyAccess
#           and 40 other contexts)
#
# So `assembleRelease` failed outright while `assembleDebug` — which does not
# minify — succeeded. Nothing had ever run the release build, so the only
# distributable variant of the app did not build at all.
#
# These are annotation types with class retention and no runtime presence, so
# ignoring them is correct rather than a workaround. Scoped to that one
# package: a broad -dontwarn would also hide a genuinely missing class, which
# is the failure this very rule exists because of.
-dontwarn com.google.errorprone.annotations.**

# Tink loads key managers reflectively through its registry, so minification
# that renames or drops them builds a release APK that then throws at the
# first access to encrypted preferences — which is where the device keypair
# is. Losing that keypair is not cosmetic: registration is idempotent on the
# pubkey, so a device that cannot persist one burns the account's device cap
# a few connects at a time and then locks the customer out.
-keep class com.google.crypto.tink.** { *; }
-keepclassmembers class com.google.crypto.tink.** { *; }
-dontwarn com.google.crypto.tink.**

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

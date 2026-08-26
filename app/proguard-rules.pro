# Castla ProGuard Rules

# NanoHTTPD — uses reflection internally
-keep class fi.iki.elonen.** { *; }

# Shizuku — AIDL + reflection-based service
-keep class com.castla.mirror.shizuku.IPrivilegedService { *; }
-keep class com.castla.mirror.shizuku.IPrivilegedService$* { *; }
-keep class com.castla.mirror.shizuku.PrivilegedService { *; }

# ZXing QR code
-keep class com.google.zxing.** { *; }

# Bouncy Castle — used by SelfSignedTls.kt to mint MirrorServer's TLS cert.
# The provider is looked up by name (Security.addProvider / JCA algorithm
# lookups) and does other reflection internally, so it needs to survive
# shrinking/obfuscation intact.
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Shizuku SDK
-keep class rikka.shizuku.** { *; }

# Keep AIDL-generated Stub/Proxy
-keep class * extends android.os.IInterface { *; }
-keep class * extends android.os.Binder { *; }

# Strip debug logs in release
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int v(...);
}

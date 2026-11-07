# R8 rules for Baluard Android (UniFFI + JNA + kotlinx.serialization).
#
# The FFI layer is name- and reflection-based: JNA binds UniffiLib methods by
# name via Native.load, reads Structure fields reflectively (@FieldOrder), and
# dispatches Callbacks from Rust. Anything on that path must survive shrinking
# and obfuscation with its names and fields intact. Everything else (Compose
# UI, ViewModels, repository layer) shrinks normally.

# ── JNA runtime ─────────────────────────────────────────────────────────
-keep class com.sun.jna.** { *; }
-dontwarn com.sun.jna.**

# Keep all JNA Library interfaces (Native.load binds methods by name)
-keep interface * extends com.sun.jna.Library { *; }

# Keep all JNA Structure subclasses including constructors (Kotlin internal = package-private)
-keep class * extends com.sun.jna.Structure { *; }
-keep class * implements com.sun.jna.Structure$ByValue { *; }
-keep class * implements com.sun.jna.Structure$ByReference { *; }

# Callback interfaces and implementations dispatched from/to Rust.
-keep interface * extends com.sun.jna.Callback { *; }
-keep class * implements com.sun.jna.Callback { *; }

# ── UniFFI generated FFI surface ────────────────────────────────────────
# UniffiLib binds by method name through Native.load.
-keep interface app.baluard.mobile.UniffiLib { *; }
# Keep UniFFI callback interface implementations registered toward Rust.
-keep class app.baluard.mobile.UniffiCallbackInterface* { *; }

# ── WorkManager: app Worker is instantiated reflectively by the runtime ──
-keep class * extends androidx.work.ListenableWorker {
    public <init>(...);
}

# ── kotlinx.serialization (ConflictModels wire payloads) ───────────────
-keepattributes *Annotation*, InnerClasses, Signature, EnclosingMethod
-dontnote kotlinx.serialization.**
-dontwarn kotlinx.serialization.**
-keep,includedescriptorclasses class app.baluard.mobile.**$$serializer { *; }
-keepclassmembers class app.baluard.mobile.** {
    *** Companion;
}
-keepclasseswithmembers class app.baluard.mobile.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# ── Entitlement cache format (ADR 0102) ────────────────────────────────
# The persisted cache encodes EntitlementPhase.name, so the constant names
# must survive R8 or a renamed field would break decode across releases and
# lock paying users out offline.
-keepclassmembers enum app.baluard.mobile.monetization.EntitlementPhase {
    <fields>;
}

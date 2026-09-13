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
-keep interface xyz.actitud.baluard.UniffiLib { *; }
# Keep UniFFI callback interface implementations registered toward Rust.
-keep class xyz.actitud.baluard.UniffiCallbackInterface* { *; }

# ── WorkManager: app Worker is instantiated reflectively by the runtime ──
-keep class * extends androidx.work.ListenableWorker {
    public <init>(...);
}

# ── kotlinx.serialization (ConflictModels wire payloads) ───────────────
-keepattributes *Annotation*, InnerClasses, Signature, EnclosingMethod
-dontnote kotlinx.serialization.**
-dontwarn kotlinx.serialization.**
-keep,includedescriptorclasses class xyz.actitud.baluard.**$$serializer { *; }
-keepclassmembers class xyz.actitud.baluard.** {
    *** Companion;
}
-keepclasseswithmembers class xyz.actitud.baluard.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# ───────────── Compose ─────────────
-keep class androidx.compose.** { *; }

# ───────────── Your app package ─────────────
-keep class com.lyecdevelopers.core.** { *; }

# ───────────── Hilt & DI ─────────────
-keep class dagger.hilt.** { *; }
-keep class javax.inject.** { *; }
-keep class dagger.internal.** { *; }

# ───────────── WorkManager + Hilt Worker ─────────────
-keep class androidx.work.Worker { *; }
-keep class androidx.hilt.work.HiltWorkerFactory { *; }
-keep class androidx.hilt.work.** { *; }

# ───────────── Room ─────────────
-keep class androidx.room.** { *; }
-keep @androidx.room.* class * { *; }

# ───────────── Moshi JSON ─────────────
-keep class com.squareup.moshi.** { *; }
-keep @com.squareup.moshi.JsonClass class * { *; }

# ───────────── Retrofit interfaces ─────────────
-keep interface retrofit2.** { *; }

# ───────────── Coil ─────────────
-keep class coil.** { *; }

# ───────────── Firebase ─────────────
# Firebase Crashlytics needs mapping file upload — no keep needed for basic config.
# If you have custom analytics events with reflection, keep them here.

# ───────────── Android FHIR ─────────────
-keep class com.google.android.fhir.** { *; }

# ───────────── Google Play Startup ─────────────
-keep class androidx.startup.** { *; }

# ───────────── DataStore ─────────────
-keep class androidx.datastore.** { *; }

# ───────────── Security Crypto ─────────────
-keep class androidx.security.crypto.** { *; }

# ───────────── Your Application class ─────────────
-keep class com.lyecdevelopers.ugandaemrmobile.**Application { *; }

# ───────────── Keep ViewModels ─────────────
-keep class *ViewModel

# ───────────── Activities & Fragments ─────────────
-keep class * extends android.app.Activity
-keep class * extends androidx.fragment.app.Fragment

# ───────────── Keep Kotlin metadata & annotations ─────────────
-keepattributes *Annotation*, Signature, InnerClasses

# ───────────── Keep enums (sealed classes safety) ─────────────
-keepclassmembers enum * { *; }

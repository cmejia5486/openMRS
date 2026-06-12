# SQLCipher (zetetic sqlcipher-android 4.6+)
-keep class net.zetetic.database.sqlcipher.** { *; }
-dontwarn net.zetetic.database.sqlcipher.**

# Bouncy Castle
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Room
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class *

# Sherpa-ONNX (JNI native speech recognition)
-keep class com.k2fsa.sherpa.onnx.** { *; }
-dontwarn com.k2fsa.sherpa.onnx.**

# ASR pipeline
-keep class com.chartlite.app.asr.SherpaASRPipeline { *; }
-keep class com.chartlite.app.asr.ModelDownloader { *; }
-keep class com.chartlite.app.asr.ModelDownloader$DownloadState { *; }
-keep class com.chartlite.app.asr.ModelDownloader$DownloadState$* { *; }

# ChartLite LLM (on-device llama.cpp JNI bridge)
-keep class com.chartlite.llm.** { *; }
-dontwarn com.chartlite.llm.**

# Gson model classes — keep all classes deserialized via gson.fromJson
-keep class com.chartlite.app.facilities.** { *; }
-keep class com.chartlite.app.protocols.** { *; }
-keep class com.chartlite.app.model.** { *; }
-keep class com.chartlite.app.sync.SyncEnvelope { *; }
-keep class com.chartlite.app.sync.SyncPayload { *; }
-keep class com.chartlite.app.sync.CrossFacilitySyncPayload { *; }
-keep class com.chartlite.app.cdss.StaticCDSS$DrugInteractionWrapper { *; }
-keep class com.chartlite.app.cdss.StaticCDSS$DrugInteraction { *; }
-keep class com.chartlite.app.auth.JoinCodeManager$JoinCode { *; }

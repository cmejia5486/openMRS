plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.ksp)
}

android {
    namespace = "com.chartlite.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.chartlite.app"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    testOptions {
        unitTests {
            isReturnDefaultValues = true
        }
    }

    packaging {
        resources {
            excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF"
        }
    }
}

ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
}

dependencies {
    // Compose
    val composeBom = platform(libs.compose.bom)
    implementation(composeBom)
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.graphics)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons)
    debugImplementation(libs.compose.ui.tooling)

    // Core
    implementation(libs.core.ktx)
    implementation(libs.activity.compose)
    implementation(libs.appcompat)

    // Lifecycle
    implementation(libs.lifecycle.runtime)
    implementation(libs.lifecycle.viewmodel.compose)
    implementation(libs.lifecycle.runtime.compose)

    // Navigation
    implementation(libs.navigation.compose)

    // Room
    implementation(libs.room.runtime)
    implementation(libs.room.ktx)
    ksp(libs.room.compiler)

    // Coroutines
    implementation(libs.coroutines.core)
    implementation(libs.coroutines.android)

    // Security
    implementation(libs.sqlcipher)
    implementation(libs.bouncycastle)
    implementation(libs.security.crypto)
    implementation(libs.biometric)

    // Serialization
    implementation(libs.gson)

    // Fuzzy matching
    implementation(libs.fuzzywuzzy)

    // Sherpa-ONNX (on-device ASR with VAD, streaming, beam search)
    implementation(files("libs/sherpa-onnx.aar"))

    // Networking (Twilio SMS)
    implementation(libs.okhttp)

    // WorkManager (offline SMS queue)
    implementation(libs.work.runtime)

    // On-device LLM inference (Qwen via llama.cpp built from source)
    implementation(project(":llm"))

    // CameraX (clinical camera capture)
    implementation(libs.camerax.core)
    implementation(libs.camerax.camera2)
    implementation(libs.camerax.lifecycle)
    implementation(libs.camerax.view)

    // QR Code (join code generation + scanning)
    implementation(libs.zxing.embedded)

    // Nearby Connections (BT/WiFi sync)
    implementation(libs.nearby)

    // Play Integrity (attestation for proxy auth)
    implementation(libs.integrity)

    // Testing
    testImplementation(libs.junit)
    testImplementation(libs.coroutines.test)
    testImplementation(libs.gson)
    testImplementation("io.mockk:mockk:1.13.10")
    androidTestImplementation(libs.test.ext)
    androidTestImplementation(libs.espresso)
    androidTestImplementation(composeBom)
    androidTestImplementation(libs.compose.test)
}

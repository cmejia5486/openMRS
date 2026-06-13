import java.io.ByteArrayOutputStream
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.hilt)
    alias(libs.plugins.ksp)
    // alias(libs.plugins.services)
    // alias(libs.plugins.crashlytics)
}

fun getVersionCode(): Int {
    val stdout = ByteArrayOutputStream()
    exec {
        commandLine("git", "rev-list", "--count", "HEAD")
        standardOutput = stdout
    }
    return stdout.toString().trim().toIntOrNull() ?: 1
}

fun getVersionName(): String {
    val stdout = ByteArrayOutputStream()
    exec {
        commandLine("git", "describe", "--tags", "--abbrev=0")
        standardOutput = stdout
        isIgnoreExitValue = true
    }
    val tag = stdout.toString().trim()
    return tag.ifEmpty { "0.1.0" }
}

val localProperties = Properties()
val localPropertiesFile = rootProject.file("local.properties")

if (localPropertiesFile.exists()) {
    localPropertiesFile.inputStream().use { localProperties.load(it) }
}

fun ciOrLocal(name: String): String? {
    val envValue = System.getenv(name)
    if (!envValue.isNullOrBlank()) return envValue

    val localValue = localProperties.getProperty(name)
    if (!localValue.isNullOrBlank()) return localValue

    return null
}

val keystoreFilePath = ciOrLocal("KEYSTORE_FILE")
val keystorePassword = ciOrLocal("KEYSTORE_PASSWORD")
val keyAliasName = ciOrLocal("KEY_ALIAS")
val keyPasswordValue = ciOrLocal("KEY_PASSWORD")

val releaseKeystoreFile = if (!keystoreFilePath.isNullOrBlank()) {
    rootProject.file(keystoreFilePath)
} else {
    null
}

val hasReleaseSigning =
    releaseKeystoreFile?.exists() == true &&
    !keystorePassword.isNullOrBlank() &&
    !keyAliasName.isNullOrBlank() &&
    !keyPasswordValue.isNullOrBlank()

android {
    namespace = "com.lyecdevelopers.ugandaemrmobile"
    compileSdk = 36

    splits {
        abi {
            isEnable = true
            reset()
            include("armeabi-v7a", "arm64-v8a", "x86", "x86_64")
            isUniversalApk = false
        }
    }

    defaultConfig {
        applicationId = "com.lyecdevelopers.ugandaemrmobile"
        minSdk = 28
        versionCode = getVersionCode()
        versionName = getVersionName()

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        create("release") {
            if (hasReleaseSigning) {
                storeFile = releaseKeystoreFile
                storePassword = keystorePassword
                keyAlias = keyAliasName
                keyPassword = keyPasswordValue
                println("[Signing] Using keystore at: ${releaseKeystoreFile?.path}")
            } else {
                println("[Signing] Release signing disabled for this build")
            }
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true

            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }

            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }

        getByName("debug") {
            isMinifyEnabled = false
            isDebuggable = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    buildFeatures {
        compose = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "2.0.20"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true
    }

    packaging {
        resources.excludes.addAll(
            listOf("META-INF/ASL-2.0.txt", "META-INF/LGPL-3.0.txt")
        )
    }

    kotlin {
        jvmToolchain(17)
    }

    hilt {
        enableAggregatingTask = false
    }

    configurations.all {
        resolutionStrategy {
            force("com.google.guava:guava:32.1.3-android")
        }
    }
}

dependencies {
    implementation(project(":core"))
    implementation(project(":sync"))
    implementation(project(":settings"))
    implementation(project(":worklist"))
    implementation(project(":auth"))
    implementation(project(":core-navigation"))
    implementation(project(":main"))
    implementation(project(":form"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.hilt.navigation.compose)
    implementation(libs.material.icons.extended)
    implementation(libs.splashscreen)
    implementation(libs.androidx.appcompat)

    implementation(libs.android.fhir.engine)
    implementation(libs.android.fhir.sdc)
    coreLibraryDesugaring(libs.desugar.jdk.libs)

    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)

    implementation(libs.retrofit)
    implementation(libs.okhttp)
    implementation(libs.logging.interceptor)

    implementation(libs.room.runtime)
    implementation(libs.room.ktx)
    ksp(libs.room.compiler)

    implementation(libs.moshi)
    implementation(libs.moshi.kotlin)
    ksp(libs.moshi.kotlin.codegen)
    implementation(libs.moshi.converter)

    implementation(libs.timber)

    implementation(platform(libs.firebase.bom))
    implementation(libs.firebase.analytics)
    implementation(libs.firebase.crashlytics)

    implementation(libs.hilt.work)
    implementation(libs.hilt.work.compiler)
    implementation(libs.work.runtime)
    implementation(libs.androidx.startup.runtime)
    implementation(libs.work.runtime.ktx)

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.ui.test.junit4)
    debugImplementation(libs.androidx.ui.tooling)
    debugImplementation(libs.androidx.ui.test.manifest)
}

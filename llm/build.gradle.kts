plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "com.chartlite.llm"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
        ndk {
            // Include 32-bit for install compatibility on older devices.
            // Runtime gating in LlmModelManager keeps on-device LLM disabled on unsupported ABIs.
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
        externalNativeBuild {
            cmake {
                arguments += listOf(
                    "-DCMAKE_BUILD_TYPE=Release",
                    "-DBUILD_SHARED_LIBS=ON",
                )
            }
        }
    }

    externalNativeBuild {
        cmake {
            path("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
}

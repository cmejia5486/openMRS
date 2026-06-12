cmake_minimum_required(VERSION 3.22.1)
project("benchmark-llm" VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED true)

# Android 15+ 16KB page size support
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,max-page-size=16384")

# ─── llama.cpp via FetchContent ───────────────────────────────────────────────
# Downloads and builds llama.cpp from source on first configure.
# Subsequent builds use the cached source in the CMake build directory.
include(FetchContent)

# Pin to a specific release for reproducibility
set(LLAMA_CPP_TAG "b8559")
FetchContent_Declare(
    llama_cpp
    GIT_REPOSITORY https://github.com/ggml-org/llama.cpp.git
    GIT_TAG        ${LLAMA_CPP_TAG}
    GIT_SHALLOW    TRUE
    GIT_PROGRESS   TRUE
)

# Configure llama.cpp build options for Android
set(LLAMA_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_SERVER OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS ON CACHE BOOL "" FORCE)

# ABI-specific optimizations
if(ANDROID_ABI STREQUAL "arm64-v8a")
    set(GGML_CPU_KLEIDIAI OFF CACHE BOOL "" FORCE)
    set(GGML_OPENMP ON CACHE BOOL "" FORCE)
elseif(ANDROID_ABI STREQUAL "x86_64")
    set(GGML_CPU_KLEIDIAI OFF CACHE BOOL "" FORCE)
    set(GGML_OPENMP OFF CACHE BOOL "" FORCE)
endif()

FetchContent_MakeAvailable(llama_cpp)

# ─── JNI bridge for llama.cpp ─────────────────────────────────────────────────
add_library(${CMAKE_PROJECT_NAME} SHARED
    llama_jni.cpp
)

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
    ${llama_cpp_SOURCE_DIR}/include
    ${llama_cpp_SOURCE_DIR}/ggml/include
)

target_link_libraries(${CMAKE_PROJECT_NAME}
    llama
    ggml
    android
    log
)

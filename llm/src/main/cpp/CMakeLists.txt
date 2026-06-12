cmake_minimum_required(VERSION 3.22.1)
project("chartlite-llm" VERSION 2.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED true)

# MNN source tree (git submodule at external/MNN)
set(MNN_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../../external/MNN")

# MNN build flags for LLM on mobile
set(MNN_BUILD_LLM ON CACHE BOOL "" FORCE)
set(MNN_LOW_MEMORY ON CACHE BOOL "" FORCE)
set(MNN_CPU_WEIGHT_DEQUANT_GEMM ON CACHE BOOL "" FORCE)
set(MNN_SUPPORT_TRANSFORMER_FUSE ON CACHE BOOL "" FORCE)
set(MNN_SEP_BUILD ON CACHE BOOL "" FORCE)
set(MNN_BUILD_SHARED_LIBS ON CACHE BOOL "" FORCE)
set(MNN_BUILD_DEMO OFF CACHE BOOL "" FORCE)
set(MNN_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(MNN_BUILD_TEST OFF CACHE BOOL "" FORCE)
set(MNN_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(MNN_BUILD_QUANTOOLS OFF CACHE BOOL "" FORCE)
set(MNN_BUILD_CONVERTER OFF CACHE BOOL "" FORCE)
set(MNN_USE_LOGCAT ON CACHE BOOL "" FORCE)

# Vision support — enables MNN::CV::imread + vision encoder in omni.cpp
set(MNN_BUILD_OPENCV ON CACHE BOOL "" FORCE)
set(MNN_IMGCODECS ON CACHE BOOL "" FORCE)

# ABI-specific optimizations
if(ANDROID_ABI STREQUAL "arm64-v8a")
    set(MNN_ARM82 ON CACHE BOOL "" FORCE)
    set(MNN_OPENCL ON CACHE BOOL "" FORCE)
    set(MNN_KLEIDIAI ON CACHE BOOL "" FORCE)
    set(MNN_VULKAN ON CACHE BOOL "" FORCE)
endif()

# Android 15+ 16KB page size support
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,max-page-size=16384")

# Build MNN from source
add_subdirectory(${MNN_ROOT} ${CMAKE_BINARY_DIR}/mnn EXCLUDE_FROM_ALL)

# Our JNI bridge
add_library(${CMAKE_PROJECT_NAME} SHARED
    chartlite_mnn.cpp
)

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
    ${MNN_ROOT}/include
    ${MNN_ROOT}/transformers/llm/engine/include
)

target_link_libraries(${CMAKE_PROJECT_NAME}
    MNN
    MNNOpenCV
    llm
    android
    log
)

package com.chartlite.benchmark.engine

import android.util.Log

/**
 * JNI bridge to llama.cpp for on-device GGUF inference.
 * Loads libbenchmark-llm.so which wraps llama.cpp's C API.
 */
object LlamaCppBridge {

    private const val TAG = "LlamaCppBridge"

    @Volatile
    private var initialized = false

    fun initialize() {
        if (initialized) return
        synchronized(this) {
            if (initialized) return
            try {
                System.loadLibrary("benchmark-llm")
                initialized = true
                Log.i(TAG, "llama.cpp backend loaded")
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "Failed to load native library", e)
            }
        }
    }

    fun isAvailable(): Boolean = initialized

    fun loadModel(modelPath: String, nThreads: Int = 4): Boolean {
        check(initialized) { "LlamaCppBridge not initialized" }
        return nativeLoadModel(modelPath, nThreads)
    }

    fun generate(prompt: String, maxTokens: Int = 256, temperature: Float = 0.1f): String? {
        check(initialized) { "LlamaCppBridge not initialized" }
        return nativeGenerate(prompt, maxTokens, temperature)
    }

    /** Returns [loadMs, prefillMs, decodeMs, promptTokens, decodedTokens] */
    fun getMetrics(): DoubleArray {
        check(initialized) { "LlamaCppBridge not initialized" }
        return nativeGetMetrics()
    }

    fun unload() {
        if (!initialized) return
        nativeUnload()
    }

    private external fun nativeLoadModel(modelPath: String, nThreads: Int): Boolean
    private external fun nativeGenerate(prompt: String, maxTokens: Int, temperature: Float): String?
    private external fun nativeGetMetrics(): DoubleArray
    private external fun nativeUnload()
}

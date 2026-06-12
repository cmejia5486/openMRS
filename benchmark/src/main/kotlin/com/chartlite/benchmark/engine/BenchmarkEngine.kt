package com.chartlite.benchmark.engine

/**
 * Common interface for LLM inference engines in the benchmark.
 * Each engine loads Qwen 3.5 0.8B in its own format for apples-to-apples comparison:
 *   - MNN:        INT4 (.mnn)          — auto-download from HuggingFace
 *   - llama.cpp:  GGUF Q4_K_M (.gguf)  — auto-download from HuggingFace
 *   - MLC LLM:    q4f16_1 (.bin)       — compile locally with mlc_llm
 *   - LiteRT-LM:  .litertlm            — convert locally with ai_edge_torch
 *   - MediaPipe:  .task (TFLite)       — convert locally with ai_edge_torch
 *   - ExecuTorch: .pte (XNNPACK)       — convert locally with executorch
 */
interface BenchmarkEngine {
    val name: String
    val modelFormat: String   // "MNN INT4", "GGUF Q4_K_M", etc.

    /** Whether the model file exists on device. */
    fun isModelReady(): Boolean

    /** Load the model into memory. Returns load time in ms. */
    suspend fun loadModel(): Double

    /** Generate text from a prompt. Returns the output string. */
    suspend fun generate(prompt: String, maxTokens: Int = 256): String?

    /** Get metrics from the last generation. */
    fun lastMetrics(): EngineMetrics

    /** Unload model and free memory. */
    fun unload()
}

data class EngineMetrics(
    val loadMs: Double = 0.0,
    val prefillMs: Double = 0.0,
    val decodeMs: Double = 0.0,
    val promptTokens: Int = 0,
    val decodedTokens: Int = 0
) {
    val prefillTokPerSec: Double
        get() = if (promptTokens > 0 && prefillMs > 0) promptTokens / (prefillMs / 1000.0) else 0.0
    val decodeTokPerSec: Double
        get() = if (decodedTokens > 0 && decodeMs > 0) decodedTokens / (decodeMs / 1000.0) else 0.0
    val totalMs: Double
        get() = prefillMs + decodeMs
}

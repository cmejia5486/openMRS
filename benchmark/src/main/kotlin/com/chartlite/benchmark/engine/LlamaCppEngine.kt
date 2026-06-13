package com.chartlite.benchmark.engine

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * llama.cpp engine — runs Qwen 3.5 0.8B from GGUF format.
 * Model file: qwen3.5-0.8b-q4_k_m.gguf (~530MB)
 */
class LlamaCppEngine(private val context: Context) : BenchmarkEngine {

    override val name = "llama.cpp"
    override val modelFormat = "GGUF Q4_K_M"

    private val modelDir = File(context.noBackupFilesDir, "benchmark_models/llamacpp")
    val modelFile = File(modelDir, "Qwen3.5-0.8B-Q4_K_M.gguf")
    private var lastMetrics = EngineMetrics()

    override fun isModelReady(): Boolean = modelFile.exists() && modelFile.length() > 100_000_000

    override suspend fun loadModel(): Double = withContext(Dispatchers.Default) {
        LlamaCppBridge.initialize()
        if (!LlamaCppBridge.isAvailable()) error("llama.cpp native library not available")

        val nThreads = Runtime.getRuntime().availableProcessors().coerceIn(2, 4)
        val success = LlamaCppBridge.loadModel(modelFile.absolutePath, nThreads)
        if (!success) error("Failed to load GGUF model")

        val metrics = LlamaCppBridge.getMetrics()
        lastMetrics = EngineMetrics(loadMs = metrics[0])
        metrics[0]
    }

    override suspend fun generate(prompt: String, maxTokens: Int): String? =
        withContext(Dispatchers.Default) {
            val result = LlamaCppBridge.generate(prompt, maxTokens, 0.1f)
            val m = LlamaCppBridge.getMetrics()
            lastMetrics = EngineMetrics(
                loadMs = m[0],
                prefillMs = m[1],
                decodeMs = m[2],
                promptTokens = m[3].toInt(),
                decodedTokens = m[4].toInt()
            )
            result
        }

    override fun lastMetrics(): EngineMetrics = lastMetrics

    override fun unload() {
        LlamaCppBridge.unload()
        lastMetrics = EngineMetrics()
    }

    companion object {
        const val MODEL_URL =
            "https://huggingface.co/prismindanalytics/Qwen3.5-0.8B-GGUF/resolve/main/Qwen3.5-0.8B-Q4_K_M.gguf"
        const val MODEL_SIZE_MB = 505
    }
}

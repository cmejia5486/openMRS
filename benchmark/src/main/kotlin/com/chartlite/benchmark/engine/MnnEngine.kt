package com.chartlite.benchmark.engine

import android.content.Context
import com.chartlite.llm.LlamaBridge
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.zip.ZipFile

/**
 * MNN engine — runs Qwen 3.5 0.8B from MNN INT4 format.
 * Model files: directory with llm.mnn, llm.mnn.weight, tokenizer.txt, configs
 */
class MnnEngine(private val context: Context) : BenchmarkEngine {

    override val name = "MNN"
    override val modelFormat = "MNN INT4"

    private val modelDir = File(context.noBackupFilesDir, "benchmark_models/mnn/qwen35-0.8b-mnn")
    private var lastMetrics = EngineMetrics()
    private var modelLoaded = false

    override fun isModelReady(): Boolean {
        val configFile = File(modelDir, "llm_config.json")
        val weightFile = File(modelDir, "llm.mnn")
        return configFile.exists() && weightFile.exists()
    }

    override suspend fun loadModel(): Double = withContext(Dispatchers.Default) {
        LlamaBridge.initialize(context)

        val t0 = System.nanoTime()
        val success = LlamaBridge.initGenerateModel(modelDir.absolutePath)
        val loadMs = (System.nanoTime() - t0) / 1_000_000.0
        if (!success) error("Failed to load MNN model")

        // Set default params for benchmarking
        LlamaBridge.updateGenerateParams(
            temperature = 0.1f,
            maxTokens = 256,
            topP = 0.95f,
            topK = 40,
            repeatPenalty = 1.0f
        )

        modelLoaded = true
        lastMetrics = EngineMetrics(loadMs = loadMs)
        loadMs
    }

    override suspend fun generate(prompt: String, maxTokens: Int): String? =
        withContext(Dispatchers.Default) {
            LlamaBridge.updateGenerateParams(
                temperature = 0.1f,
                maxTokens = maxTokens,
                topP = 0.95f,
                topK = 40,
                repeatPenalty = 1.0f
            )

            val t0 = System.nanoTime()
            val result = LlamaBridge.generateChat(
                "You are a helpful assistant. Respond concisely.",
                prompt
            )
            val totalMs = (System.nanoTime() - t0) / 1_000_000.0

            // MNN logs prefill/decode metrics to logcat — we measure wall time here
            val estimatedTokens = (result?.length ?: 0) / 4 // rough char-to-token ratio
            lastMetrics = EngineMetrics(
                loadMs = lastMetrics.loadMs,
                prefillMs = 0.0, // included in totalMs
                decodeMs = totalMs,
                promptTokens = prompt.length / 4,
                decodedTokens = estimatedTokens
            )
            result
        }

    override fun lastMetrics(): EngineMetrics = lastMetrics

    override fun unload() {
        if (modelLoaded) {
            LlamaBridge.shutdown()
            modelLoaded = false
        }
        lastMetrics = EngineMetrics()
    }

    companion object {
        const val MODEL_URL =
            "https://huggingface.co/prismindanalytics/qwen3.5-0.8b-int4-mnn/resolve/main/qwen35-0.8b-int4-mnn.zip"
        const val MODEL_SIZE_MB = 390
    }
}

package com.chartlite.benchmark.engine

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * LiteRT-LM engine — Google's on-device LLM inference runtime.
 * Uses .litertlm model format with CPU/GPU/NPU backends.
 *
 * Requires: com.google.ai.edge.litertlm:litertlm-android dependency
 *
 * No pre-built Qwen 3.5 0.8B .litertlm exists. Convert locally:
 *   pip install ai-edge-torch
 *   python -m ai_edge_torch.generative.examples.qwen export \
 *       --ckpt_path Qwen3.5-0.8B/ --output qwen3.5-0.8b.litertlm
 *   adb push qwen3.5-0.8b.litertlm /data/local/tmp/
 */
class LiteRtLmEngine(private val context: Context) : BenchmarkEngine {

    override val name = "LiteRT-LM"
    override val modelFormat = "LiteRT"

    private val modelDir = File(context.noBackupFilesDir, "benchmark_models/litertlm")
    val modelFile = File(modelDir, "qwen3.5-0.8b.litertlm")
    private var lastMetrics = EngineMetrics()
    private var engine: Any? = null
    private var conversation: Any? = null

    override fun isModelReady(): Boolean = modelFile.exists() && modelFile.length() > 50_000_000

    override suspend fun loadModel(): Double = withContext(Dispatchers.Default) {
        val t0 = System.nanoTime()
        try {
            // Use reflection to avoid hard compile-time dependency
            val backendClass = Class.forName("com.google.ai.edge.litertlm.Backend")
            val cpuMethod = backendClass.getMethod("CPU")
            val cpuBackend = cpuMethod.invoke(null)

            val engineConfigClass = Class.forName("com.google.ai.edge.litertlm.EngineConfig")
            val engineConfig = engineConfigClass.getConstructor(
                String::class.java,
                backendClass,
            ).newInstance(modelFile.absolutePath, cpuBackend)

            val engineClass = Class.forName("com.google.ai.edge.litertlm.Engine")
            engine = engineClass.getConstructor(engineConfigClass).newInstance(engineConfig)
            engineClass.getMethod("initialize").invoke(engine)

            // Create a conversation for generation
            conversation = engineClass.getMethod("createConversation").invoke(engine)

            val loadMs = (System.nanoTime() - t0) / 1_000_000.0
            lastMetrics = EngineMetrics(loadMs = loadMs)
            loadMs
        } catch (e: ClassNotFoundException) {
            error("LiteRT-LM library not available. Add com.google.ai.edge.litertlm:litertlm-android to dependencies.")
        }
    }

    override suspend fun generate(prompt: String, maxTokens: Int): String? =
        withContext(Dispatchers.Default) {
            val conv = conversation ?: error("Model not loaded")
            val t0 = System.nanoTime()

            // Build user message
            val messageClass = Class.forName("com.google.ai.edge.litertlm.Message")
            val userMsg = messageClass.getMethod("user", String::class.java)
                .invoke(null, prompt)

            // Send synchronously
            val response = conv.javaClass.getMethod("sendMessage", messageClass)
                .invoke(conv, userMsg)

            // Extract text from response
            val result = response?.toString()

            val totalMs = (System.nanoTime() - t0) / 1_000_000.0
            val estimatedTokens = (result?.length ?: 0) / 4
            lastMetrics = EngineMetrics(
                loadMs = lastMetrics.loadMs,
                prefillMs = 0.0,
                decodeMs = totalMs,
                promptTokens = prompt.length / 4,
                decodedTokens = estimatedTokens
            )
            result
        }

    override fun lastMetrics(): EngineMetrics = lastMetrics

    override fun unload() {
        conversation?.let {
            try { it.javaClass.getMethod("close").invoke(it) } catch (_: Exception) {}
        }
        engine?.let {
            try { it.javaClass.getMethod("close").invoke(it) } catch (_: Exception) {}
        }
        conversation = null
        engine = null
        lastMetrics = EngineMetrics()
    }

    companion object {
        // No pre-built Qwen 3.5 0.8B .litertlm — must convert locally. See class header.
        const val MODEL_URL = ""
        const val MODEL_SIZE_MB = 500
    }
}

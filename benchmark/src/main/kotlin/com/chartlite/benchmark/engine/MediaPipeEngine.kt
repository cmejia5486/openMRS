package com.chartlite.benchmark.engine

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * MediaPipe LLM Inference API engine — runs Qwen 3.5 0.8B via TFLite/GPU delegate.
 *
 * Uses Google's MediaPipe Tasks GenAI runtime. Model must be in .task format.
 *
 * Convert locally:
 *   pip install ai-edge-torch mediapipe
 *   python -m ai_edge_torch.generative.examples.qwen export \
 *       --ckpt_path Qwen3.5-0.8B/ --output qwen3.5-0.8b-int4.task
 *   adb push qwen3.5-0.8b-int4.task /data/local/tmp/
 *
 * Requires: com.google.mediapipe:tasks-genai dependency
 */
class MediaPipeEngine(private val context: Context) : BenchmarkEngine {

    override val name = "MediaPipe"
    override val modelFormat = "TFLite INT4"

    private val modelDir = File(context.noBackupFilesDir, "benchmark_models/mediapipe")
    val modelFile = File(modelDir, "qwen3.5-0.8b-int4.task")
    private var lastMetrics = EngineMetrics()
    private var inference: Any? = null // LlmInference instance via reflection

    override fun isModelReady(): Boolean = modelFile.exists() && modelFile.length() > 50_000_000

    override suspend fun loadModel(): Double = withContext(Dispatchers.Default) {
        val t0 = System.nanoTime()
        try {
            // Use reflection to avoid hard compile-time dependency.
            // MediaPipe GenAI may not be on classpath in all builds.
            val optionsClass = Class.forName("com.google.mediapipe.tasks.genai.llminference.LlmInference\$LlmInferenceOptions")
            val builderClass = Class.forName("com.google.mediapipe.tasks.genai.llminference.LlmInference\$LlmInferenceOptions\$Builder")
            val inferenceClass = Class.forName("com.google.mediapipe.tasks.genai.llminference.LlmInference")

            val builder = builderClass.getConstructor().newInstance()
            builderClass.getMethod("setModelPath", String::class.java)
                .invoke(builder, modelFile.absolutePath)
            builderClass.getMethod("setMaxTokens", Int::class.javaPrimitiveType)
                .invoke(builder, 512)
            builderClass.getMethod("setMaxTopK", Int::class.javaPrimitiveType)
                .invoke(builder, 40)

            val options = builderClass.getMethod("build").invoke(builder)

            inference = inferenceClass.getMethod("createFromOptions", Context::class.java, optionsClass)
                .invoke(null, context, options)

            val loadMs = (System.nanoTime() - t0) / 1_000_000.0
            lastMetrics = EngineMetrics(loadMs = loadMs)
            loadMs
        } catch (e: ClassNotFoundException) {
            error("MediaPipe GenAI library not available. Add com.google.mediapipe:tasks-genai to dependencies.")
        }
    }

    override suspend fun generate(prompt: String, maxTokens: Int): String? =
        withContext(Dispatchers.Default) {
            val inf = inference ?: error("Model not loaded")
            val t0 = System.nanoTime()

            val result = inf.javaClass.getMethod("generateResponse", String::class.java)
                .invoke(inf, prompt) as? String

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
        inference?.let {
            try {
                it.javaClass.getMethod("close").invoke(it)
            } catch (_: Exception) {}
        }
        inference = null
        lastMetrics = EngineMetrics()
    }

    companion object {
        // No official Qwen TFLite model — placeholder URL
        // Users can convert with: python -m ai_edge_torch.generative.examples.qwen export --ckpt_path <path> --output <output.task>
        const val MODEL_URL = ""
        const val MODEL_SIZE_MB = 450
    }
}

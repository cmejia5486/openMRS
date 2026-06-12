package com.chartlite.app.extraction

import android.content.Context
import android.util.Log
import com.chartlite.app.model.Formulary
import com.chartlite.app.model.ICD10Index
import com.chartlite.app.model.StructuredEncounter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Extraction strategy using Google's Gemini Nano via AICore (on-device).
 *
 * CURRENT STATUS: Experimental placeholder, not wired into the production
 * extraction chain. The reflection-based approach cannot call
 * Kotlin suspend functions (like generateContent) because their JVM signature
 * includes a hidden Continuation parameter. This strategy will gracefully
 * fall through to Qwen/Regex on all devices if re-enabled for experiments.
 *
 * TODO: Replace reflection with compile-time AI Edge SDK dependency
 * (com.google.ai.edge:aicore) once we can add it to build.gradle.
 *
 * Only available on flagship devices with Google AICore support
 * (Pixel 9+, Galaxy S24+, etc.). Uses condensed prompts due to
 * Gemini Nano's smaller context window (~4K tokens).
 */
class GeminiNanoExtractionStrategy(
    private val context: Context,
    private val promptBuilder: ExtractionPromptBuilder,
    private val responseParser: LlmResponseParser
) : ExtractionStrategy {

    override val name = "Gemini Nano (on-device)"

    private var cachedAvailability: Boolean? = null

    override suspend fun isAvailable(): Boolean {
        cachedAvailability?.let { return it }

        return withContext(Dispatchers.IO) {
            try {
                // Check if AICore package is installed.
                // NOTE: Even if installed, the reflection-based approach below cannot
                // call Kotlin suspend functions (hidden Continuation param). This
                // strategy always falls through to Qwen/Regex until we add a compile-
                // time AI Edge SDK dependency. We still check availability so we can
                // log which devices could benefit once the real SDK is integrated.
                val aiCoreAvailable = isAiCoreAvailable()
                if (aiCoreAvailable) {
                    Log.i(TAG, "AICore installed but SDK integration pending — falling through to next strategy")
                }
                cachedAvailability = false // Always unavailable until real SDK is added
                false
            } catch (e: Exception) {
                Log.w(TAG, "AICore availability check failed", e)
                cachedAvailability = false
                false
            }
        }
    }

    override suspend fun extract(
        transcript: String,
        patientId: String,
        providerId: String,
        facilityId: String
    ): StructuredEncounter? = withContext(Dispatchers.IO) {
        try {
            // Use condensed prompt for Gemini Nano's smaller context window
            val prompt = promptBuilder.buildCombinedPrompt(transcript, condensed = true)

            val responseText = runGeminiNanoInference(prompt)
            if (responseText.isNullOrBlank()) {
                Log.w(TAG, "Gemini Nano returned empty response")
                return@withContext null
            }

            responseParser.parse(responseText, transcript, patientId, providerId, facilityId)
        } catch (e: Exception) {
            Log.e(TAG, "Gemini Nano extraction failed", e)
            null
        }
    }

    /**
     * Check if Google AICore is available on this device.
     * AICore is pre-installed on Pixel 9+, Galaxy S24+, and similar flagships.
     */
    private fun isAiCoreAvailable(): Boolean {
        return try {
            // Check for AICore package
            val pm = context.packageManager
            pm.getPackageInfo("com.google.android.aicore", 0)
            true
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Run inference using Gemini Nano via AICore.
     *
     * Uses the Google AI Edge SDK (com.google.ai.edge.aicore).
     * Returns the generated text or null on failure.
     */
    private suspend fun runGeminiNanoInference(prompt: String): String? {
        return try {
            // Use reflection to avoid hard compile-time dependency on AICore SDK.
            // This allows the app to compile and run on all devices — Gemini Nano
            // is simply unavailable on devices without AICore.
            val generativeModelClass = Class.forName("com.google.ai.edge.aicore.GenerativeModel")
            val contentClass = Class.forName("com.google.ai.edge.aicore.Content")

            // Build GenerationConfig
            val configBuilderClass = Class.forName("com.google.ai.edge.aicore.GenerationConfig\$Builder")
            val configBuilder = configBuilderClass.getDeclaredConstructor().newInstance()
            configBuilderClass.getMethod("setTemperature", Float::class.java)
                .invoke(configBuilder, 0.1f)
            configBuilderClass.getMethod("setTopK", Int::class.java)
                .invoke(configBuilder, 16)
            configBuilderClass.getMethod("setMaxOutputTokens", Int::class.java)
                .invoke(configBuilder, 2048)
            val config = configBuilderClass.getMethod("build").invoke(configBuilder)

            // Create GenerativeModel
            val configClass = Class.forName("com.google.ai.edge.aicore.GenerationConfig")
            val model = generativeModelClass
                .getDeclaredConstructor(configClass)
                .newInstance(config)

            // Build Content with the prompt text
            val contentBuilderClass = Class.forName("com.google.ai.edge.aicore.Content\$Builder")
            val contentBuilder = contentBuilderClass.getDeclaredConstructor().newInstance()
            contentBuilderClass.getMethod("addText", String::class.java)
                .invoke(contentBuilder, prompt)
            val content = contentBuilderClass.getMethod("build").invoke(contentBuilder)

            // Call generateContent (suspend function — use the blocking variant)
            val generateMethod = generativeModelClass.getMethod("generateContent", contentClass)
            val response = generateMethod.invoke(model, content)

            // Extract text from response
            val getText = response.javaClass.getMethod("getText")
            getText.invoke(response) as? String
        } catch (e: ClassNotFoundException) {
            Log.d(TAG, "AICore SDK classes not found on this device")
            cachedAvailability = false
            null
        } catch (e: Exception) {
            Log.e(TAG, "Gemini Nano inference failed", e)
            null
        }
    }

    companion object {
        private const val TAG = "GeminiNano"
    }
}

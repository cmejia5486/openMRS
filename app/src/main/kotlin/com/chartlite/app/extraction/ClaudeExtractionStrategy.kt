package com.chartlite.app.extraction

import android.content.Context
import android.util.Base64
import android.util.Log
import java.io.File
import com.chartlite.app.asr.cloud.NetworkUtils
import com.chartlite.app.asr.cloud.SharedHttpClient
import com.chartlite.app.model.StructuredEncounter
import com.google.gson.Gson
import com.google.gson.JsonObject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * Cloud-based clinical extraction via the Anthropic Messages API.
 * Uses the same benchmark JSON prompt contract as the on-device extractor.
 *
 * Supports two modes:
 * - **Direct** (BYOK): Calls api.anthropic.com with user's API key
 * - **Proxied** (ChartLite Cloud): Calls api.chartlite.health with a session JWT;
 *   the proxy injects the Anthropic API key server-side
 *
 * Mode is determined by the [authConfig] parameter.
 */
class ClaudeExtractionStrategy(
    private val context: Context,
    private val promptBuilder: ExtractionPromptBuilder,
    private val responseParser: LlmResponseParser,
    private val authConfig: AuthConfig
) : ExtractionStrategy {

    /** Auth configuration — either direct API key or proxy auth. */
    sealed class AuthConfig {
        /** Direct calls to Anthropic API with user's own key. */
        data class Direct(val apiKeyProvider: () -> String) : AuthConfig()

        /** Proxied calls through ChartLite backend with session-based auth. */
        data class Proxied(val authHeaderProvider: suspend () -> Map<String, String>) : AuthConfig()
    }

    override val name = when (authConfig) {
        is AuthConfig.Direct -> "Claude (cloud)"
        is AuthConfig.Proxied -> "Claude (ChartLite Cloud)"
    }

    private val gson = Gson()

    override suspend fun isAvailable(): Boolean {
        val hasCredential = when (authConfig) {
            is AuthConfig.Direct -> authConfig.apiKeyProvider().isNotBlank()
            is AuthConfig.Proxied -> true // Auth is resolved lazily at request time
        }
        if (!hasCredential) {
            Log.d(TAG, "Claude not available: no credential")
            return false
        }
        if (!NetworkUtils.hasNetwork(context)) {
            Log.d(TAG, "Claude not available: no network")
            return false
        }
        return true
    }

    override suspend fun extract(
        transcript: String,
        patientId: String,
        providerId: String,
        facilityId: String
    ): StructuredEncounter? = withContext(Dispatchers.IO) {
        val systemPrompt = promptBuilder.buildSystemPrompt(condensed = false)
        val userPrompt = promptBuilder.buildUserPrompt(transcript)

        val responseText = callClaudeApi(systemPrompt, userPrompt, "extraction")
            ?: return@withContext null

        responseParser.parse(responseText, transcript, patientId, providerId, facilityId)
    }

    /**
     * Generate a draft clinical note from transcript via Claude API.
     * Returns plain text (not JSON) — the clinician reviews/edits this before extraction.
     */
    override suspend fun generateNote(transcript: String): String? = withContext(Dispatchers.IO) {
        val systemPrompt = promptBuilder.buildNoteSystemPrompt()
        val userPrompt = promptBuilder.buildNoteUserPrompt(transcript)

        callClaudeApi(systemPrompt, userPrompt, "note generation")?.trim()
    }

    /** Shared helper: send a system+user prompt pair to the Claude API and return the text response. */
    private suspend fun callClaudeApi(
        systemPrompt: String,
        userPrompt: String,
        purpose: String
    ): String? {
        when (authConfig) {
            is AuthConfig.Direct -> {
                if (authConfig.apiKeyProvider().isBlank()) return null
            }
            is AuthConfig.Proxied -> { /* Always available */ }
        }

        Log.d(TAG, "Calling Claude API for $purpose (system: ${systemPrompt.length}, user: ${userPrompt.length} chars)")

        val requestBody = gson.toJson(mapOf(
            "model" to MODEL,
            "max_tokens" to 2048,
            "system" to systemPrompt,
            "messages" to listOf(
                mapOf("role" to "user", "content" to userPrompt)
            )
        ))

        val requestBuilder = when (authConfig) {
            is AuthConfig.Direct -> {
                Request.Builder()
                    .url(DIRECT_API_URL)
                    .addHeader("x-api-key", authConfig.apiKeyProvider())
                    .addHeader("anthropic-version", API_VERSION)
            }
            is AuthConfig.Proxied -> {
                val builder = Request.Builder()
                    .url("$PROXY_BASE_URL/v1/extract")
                    .addHeader("X-Anthropic-Version", API_VERSION)
                val authHeaders = try {
                    authConfig.authHeaderProvider()
                } catch (e: Exception) {
                    Log.w(TAG, "Claude proxy auth unavailable: ${e.message}")
                    return null
                }
                authHeaders.forEach { (key, value) ->
                    builder.addHeader(key, value)
                }
                builder
            }
        }

        val request = requestBuilder
            .addHeader("content-type", "application/json")
            .post(requestBody.toRequestBody("application/json".toMediaType()))
            .build()

        val call = SharedHttpClient.instance.newCall(request)
        val response = suspendCancellableCoroutine { cont ->
            cont.invokeOnCancellation { call.cancel() }
            try {
                cont.resumeWith(Result.success(call.execute()))
            } catch (e: Exception) {
                cont.resumeWith(Result.failure(e))
            }
        }

        return response.use { resp ->
            if (!resp.isSuccessful) {
                Log.e(TAG, "Claude $purpose error ${resp.code}")
                return@use null
            }

            val body = resp.body?.string() ?: return@use null

            val text = try {
                val json = gson.fromJson(body, JsonObject::class.java)
                val content = json.getAsJsonArray("content")
                content?.get(0)?.asJsonObject?.get("text")?.asString
            } catch (e: Exception) {
                Log.e(TAG, "Failed to parse Claude $purpose response", e)
                null
            } ?: return@use null

            Log.d(TAG, "Claude $purpose response (${text.length} chars)")
            text
        }
    }

    /**
     * Extract clinical data from a photo via Claude Vision API.
     * Sends image as base64 alongside the vision prompt.
     */
    suspend fun extractVision(imagePath: String, promptBuilder: ExtractionPromptBuilder): String? = withContext(Dispatchers.IO) {
        if (!isAvailable()) return@withContext null

        val file = File(imagePath)
        if (!file.exists()) {
            Log.e(TAG, "Vision image not found: $imagePath")
            return@withContext null
        }

        val imageBytes = file.readBytes()
        val base64Image = Base64.encodeToString(imageBytes, Base64.NO_WRAP)
        val mediaType = if (imagePath.endsWith(".png")) "image/png" else "image/jpeg"

        val systemPrompt = "Read the image. Respond with ONLY a JSON object."
        val userPrompt = promptBuilder.visionUserPrompt(isLargeModel = true)

        Log.d(TAG, "Calling Claude Vision API (image: ${imageBytes.size / 1024}KB)")

        val requestBody = gson.toJson(mapOf(
            "model" to MODEL,
            "max_tokens" to 1024,
            "system" to systemPrompt,
            "messages" to listOf(
                mapOf("role" to "user", "content" to listOf(
                    mapOf(
                        "type" to "image",
                        "source" to mapOf(
                            "type" to "base64",
                            "media_type" to mediaType,
                            "data" to base64Image
                        )
                    ),
                    mapOf(
                        "type" to "text",
                        "text" to userPrompt
                    )
                ))
            )
        ))

        val requestBuilder = when (authConfig) {
            is AuthConfig.Direct -> {
                Request.Builder()
                    .url(DIRECT_API_URL)
                    .addHeader("x-api-key", authConfig.apiKeyProvider())
                    .addHeader("anthropic-version", API_VERSION)
            }
            is AuthConfig.Proxied -> {
                val builder = Request.Builder()
                    .url("$PROXY_BASE_URL/v1/extract")
                    .addHeader("X-Anthropic-Version", API_VERSION)
                val authHeaders = try { authConfig.authHeaderProvider() } catch (e: Exception) {
                    Log.e(TAG, "Vision auth failed: ${e.message}")
                    return@withContext null
                }
                authHeaders.entries.fold(builder) { b, (k, v) -> b.addHeader(k, v) }
            }
        }

        val request = requestBuilder
            .addHeader("content-type", "application/json")
            .post(requestBody.toRequestBody("application/json".toMediaType()))
            .build()

        val call = SharedHttpClient.instance.newCall(request)
        val response = suspendCancellableCoroutine { cont ->
            cont.invokeOnCancellation { call.cancel() }
            try {
                cont.resumeWith(Result.success(call.execute()))
            } catch (e: Exception) {
                cont.resumeWith(Result.failure(e))
            }
        }

        response.use { resp ->
            if (!resp.isSuccessful) {
                Log.e(TAG, "Claude vision error ${resp.code}")
                return@withContext null
            }
            val body = resp.body?.string() ?: return@withContext null
            val json = gson.fromJson(body, JsonObject::class.java)
            val text = json.getAsJsonArray("content")?.firstOrNull()?.asJsonObject
                ?.get("text")?.asString

            Log.d(TAG, "Claude vision response (${text?.length ?: 0} chars)")
            text
        }
    }

    companion object {
        private const val TAG = "ClaudeExtraction"
        private const val DIRECT_API_URL = "https://api.anthropic.com/v1/messages"
        private const val PROXY_BASE_URL = "https://api.chartlite.health"
        private const val API_VERSION = "2023-06-01"
        private const val MODEL = "claude-sonnet-4-20250514"
    }
}

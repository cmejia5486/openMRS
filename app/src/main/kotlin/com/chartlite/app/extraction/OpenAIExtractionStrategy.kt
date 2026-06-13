package com.chartlite.app.extraction

import android.content.Context
import android.util.Log
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
 * Clinical extraction via OpenAI GPT models (gpt-5.4 / gpt-4.1).
 * Supports proxied (ChartLite Cloud) and direct (BYOK) modes.
 */
class OpenAIExtractionStrategy(
    private val context: Context,
    private val promptBuilder: ExtractionPromptBuilder,
    private val responseParser: LlmResponseParser,
    private val authConfig: AuthConfig,
    private val model: String = GPT_5_4
) : ExtractionStrategy {

    sealed class AuthConfig {
        data class Direct(val apiKeyProvider: () -> String) : AuthConfig()
        data class Proxied(val authHeaderProvider: suspend () -> Map<String, String>) : AuthConfig()
    }

    override val name = when (authConfig) {
        is AuthConfig.Direct -> "OpenAI $model (cloud)"
        is AuthConfig.Proxied -> "OpenAI $model (ChartLite Cloud)"
    }

    private val gson = Gson()

    override suspend fun isAvailable(): Boolean {
        val hasCredential = when (authConfig) {
            is AuthConfig.Direct -> authConfig.apiKeyProvider().isNotBlank()
            is AuthConfig.Proxied -> true
        }
        if (!hasCredential) return false
        if (!NetworkUtils.hasNetwork(context)) return false
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
        val responseText = callApi(systemPrompt, userPrompt, "extraction") ?: return@withContext null
        responseParser.parse(responseText, transcript, patientId, providerId, facilityId)
    }

    override suspend fun generateNote(transcript: String): String? = withContext(Dispatchers.IO) {
        val systemPrompt = promptBuilder.buildNoteSystemPrompt()
        val userPrompt = promptBuilder.buildNoteUserPrompt(transcript)
        callApi(systemPrompt, userPrompt, "note generation")?.trim()
    }

    private suspend fun callApi(systemPrompt: String, userPrompt: String, purpose: String): String? {
        Log.d(TAG, "Calling OpenAI $model for $purpose")

        return when (authConfig) {
            is AuthConfig.Direct -> callDirectApi(systemPrompt, userPrompt, purpose, authConfig.apiKeyProvider())
            is AuthConfig.Proxied -> {
                val requestBody = gson.toJson(
                    mapOf(
                        "model" to model,
                        "max_tokens" to 2048,
                        "system" to systemPrompt,
                        "messages" to listOf(mapOf("role" to "user", "content" to userPrompt))
                    )
                )
                val authHeaders = try {
                    authConfig.authHeaderProvider()
                } catch (e: Exception) {
                    Log.w(TAG, "OpenAI proxy auth unavailable: ${e.message}")
                    return null
                }
                val request = Request.Builder()
                    .url("$PROXY_BASE_URL/v1/extract")
                    .addHeader("X-ChartLite-AI-Provider", "openai")
                    .addHeader("content-type", "application/json")
                    .apply { authHeaders.forEach { (k, v) -> addHeader(k, v) } }
                    .post(requestBody.toRequestBody("application/json".toMediaType()))
                    .build()
                executeRequest(request, purpose, ::parseProxyResponse)
            }
        }
    }

    private suspend fun callDirectApi(
        systemPrompt: String,
        userPrompt: String,
        purpose: String,
        apiKey: String
    ): String? {
        if (apiKey.isBlank()) return null

        val requestBody = gson.toJson(
            mapOf(
                "model" to model,
                "messages" to listOf(
                    mapOf("role" to "system", "content" to systemPrompt),
                    mapOf("role" to "user", "content" to userPrompt)
                ),
                "max_tokens" to 2048
            )
        )
        val request = Request.Builder()
            .url(DIRECT_API_URL)
            .addHeader("Authorization", "Bearer $apiKey")
            .addHeader("content-type", "application/json")
            .post(requestBody.toRequestBody("application/json".toMediaType()))
            .build()

        return executeRequest(request, purpose, ::parseDirectResponse)
    }

    private suspend fun executeRequest(
        request: Request,
        purpose: String,
        parser: (String) -> String?
    ): String? {
        val call = SharedHttpClient.instance.newCall(request)
        val response = suspendCancellableCoroutine { cont ->
            cont.invokeOnCancellation { call.cancel() }
            try { cont.resumeWith(Result.success(call.execute())) }
            catch (e: Exception) { cont.resumeWith(Result.failure(e)) }
        }

        return response.use { resp ->
            if (!resp.isSuccessful) {
                val errBody = resp.body?.string()?.take(500).orEmpty()
                Log.e(TAG, "OpenAI $model $purpose error ${resp.code}: $errBody")
                return@use null
            }
            val body = resp.body?.string() ?: return@use null
            try {
                parser(body)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to parse OpenAI response", e)
                null
            }
        }
    }

    private fun parseProxyResponse(body: String): String? {
        val json = gson.fromJson(body, JsonObject::class.java)
        return json.get("text")?.asString
    }

    private fun parseDirectResponse(body: String): String? {
        val json = gson.fromJson(body, JsonObject::class.java)
        val message = json.getAsJsonArray("choices")
            ?.firstOrNull()
            ?.asJsonObject
            ?.getAsJsonObject("message")
            ?: return null
        val content = message.get("content") ?: return null
        return when {
            content.isJsonPrimitive -> content.asString
            content.isJsonArray -> {
                buildString {
                    content.asJsonArray.forEach { item ->
                        val chunk = item.asJsonObject.get("text")?.asString?.trim().orEmpty()
                        if (chunk.isNotBlank()) {
                            if (isNotEmpty()) append('\n')
                            append(chunk)
                        }
                    }
                }.takeIf { it.isNotBlank() }
            }
            else -> null
        }
    }

    companion object {
        private const val TAG = "OpenAIExtraction"
        private const val PROXY_BASE_URL = "https://api.chartlite.health"
        private const val DIRECT_API_URL = "https://api.openai.com/v1/chat/completions"
        const val GPT_5_4 = "gpt-5.4"
        const val GPT_4_1 = "gpt-4.1"
    }
}

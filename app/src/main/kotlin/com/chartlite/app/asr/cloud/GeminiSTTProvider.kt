package com.chartlite.app.asr.cloud

import android.content.Context
import android.util.Base64
import android.util.Log
import com.google.gson.Gson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * Gemini 3 Flash Preview cloud STT provider (BYOK path).
 *
 * Uses the Gemini generateContent API with inline audio — no separate STT pipeline needed.
 * Strong multilingual support including African languages (Swahili, Amharic, Zulu, Xhosa).
 *
 * Model: gemini-3.1-flash-lite-preview
 * API reference: https://ai.google.dev/gemini-api/docs/audio
 */
class GeminiSTTProvider(
    private val context: Context,
    private val apiKeyProvider: () -> String
) : CloudASRProvider {

    companion object {
        private const val TAG = "GeminiSTT"
        private const val GEMINI_MODEL = "gemini-3.1-flash-lite-preview"
        private const val API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
    }

    private val gson = Gson()

    override val name = "Gemini 3 Flash (STT)"

    override val supportedLanguages = setOf(
        "en-US", "en-ZA", "en-GB", "en-AU",
        "zu-ZA", "xh-ZA", "am-ET", "sw-KE", "sw-TZ",
        "af-ZA", "st-ZA", "tn-ZA", "ny-MW",
        "fr-FR", "es-ES", "pt-BR", "de-DE", "it-IT",
        "zh-CN", "ja-JP", "ko-KR", "hi-IN",
        "ar-SA", "ru-RU", "tr-TR", "nl-NL",
        "pl-PL", "sv-SE", "ha-NG", "yo-NG"
    )

    override val acceptedFormats = setOf(
        AudioEncoding.WAV, AudioEncoding.FLAC, AudioEncoding.MP3, AudioEncoding.OPUS_OGG
    )
    override val maxUploadBytes = 20_000_000L  // 20 MB inline limit
    override val supportsWordTimestamps = false
    override val supportsDiarization = false

    override suspend fun isAvailable(): Boolean {
        if (apiKeyProvider().isBlank()) {
            Log.d(TAG, "Not available: no API key")
            return false
        }
        if (!NetworkUtils.hasNetwork(context)) {
            Log.d(TAG, "Not available: no network")
            return false
        }
        return true
    }

    override suspend fun transcribe(
        audioData: ByteArray,
        languageCode: String,
        sampleRate: Int,
        encoding: AudioEncoding
    ): CloudTranscriptionResult? = withContext(Dispatchers.IO) {
        val apiKey = apiKeyProvider()
        if (apiKey.isBlank()) return@withContext null

        Log.d(TAG, "Transcribing ${audioData.size} bytes via Gemini, lang=$languageCode")

        val mimeType = when (encoding) {
            AudioEncoding.WAV -> "audio/wav"
            AudioEncoding.FLAC -> "audio/flac"
            AudioEncoding.MP3 -> "audio/mpeg"
            AudioEncoding.OPUS_OGG -> "audio/ogg"
            else -> "audio/wav"
        }

        val prompt = "Transcribe this clinical consultation accurately in $languageCode. " +
            "Return only the transcription text with no commentary or formatting."

        val requestBody = gson.toJson(mapOf(
            "contents" to listOf(mapOf(
                "parts" to listOf(
                    mapOf("inlineData" to mapOf(
                        "mimeType" to mimeType,
                        "data" to Base64.encodeToString(audioData, Base64.NO_WRAP)
                    )),
                    mapOf("text" to prompt)
                )
            )),
            "generationConfig" to mapOf(
                "temperature" to 0,
                "maxOutputTokens" to 8192
            )
        ))

        val url = "$API_BASE/$GEMINI_MODEL:generateContent?key=$apiKey"
        val request = Request.Builder()
            .url(url)
            .addHeader("Content-Type", "application/json")
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
                Log.e(TAG, "Gemini STT error ${resp.code}")
                return@withContext CloudTranscriptionResult(
                    text = "",
                    error = "Gemini STT error ${resp.code}"
                )
            }

            val body = resp.body?.string() ?: return@withContext null
            try {
                val result = CloudASRResponseParsers.parseGeminiResponse(body)
                Log.d(TAG, "Transcription complete: ${result.text.length} chars")
                result
            } catch (e: Exception) {
                Log.e(TAG, "Failed to parse Gemini response", e)
                CloudTranscriptionResult(text = "", error = "Parse error: ${e.message}")
            }
        }
    }
}

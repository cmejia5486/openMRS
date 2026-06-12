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
 * Google Cloud Speech-to-Text provider using Chirp 3 model.
 *
 * Best African language support: zu-ZA, xh-ZA, am-ET, sw-KE + 100 more.
 * Uses the synchronous recognize endpoint (V1 API — simpler, widely available).
 *
 * API reference: https://cloud.google.com/speech-to-text/docs/sync-recognize
 */
class GoogleCloudSTTProvider(
    private val context: Context,
    private val apiKeyProvider: () -> String
) : CloudASRProvider {

    companion object {
        private const val TAG = "GoogleCloudSTT"
        private const val API_URL = "https://speech.googleapis.com/v1/speech:recognize"
    }

    private val gson = Gson()

    override val name = "Google Cloud STT (Chirp 3)"

    override val supportedLanguages = setOf(
        "en-US", "en-ZA", "en-GB", "en-AU",
        "zu-ZA", "xh-ZA", "am-ET", "sw-KE", "sw-TZ",
        "af-ZA", "st-ZA", "tn-ZA",
        "fr-FR", "es-ES", "pt-BR", "de-DE", "it-IT",
        "zh-CN", "ja-JP", "ko-KR", "hi-IN",
        "ar-SA", "ru-RU", "tr-TR"
    )

    override val acceptedFormats = setOf(AudioEncoding.OPUS_OGG, AudioEncoding.FLAC, AudioEncoding.WAV)
    override val maxUploadBytes = 10_000_000L
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

        Log.d(TAG, "Transcribing ${audioData.size} bytes, lang=$languageCode, encoding=$encoding")

        val encodingStr = when (encoding) {
            AudioEncoding.WAV -> "LINEAR16"
            AudioEncoding.FLAC -> "FLAC"
            AudioEncoding.OPUS_OGG -> "OGG_OPUS"
            else -> "LINEAR16"
        }

        val requestBody = gson.toJson(mapOf(
            "config" to mapOf(
                "encoding" to encodingStr,
                "sampleRateHertz" to sampleRate,
                "languageCode" to languageCode,
                "model" to "chirp",
                "enableAutomaticPunctuation" to true,
                "audioChannelCount" to 1
            ),
            "audio" to mapOf(
                "content" to Base64.encodeToString(audioData, Base64.NO_WRAP)
            )
        ))

        val request = Request.Builder()
            .url("$API_URL?key=$apiKey")
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
                Log.e(TAG, "Google STT error ${resp.code}")
                return@withContext CloudTranscriptionResult(
                    text = "",
                    error = "Google STT error ${resp.code}"
                )
            }

            val body = resp.body?.string() ?: return@withContext null

            try {
                val result = CloudASRResponseParsers.parseGoogleResponse(body)
                Log.d(TAG, "Transcription: ${result.text.length} chars, confidence=${result.confidence}")
                result
            } catch (e: Exception) {
                Log.e(TAG, "Failed to parse response", e)
                CloudTranscriptionResult(text = "", error = "Parse error: ${e.message}")
            }
        }
    }
}

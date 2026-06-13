package com.chartlite.app.asr.cloud

import android.content.Context
import android.util.Base64
import android.util.Log
import com.google.gson.Gson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * Cloud ASR provider that routes through ChartLite's backend proxy.
 *
 * API keys are held server-side. Auth is provided by [authHeaderProvider] which returns
 * the appropriate session JWT headers.
 * Delegates to Gemini, Deepgram, or OpenAI depending on [backendProvider].
 * The proxy endpoint is a Cloudflare Worker at api.chartlite.health.
 */
class ChartLiteProxyProvider(
    private val context: Context,
    private val backendProvider: String, // "gemini", "deepgram", or "openai"
    private val authHeaderProvider: suspend () -> Map<String, String>
) : CloudASRProvider {

    companion object {
        private const val TAG = "ChartLiteProxy"
        private const val PROXY_BASE_URL = "https://api.chartlite.health"
    }

    private val gson = Gson()

    override val name = "ChartLite Cloud ($backendProvider)"

    // Union of all provider languages — the proxy backend handles provider-specific filtering
    override val supportedLanguages = setOf(
        "en-US", "en-GB", "en-AU", "en-ZA",
        "zu-ZA", "xh-ZA", "am-ET", "sw-KE", "sw-TZ",
        "af-ZA", "st-ZA", "tn-ZA",
        "es-ES", "fr-FR", "de-DE", "pt-BR", "it-IT",
        "zh-CN", "ja-JP", "ko-KR", "hi-IN",
        "ar-SA", "ru-RU", "tr-TR", "nl-NL",
        "pl-PL", "sv-SE", "da-DK", "fi-FI", "no-NO"
    )

    override val acceptedFormats = when (backendProvider) {
        "openai" -> setOf(AudioEncoding.WAV, AudioEncoding.MP3, AudioEncoding.FLAC)
        else -> setOf(AudioEncoding.WAV, AudioEncoding.FLAC, AudioEncoding.MP3, AudioEncoding.OPUS_OGG)
    }

    override val maxUploadBytes = when (backendProvider) {
        "openai" -> 25_000_000L
        "gemini" -> 20_000_000L
        else -> 2_000_000_000L
    }

    override val supportsWordTimestamps = backendProvider == "deepgram"
    override val supportsDiarization = backendProvider == "deepgram"

    override suspend fun isAvailable(): Boolean {
        if (!NetworkUtils.hasNetwork(context)) {
            Log.d(TAG, "Not available: no network")
            return false
        }
        // Auth is resolved lazily when a request starts.
        return true
    }

    override suspend fun transcribe(
        audioData: ByteArray,
        languageCode: String,
        sampleRate: Int,
        encoding: AudioEncoding
    ): CloudTranscriptionResult? = withContext(Dispatchers.IO) {
        Log.d(TAG, "Transcribing ${audioData.size} bytes via proxy, provider=$backendProvider, lang=$languageCode")

        val authHeaders = try {
            authHeaderProvider()
        } catch (e: Exception) {
            val message = e.message ?: "ChartLite Cloud authentication failed"
            Log.w(TAG, message)
            return@withContext CloudTranscriptionResult(text = "", error = message)
        }

        val request = when (backendProvider) {
            "gemini" -> buildGeminiProxyRequest(audioData, languageCode, encoding, authHeaders)
            "deepgram" -> buildDeepgramProxyRequest(audioData, languageCode, sampleRate, encoding, authHeaders)
            "openai" -> buildOpenAIProxyRequest(audioData, languageCode, encoding, authHeaders)
            else -> return@withContext null
        }

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
                Log.e(TAG, "Proxy error ${resp.code}")
                return@withContext CloudTranscriptionResult(
                    text = "",
                    error = "Proxy error ${resp.code}"
                )
            }

            val body = resp.body?.string() ?: return@withContext null

            // Parse using the same shared parsers as direct providers
            try {
                when (backendProvider) {
                    "gemini" -> CloudASRResponseParsers.parseGeminiResponse(body)
                    "deepgram" -> CloudASRResponseParsers.parseDeepgramResponse(body)
                    "openai" -> CloudASRResponseParsers.parseOpenAIResponse(body)
                    else -> null
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to parse proxy response", e)
                CloudTranscriptionResult(text = "", error = "Parse error: ${e.message}")
            }
        }
    }

    // ── Request builders ──

    /** Apply auth headers to a request builder. */
    private fun Request.Builder.withAuthHeaders(headers: Map<String, String>): Request.Builder {
        headers.forEach { (key, value) -> addHeader(key, value) }
        return this
    }

    private fun buildGeminiProxyRequest(
        audioData: ByteArray, languageCode: String,
        encoding: AudioEncoding, authHeaders: Map<String, String>
    ): Request {
        val mimeType = when (encoding) {
            AudioEncoding.WAV -> "audio/wav"
            AudioEncoding.FLAC -> "audio/flac"
            AudioEncoding.MP3 -> "audio/mpeg"
            AudioEncoding.OPUS_OGG -> "audio/ogg"
            else -> "audio/wav"
        }

        val requestBody = gson.toJson(mapOf(
            "audio_data" to Base64.encodeToString(audioData, Base64.NO_WRAP),
            "mime_type" to mimeType,
            "language" to languageCode
        ))

        return Request.Builder()
            .url("$PROXY_BASE_URL/v1/transcribe")
            .withAuthHeaders(authHeaders)
            .addHeader("X-ChartLite-Provider", "gemini")
            .addHeader("Content-Type", "application/json")
            .post(requestBody.toRequestBody("application/json".toMediaType()))
            .build()
    }

    private fun buildDeepgramProxyRequest(
        audioData: ByteArray, languageCode: String, sampleRate: Int,
        encoding: AudioEncoding, authHeaders: Map<String, String>
    ): Request {
        val dgLang = languageCode.substringBefore("-").lowercase()
        val model = if (dgLang == "en") "nova-3-medical" else "nova-3"
        val contentType = when (encoding) {
            AudioEncoding.WAV -> "audio/wav"
            AudioEncoding.FLAC -> "audio/flac"
            AudioEncoding.OPUS_OGG -> "audio/ogg"
            AudioEncoding.MP3 -> "audio/mpeg"
            else -> "audio/wav"
        }

        val queryParams = "model=$model&language=$dgLang&punctuate=true&smart_format=true&sample_rate=$sampleRate"

        return Request.Builder()
            .url("$PROXY_BASE_URL/v1/transcribe")
            .withAuthHeaders(authHeaders)
            .addHeader("X-ChartLite-Provider", "deepgram")
            .addHeader("X-ChartLite-Query", queryParams)
            .addHeader("X-ChartLite-Audio-Type", contentType)
            .addHeader("Content-Type", contentType)
            .post(audioData.toRequestBody(contentType.toMediaType()))
            .build()
    }

    private fun buildOpenAIProxyRequest(
        audioData: ByteArray, languageCode: String,
        encoding: AudioEncoding, authHeaders: Map<String, String>
    ): Request {
        val contentType = when (encoding) {
            AudioEncoding.WAV -> "audio/wav"
            AudioEncoding.FLAC -> "audio/flac"
            AudioEncoding.MP3 -> "audio/mpeg"
            else -> "audio/wav"
        }
        val fileExtension = when (encoding) {
            AudioEncoding.WAV -> "wav"
            AudioEncoding.FLAC -> "flac"
            AudioEncoding.MP3 -> "mp3"
            else -> "wav"
        }
        val isoLang = languageCode.substringBefore("-").lowercase()

        val multipartBody = MultipartBody.Builder()
            .setType(MultipartBody.FORM)
            .addFormDataPart(
                "file", "recording.$fileExtension",
                audioData.toRequestBody(contentType.toMediaType())
            )
            .addFormDataPart("model", "gpt-4o-transcribe")
            .addFormDataPart("language", isoLang)
            .addFormDataPart("response_format", "json")
            .build()

        return Request.Builder()
            .url("$PROXY_BASE_URL/v1/transcribe")
            .withAuthHeaders(authHeaders)
            .addHeader("X-ChartLite-Provider", "openai")
            .post(multipartBody)
            .build()
    }
}

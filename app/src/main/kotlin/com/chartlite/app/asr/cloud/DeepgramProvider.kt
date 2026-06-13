package com.chartlite.app.asr.cloud

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * Deepgram Nova-3 provider.
 *
 * Supports word timestamps, diarization, and smart formatting.
 * Nova-3 Medical is English-only; Nova-3 general supports multiple languages.
 *
 * API reference: https://developers.deepgram.com/docs/pre-recorded-audio
 */
class DeepgramProvider(
    private val context: Context,
    private val apiKeyProvider: () -> String
) : CloudASRProvider {

    companion object {
        private const val TAG = "DeepgramProvider"
        private const val API_URL = "https://api.deepgram.com/v1/listen"
    }

    override val name = "Deepgram Nova-3"

    override val supportedLanguages = setOf(
        "en-US", "en-GB", "en-AU", "en-ZA",
        "es-ES", "fr-FR", "de-DE", "pt-BR", "it-IT",
        "zh-CN", "ja-JP", "ko-KR", "hi-IN",
        "ar-SA", "ru-RU", "tr-TR", "nl-NL"
    )

    override val acceptedFormats = setOf(
        AudioEncoding.OPUS_OGG, AudioEncoding.WAV, AudioEncoding.FLAC, AudioEncoding.MP3
    )
    override val maxUploadBytes = 2_000_000_000L
    override val supportsWordTimestamps = true
    override val supportsDiarization = true

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

        Log.d(TAG, "Transcribing ${audioData.size} bytes, lang=$languageCode")

        val dgLang = languageCode.substringBefore("-").lowercase()
        val model = if (dgLang == "en") "nova-3-medical" else "nova-3"

        val contentType = when (encoding) {
            AudioEncoding.WAV -> "audio/wav"
            AudioEncoding.FLAC -> "audio/flac"
            AudioEncoding.OPUS_OGG -> "audio/ogg"
            AudioEncoding.MP3 -> "audio/mpeg"
            else -> "audio/wav"
        }

        val url = buildString {
            append(API_URL)
            append("?model=$model")
            append("&language=$dgLang")
            append("&punctuate=true")
            append("&smart_format=true")
            append("&sample_rate=$sampleRate")
        }

        val request = Request.Builder()
            .url(url)
            .addHeader("Authorization", "Token $apiKey")
            .addHeader("Content-Type", contentType)
            .post(audioData.toRequestBody(contentType.toMediaType()))
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
                Log.e(TAG, "Deepgram error ${resp.code}")
                return@withContext CloudTranscriptionResult(
                    text = "",
                    error = "Deepgram error ${resp.code}"
                )
            }

            val body = resp.body?.string() ?: return@withContext null

            try {
                val result = CloudASRResponseParsers.parseDeepgramResponse(body)
                Log.d(TAG, "Transcription: ${result.text.length} chars, ${result.words?.size ?: 0} words, confidence=${result.confidence}")
                result
            } catch (e: Exception) {
                Log.e(TAG, "Failed to parse response", e)
                CloudTranscriptionResult(text = "", error = "Parse error: ${e.message}")
            }
        }
    }
}

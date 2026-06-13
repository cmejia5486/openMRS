package com.chartlite.app.asr.cloud

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * OpenAI GPT-4o Transcribe provider.
 *
 * Batch-only (no streaming). Accepts WAV/MP3/FLAC — NOT Ogg/Opus.
 * No word-level timestamps (verbose_json timestamps are whisper-1 only).
 * Multipart file upload.
 *
 * API reference: https://platform.openai.com/docs/api-reference/audio/createTranscription
 */
class OpenAITranscribeProvider(
    private val context: Context,
    private val apiKeyProvider: () -> String
) : CloudASRProvider {

    companion object {
        private const val TAG = "OpenAITranscribe"
        private const val API_URL = "https://api.openai.com/v1/audio/transcriptions"
        private const val MODEL = "gpt-4o-transcribe"
    }

    override val name = "OpenAI GPT-4o Transcribe"

    override val supportedLanguages = setOf(
        "en-US", "en-GB",
        "es-ES", "fr-FR", "de-DE", "pt-BR", "it-IT",
        "zh-CN", "ja-JP", "ko-KR",
        "ar-SA", "ru-RU", "tr-TR", "hi-IN",
        "nl-NL", "pl-PL", "sv-SE", "da-DK", "fi-FI", "no-NO"
    )

    override val acceptedFormats = setOf(AudioEncoding.WAV, AudioEncoding.MP3, AudioEncoding.FLAC)
    override val maxUploadBytes = 25_000_000L
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

        Log.d(TAG, "Transcribing ${audioData.size} bytes, lang=$languageCode")

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
                "file",
                "recording.$fileExtension",
                audioData.toRequestBody(contentType.toMediaType())
            )
            .addFormDataPart("model", MODEL)
            .addFormDataPart("language", isoLang)
            .addFormDataPart("response_format", "json")
            .build()

        val request = Request.Builder()
            .url(API_URL)
            .addHeader("Authorization", "Bearer $apiKey")
            .post(multipartBody)
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
                Log.e(TAG, "API error ${resp.code}")
                return@withContext CloudTranscriptionResult(
                    text = "",
                    error = "OpenAI error ${resp.code}"
                )
            }

            val body = resp.body?.string() ?: return@withContext null

            try {
                val result = CloudASRResponseParsers.parseOpenAIResponse(body)
                Log.d(TAG, "Transcription: ${result.text.length} chars")
                result
            } catch (e: Exception) {
                Log.e(TAG, "Failed to parse response", e)
                CloudTranscriptionResult(text = "", error = "Parse error: ${e.message}")
            }
        }
    }
}

package com.chartlite.app.asr.cloud

import android.content.Context
import android.util.Log
import com.chartlite.app.auth.PlayIntegrityManager
import com.chartlite.app.config.AppConfig
import com.chartlite.app.model.TranscriptionResult
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Connectivity-aware cloud ASR orchestrator.
 *
 * Manages the audio → accumulate → upload → transcript pipeline for cloud providers.
 * When offline, returns an error (store-and-forward not yet implemented).
 *
 * Phase 1: WAV encoding for all providers (simple, universally accepted).
 * Phase 2: Add Opus/Ogg compression for store-and-forward bandwidth savings.
 */
class CloudASRManager(
    private val context: Context,
    private val appConfig: AppConfig,
    private val playIntegrityManager: PlayIntegrityManager? = null
) {

    companion object {
        private const val TAG = "CloudASRManager"
    }

    private val _queuedCount = MutableStateFlow(0)
    val queuedCount: StateFlow<Int> = _queuedCount

    private var isRecording = false
    private var currentLanguage = "en"
    private val audioAccumulator = AudioAccumulator()

    // ── Provider management ──

    private var currentProvider: CloudASRProvider? = null

    private fun resolveProvider(): CloudASRProvider? {
        val providerName = appConfig.cloudAsrProvider
        val keyMode = appConfig.cloudKeyMode

        val provider = if (keyMode == "chartlite") {
            // Route through ChartLite backend proxy — auth via session JWT
            val authProvider: suspend () -> Map<String, String> = if (playIntegrityManager != null) {
                { playIntegrityManager.getAuthHeaders() }
            } else {
                { throw com.chartlite.app.auth.ProxyAuthException("ChartLite Cloud auth is unavailable on this device.") }
            }
            ChartLiteProxyProvider(context, providerName, authProvider)
        } else {
            // BYOK: direct API calls with user's own key
            when (providerName) {
                "gemini" -> GeminiSTTProvider(context) { appConfig.geminiApiKey }
                "deepgram" -> DeepgramProvider(context) { appConfig.deepgramApiKey }
                "openai" -> OpenAITranscribeProvider(context) { appConfig.openaiApiKey }
                else -> {
                    Log.w(TAG, "Unknown cloud ASR provider: $providerName")
                    null
                }
            }
        }
        currentProvider = provider
        return provider
    }

    fun isAvailable(): Boolean {
        val provider = currentProvider ?: resolveProvider() ?: return false
        return when (provider) {
            is ChartLiteProxyProvider -> true // Auth is resolved lazily at request time
            is GeminiSTTProvider -> appConfig.geminiApiKey.isNotBlank()
            is DeepgramProvider -> appConfig.deepgramApiKey.isNotBlank()
            is OpenAITranscribeProvider -> appConfig.openaiApiKey.isNotBlank()
            else -> false
        }
    }

    // ── Recording lifecycle ──

    fun startRecording(language: String) {
        currentLanguage = language
        isRecording = true
        audioAccumulator.reset()
        resolveProvider()
        Log.d(TAG, "Cloud recording started for language=$language, provider=${currentProvider?.name}")
    }

    fun onAudioChunk(chunk: ShortArray) {
        if (!isRecording) return
        if (!audioAccumulator.addChunk(chunk)) {
            Log.w(TAG, "Audio accumulator full — chunk dropped")
        }
    }

    /**
     * Finalize recording: upload audio if connected, or enqueue for store-and-forward.
     * Returns a TranscriptionResult — may have pendingCloudTranscription=true if offline.
     */
    suspend fun stopAndFinalize(durationMs: Long): TranscriptionResult {
        isRecording = false

        val pcmBytes = audioAccumulator.pcmByteCount
        val audioDurationMs = audioAccumulator.durationMs
        Log.d(TAG, "Recording stopped: ${pcmBytes} PCM bytes, ${audioDurationMs}ms duration")

        if (pcmBytes == 0) {
            return TranscriptionResult(
                text = "",
                words = emptyList(),
                durationMs = durationMs,
                error = "No audio captured"
            )
        }

        if (!hasValidatedConnectivity()) {
            Log.d(TAG, "No connectivity — cloud ASR requires internet")
            // Store-and-forward queue not yet implemented (plan Steps 7-8).
            // Return an error so the UI doesn't mislead the user.
            return TranscriptionResult(
                text = "",
                words = emptyList(),
                durationMs = durationMs,
                error = "Cloud ASR requires internet. Please connect and try again, or switch to on-device mode."
            )
        }

        val provider = currentProvider
        if (provider == null) {
            return TranscriptionResult(
                text = "",
                words = emptyList(),
                durationMs = durationMs,
                error = "No cloud ASR provider configured"
            )
        }

        // Encode to WAV and upload
        val wavData = audioAccumulator.toWav()
        Log.d(TAG, "Uploading ${wavData.size} bytes WAV to ${provider.name}")

        return try {
            val result = provider.transcribe(
                audioData = wavData,
                languageCode = mapLanguageCode(currentLanguage),
                sampleRate = 16000,
                encoding = AudioEncoding.WAV
            )

            if (result != null && result.error == null) {
                TranscriptionResult(
                    text = result.text,
                    words = result.words?.map { wt ->
                        com.chartlite.app.model.WordResult(
                            word = wt.word,
                            confidence = wt.confidence,
                            startMs = wt.startMs,
                            endMs = wt.endMs,
                            alternatives = emptyList()
                        )
                    } ?: emptyList(),
                    durationMs = durationMs
                )
            } else {
                TranscriptionResult(
                    text = "",
                    words = emptyList(),
                    durationMs = durationMs,
                    error = result?.error ?: "Cloud transcription returned no result"
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "Cloud transcription failed", e)
            TranscriptionResult(
                text = "",
                words = emptyList(),
                durationMs = durationMs,
                error = "Cloud transcription failed: ${e.message}"
            )
        }
    }

    fun cancelRecording() {
        isRecording = false
        audioAccumulator.reset()
        Log.d(TAG, "Cloud recording cancelled")
    }

    // ── Connectivity ──

    private fun hasValidatedConnectivity(): Boolean = NetworkUtils.hasValidatedNetwork(context)

    // ── Language mapping ──

    /** Map short language codes to BCP-47 for cloud ASR providers */
    private fun mapLanguageCode(code: String): String = when (code) {
        "en" -> "en-US"
        "zu" -> "zu-ZA"
        "xh" -> "xh-ZA"
        "am" -> "am-ET"
        "ny" -> "ny-MW"
        "af" -> "af-ZA"
        "st" -> "st-ZA"
        "tn" -> "tn-ZA"
        "sw" -> "sw-KE"
        "fr" -> "fr-FR"
        "zh" -> "zh-CN"
        "ja" -> "ja-JP"
        "ko" -> "ko-KR"
        else -> code
    }
}

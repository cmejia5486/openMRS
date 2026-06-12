package com.chartlite.app.asr.cloud

/**
 * Interface for cloud-based speech-to-text providers.
 *
 * Each provider declares its capabilities explicitly — no assumed feature parity.
 * Encoding format is provider-specific (Google/Deepgram accept Ogg/Opus;
 * OpenAI accepts WAV/MP3/FLAC but not Ogg).
 */
interface CloudASRProvider {

    /** Human-readable name for UI display */
    val name: String

    /** BCP-47 language codes this provider supports (e.g., "en-US", "zu-ZA") */
    val supportedLanguages: Set<String>

    /** Audio formats accepted by this provider's transcription endpoint */
    val acceptedFormats: Set<AudioEncoding>

    /** Maximum upload size in bytes (e.g., 25MB for OpenAI, 10MB for Google sync) */
    val maxUploadBytes: Long

    /** Whether the provider returns word-level timestamps */
    val supportsWordTimestamps: Boolean

    /** Whether the provider supports speaker diarization */
    val supportsDiarization: Boolean

    /** Check if this provider is currently available (API key configured + network) */
    suspend fun isAvailable(): Boolean

    /**
     * Transcribe audio data and return the result.
     * Returns null if transcription failed (allows fallback to another provider).
     */
    suspend fun transcribe(
        audioData: ByteArray,
        languageCode: String,
        sampleRate: Int = 16000,
        encoding: AudioEncoding
    ): CloudTranscriptionResult?
}

/**
 * Result from a cloud ASR transcription.
 * Fields are optional based on provider capabilities.
 */
data class CloudTranscriptionResult(
    val text: String,
    val confidence: Float = 0f,
    val languageDetected: String? = null,
    val words: List<WordTimestamp>? = null,
    val durationMs: Long = 0L,
    val error: String? = null
)

/** Word-level timing from providers that support it (e.g., Deepgram) */
data class WordTimestamp(
    val word: String,
    val startMs: Long,
    val endMs: Long,
    val confidence: Float
)

/** Audio encoding formats — selected per-provider, not hardcoded */
enum class AudioEncoding {
    PCM_16BIT,  // Raw 16-bit signed PCM (large, uncompressed)
    OPUS_OGG,   // Opus codec in Ogg container (Google, Deepgram)
    FLAC,       // FLAC lossless (all providers)
    WAV,        // WAV/RIFF container with PCM (OpenAI)
    MP3         // MP3 lossy (OpenAI)
}
